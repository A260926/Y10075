# Webhook 重放站（Webhook Replay Station）

完全本地的 Webhook 投递复现实验室，用于复现接收方偶发超时、固定错误码、
限流（429 + Retry-After）、签名密钥轮换、重复响应以及“进程在落最终状态前崩溃”
等投递行为。状态全部保存在 SQLite，自带可编程假接收器，自动化测试与演示不
依赖外网。

## 安装与运行

```bash
cargo build

# 测试 + 演示（页面与 API 监听 127.0.0.1:5205，假接收器监听 5206）
cargo test
cargo run -- --listen 127.0.0.1:5205
```

打开 http://127.0.0.1:5205/ 即可看到标题“Webhook 重放站”。启动时会预置一个
场景：端点处于 `fail_twice` 模式，同一个 delivery 的三次 attempt 按
`503 → 503 → 200` 的稳定顺序完成，页面上可展开查看每次尝试。

可选参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--listen` | `127.0.0.1:5205` | 操作页面 / HTTP API 监听地址 |
| `--receiver` | `127.0.0.1:5206` | 内置假接收器监听地址 |
| `--db` | `webhook-replay.db` | SQLite 数据库文件 |
| `--master-key-file` | `webhook-replay.masterkey` | 本地主密钥（0600，首次自动生成） |
| `--lease-ms` | `15000` | 队列领取租约时长 |
| `--no-seed` | 关 | 不预置演示场景 |

## 核心语义

- **幂等创建**：创建 delivery 需带幂等键。键 + 规范化内容相同则返回原
  delivery（200 `replayed`）；同键不同内容返回 `409` 冲突，不新建。
- **载荷/密钥冻结**：入队时冻结精确的 JSON 字节，并选定当时有效期内的密钥；
  之后编辑事件或轮换密钥都不改变已排队的 attempt。密钥 id 随每个 attempt
  记录，HMAC 基于冻结字节计算。
- **崩溃安全**：attempt 行先以租约写入；收到响应后先提交“收据”
  （`state=responded`、结果、时间），再写 delivery 最终状态并把 attempt 置为
  `done`。若进程在两者之间退出，重启协调逻辑识别已落下的收据并幂等地完成
  最终化，绝不会悄悄再发一次。
- **租约与接管**：领取带过期时间的租约；两个 worker 并发时同一代次只有一个
  能发送。租约到期后接管，原在途结果记为 `lease_lost`，并在审计流水中留下
  “takeover”事件；迟到的响应会被忽略，不会二次最终化。
- **退避**：基于可注入时钟（生产用系统时钟，测试用 `FakeClock`）。5xx/超时/
  传输错误使用端点指数退避；429 的 `Retry-After` 仅影响该 delivery。
- **人工重放**：产生新 `generation`，`parent_id`/`root_id` 链接到原 delivery，
  旧代次的 attempt 全部保留可见，而不是清空。
- **密钥材料**：AES-256-GCM 加密后存入 SQLite，主密钥在本地文件（0600）。
  界面、API 与日志只显示 `key_id`，签名仅展示短指纹。

## 假接收器模式

每个端点拥有独立 token，投递地址为 `http://<receiver>/recv/<token>`。可在页面
或 API 切换：

- `success`：始终 200
- `timeout`：接受连接但不响应（触发发送方超时）
- `fail_twice`：前两次 503，之后 200
- `fixed_status`：固定状态码（默认 409，不可重试的终态）
- `rate_limited`：429 并带 `Retry-After`（秒）

接收器在存在签名头时用冻结的 key id 校验 HMAC，失败返回 401。

## HTTP API（JSON）

- `GET  /api/endpoints`、`POST /api/endpoints`
- `POST /api/endpoints/mode`（切换模式、固定码、Retry-After、重试策略）
- `GET  /api/events`、`POST /api/events`、`POST /api/events/edit`
- `GET  /api/keys`、`POST /api/keys`（`label`、`secret`、`not_before_ms`、
  `not_after_ms` 或 `ttl_ms`；响应只回 `key_id`）
- `POST /api/deliveries`（`endpoint_id`、`idempotency_key`、`payload`、
  可选 `event_name`）
- `GET  /api/deliveries`（含每次 attempt 的请求摘要、key id、计划/实际时间、
  结果与最终原因）
- `POST /api/deliveries/replay`（`delivery_id`，可选新 `payload`）

## 测试

虚拟时钟覆盖退避端点、密钥跨期轮换、幂等冲突、编辑/轮换不影响冻结 attempt、
崩溃窗口、租约接管与人工重放：

```bash
cargo test
```

崩溃窗口测试会真实地以子进程 `exit(7)` 模拟“收据已落、最终状态未写”，随后用
同一个 SQLite 文件重新打开并协调，验证 attempt 数量不增加、第二次发送的编号
正确递增。
