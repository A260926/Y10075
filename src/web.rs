//! Operations UI and HTTP API, served from a single std TCP listener.
//!
//! HTML forms drive the UI (`/ui/*`); the JSON surface lives under `/api/*`.
//! Secret material is never rendered: signing keys appear by id only, and
//! signatures are truncated to a short, non-secret fingerprint.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use serde_json::{json, Value};

use crate::model::RetryPolicy;
use crate::service::App;

pub fn start(listen: &str, app: Arc<App>) -> anyhow::Result<String> {
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?.to_string();
    thread::Builder::new()
        .name("web".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(sock) => {
                        let app = Arc::clone(&app);
                        thread::spawn(move || {
                            if let Err(e) = handle_conn(sock, app) {
                                eprintln!("web connection error: {e}");
                            }
                        });
                    }
                    Err(e) => eprintln!("web accept error: {e}"),
                }
            }
        })?;
    Ok(addr)
}

#[allow(dead_code)]
struct Request {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn handle_conn(mut sock: TcpStream, app: Arc<App>) -> anyhow::Result<()> {
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut header_end = None;
    loop {
        let n = sock.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos);
            break;
        }
        if raw.len() > 2_000_000 {
            break;
        }
    }
    let Some(header_end) = header_end else {
        return Ok(());
    };
    let header_text = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut rl = request_line.split_whitespace();
    let method = rl.next().unwrap_or("GET").to_string();
    let target = rl.next().unwrap_or("/");
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    };
    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_lowercase();
            let v = v.trim().to_string();
            if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
            }
            headers.insert(k, v);
        }
    }
    let body_start = header_end + 4;
    while raw.len() < body_start + content_length {
        let n = sock.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    let body_end = (body_start + content_length).min(raw.len());
    let body = raw[body_start..body_end].to_vec();
    let req = Request {
        method,
        path,
        query,
        headers,
        body,
    };
    let response = route(req, &app);
    write_response(&mut sock, &response)?;
    Ok(())
}

struct Response {
    status: u16,
    reason: String,
    content_type: String,
    body: Vec<u8>,
    extra_headers: Vec<(String, String)>,
}

impl Response {
    fn html(status: u16, reason: &str, body: String) -> Self {
        Self {
            status,
            reason: reason.to_string(),
            content_type: "text/html; charset=utf-8".to_string(),
            body: body.into_bytes(),
            extra_headers: Vec::new(),
        }
    }
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            reason: reason_for(status).to_string(),
            content_type: "application/json; charset=utf-8".to_string(),
            body: serde_json::to_vec_pretty(&value).unwrap_or_default(),
            extra_headers: Vec::new(),
        }
    }
    fn redirect(location: &str) -> Self {
        Self {
            status: 303,
            reason: "See Other".to_string(),
            content_type: "text/plain; charset=utf-8".to_string(),
            body: b"redirect".to_vec(),
            extra_headers: vec![("Location".to_string(), location.to_string())],
        }
    }
    fn error(status: u16, msg: &str) -> Self {
        Self::json(status, json!({ "error": msg }))
    }
}

fn reason_for(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn write_response(sock: &mut TcpStream, resp: &Response) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status,
        resp.reason,
        resp.content_type,
        resp.body.len()
    );
    for (k, v) in &resp.extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    sock.write_all(head.as_bytes())?;
    sock.write_all(&resp.body)?;
    sock.flush()
}

fn urlencoded(body: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let text = String::from_utf8_lossy(body);
    for pair in text.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(urldecode(k), urldecode(v));
        }
    }
    map
}

fn urldecode(s: &str) -> String {
    let bytes = s.replace('+', " ");
    let mut out = Vec::new();
    let mut chars = bytes.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h = chars.next().unwrap_or(b'0');
            let l = chars.next().unwrap_or(b'0');
            let val = u8::from_str_radix(
                &format!("{}{}", h as char, l as char),
                16,
            )
            .unwrap_or(0);
            out.push(val);
        } else {
            out.push(b);
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn query_params(query: &str) -> HashMap<String, String> {
    urlencoded(query.as_bytes())
}

fn route(req: Request, app: &App) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/ui") => page_index(app),
        ("GET", "/healthz") => Response::json(200, json!({"ok": true})),

        // API: endpoints
        ("GET", "/api/endpoints") => list_endpoints(app),
        ("POST", "/api/endpoints") => create_endpoint(&req, app),
        ("POST", "/api/endpoints/mode") if json_body(&req).is_ok() => {
            set_endpoint_mode(&req, app)
        }

        // API: events
        ("GET", "/api/events") => list_events(app),
        ("POST", "/api/events") => create_event(&req, app),
        ("POST", "/api/events/edit") if json_body(&req).is_ok() => {
            edit_event(&req, app)
        }

        // API: signing keys
        ("GET", "/api/keys") => list_keys(app),
        ("POST", "/api/keys") if json_body(&req).is_ok() => create_key(&req, app),

        // API: deliveries
        ("POST", "/api/deliveries") if json_body(&req).is_ok() => {
            enqueue_delivery(&req, app)
        }
        ("GET", "/api/deliveries") => list_deliveries(app, &query_params(&req.query)),
        ("POST", "/api/deliveries/replay") if json_body(&req).is_ok() => {
            replay(&req, app)
        }

        // HTML form actions (redirect back to the page)
        ("POST", "/ui/endpoints") => ui_create_endpoint(&req, app),
        ("POST", "/ui/endpoints/mode") => ui_set_mode(&req, app),
        ("POST", "/ui/events") => ui_publish(&req, app),
        ("POST", "/ui/events/edit") => ui_edit_event(&req, app),
        ("POST", "/ui/keys") => ui_create_key(&req, app),
        ("POST", "/ui/deliveries/replay") => ui_replay(&req, app),

        _ => Response::error(404, "not found"),
    }
}

fn json_body(req: &Request) -> anyhow::Result<Value> {
    Ok(serde_json::from_slice(&req.body)?)
}

fn required<'a>(v: &'a Value, key: &str) -> Result<&'a Value, Response> {
    v.get(key).ok_or_else(|| {
        Response::error(400, &format!("missing field: {key}"))
    })
}

fn string_field<'a>(v: &'a Value, key: &str) -> Result<&'a str, Response> {
    required(v, key)?.as_str().ok_or_else(|| {
        Response::error(400, &format!("field must be string: {key}"))
    })
}

fn policy_from(v: &Value) -> RetryPolicy {
    let d = RetryPolicy::default();
    let get_i = |k: &str, def: i64| v.get(k).and_then(|x| x.as_i64()).unwrap_or(def);
    let get_f = |k: &str, def: f64| v.get(k).and_then(|x| x.as_f64()).unwrap_or(def);
    RetryPolicy {
        max_attempts: get_i("max_attempts", d.max_attempts).max(1),
        base_delay_ms: get_i("base_delay_ms", d.base_delay_ms).max(0),
        max_delay_ms: get_i("max_delay_ms", d.max_delay_ms).max(0),
        multiplier: get_f("multiplier", d.multiplier).max(1.0),
    }
}

fn list_endpoints(app: &App) -> Response {
    match app.store.list_endpoints() {
        Ok(rows) => Response::json(200, json!(rows.iter().map(endpoint_json).collect::<Vec<_>>())),
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn endpoint_json(e: &crate::repo::Endpoint) -> Value {
    json!({
        "id": e.id,
        "name": e.name,
        "target_url": e.target_url,
        "use_fake": e.use_fake,
        "receiver_mode": e.receiver_mode,
        "fixed_status": e.fixed_status,
        "retry_after_secs": e.retry_after_secs,
        "hits": e.hits,
        "retry_policy": {
            "max_attempts": e.policy.max_attempts,
            "base_delay_ms": e.policy.base_delay_ms,
            "max_delay_ms": e.policy.max_delay_ms,
            "multiplier": e.policy.multiplier,
        },
        "created_ms": e.created_ms,
    })
}

fn create_endpoint(req: &Request, app: &App) -> Response {
    let v = match json_body(req) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e.to_string()),
    };
    let name = match string_field(&v, "name") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let mode_str = v.get("mode").and_then(|x| x.as_str()).unwrap_or("success");
    let Some(mode) = crate::model::ReceiverMode::parse(mode_str) else {
        return Response::error(400, "invalid mode");
    };
    let fixed_status = v.get("fixed_status").and_then(|x| x.as_i64()).unwrap_or(409);
    let retry_after_secs = v.get("retry_after_secs").and_then(|x| x.as_i64()).unwrap_or(3);
    let policy = policy_from(&v);
    let target = v.get("target_url").and_then(|x| x.as_str());
    let use_fake = v.get("use_fake").and_then(|x| x.as_bool()).unwrap_or(true);
    match app.create_endpoint(name, mode, fixed_status, retry_after_secs, policy, target, use_fake) {
        Ok(created) => Response::json(201, json!({
            "endpoint": endpoint_json(&created.endpoint),
            "target_url": created.target_url,
        })),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

fn set_endpoint_mode(req: &Request, app: &App) -> Response {
    let v = match json_body(req) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e.to_string()),
    };
    let id = match string_field(&v, "endpoint_id") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let mode_str = match string_field(&v, "mode") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(mode) = crate::model::ReceiverMode::parse(mode_str) else {
        return Response::error(400, "invalid mode");
    };
    let fixed_status = v.get("fixed_status").and_then(|x| x.as_i64()).unwrap_or(409);
    let retry_after_secs = v.get("retry_after_secs").and_then(|x| x.as_i64()).unwrap_or(3);
    let policy = policy_from(&v);
    let existing = match app.store.endpoint(id) {
        Ok(Some(e)) => e,
        Ok(None) => return Response::error(404, "endpoint not found"),
        Err(e) => return Response::error(500, &e.to_string()),
    };
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or(&existing.name);
    match app
        .store
        .update_endpoint_config(id, name, mode.as_str(), fixed_status, retry_after_secs, &policy)
    {
        Ok(true) => Response::json(200, json!({"ok": true})),
        Ok(false) => Response::error(404, "endpoint not found"),
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn list_events(app: &App) -> Response {
    match app.store.list_events() {
        Ok(rows) => Response::json(
            200,
            json!(rows
                .iter()
                .map(|e| json!({
                    "id": e.id, "name": e.name, "payload": serde_json::from_str::<Value>(&e.payload_json).unwrap_or(Value::Null),
                    "created_ms": e.created_ms, "updated_ms": e.updated_ms,
                }))
                .collect::<Vec<_>>()),
        ),
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn create_event(req: &Request, app: &App) -> Response {
    let v = match json_body(req) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e.to_string()),
    };
    let name = match string_field(&v, "name") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let payload = v.get("payload").cloned().unwrap_or(Value::Object(Default::default()));
    match app.create_event(name, &payload) {
        Ok(e) => Response::json(201, json!({"id": e.id, "name": e.name})),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

/// Edit an event's latest payload. Existing queued/in-flight deliveries keep
/// their frozen bytes; only a new publish/replay sees the new payload.
fn edit_event(req: &Request, app: &App) -> Response {
    let v = match json_body(req) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e.to_string()),
    };
    let event_id = match string_field(&v, "event_id") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let payload = match required(&v, "payload") {
        Ok(p) => p.clone(),
        Err(r) => return r,
    };
    match app
        .store
        .update_event_payload(event_id, &payload, app.clock.now_ms())
    {
        Ok(true) => Response::json(200, json!({"ok": true})),
        Ok(false) => Response::error(404, "event not found"),
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn list_keys(app: &App) -> Response {
    match app.store.list_keys() {
        Ok(rows) => Response::json(
            200,
            json!(rows
                .iter()
                .map(|k| json!({
                    "key_id": k.id,
                    "label": k.label,
                    "not_before_ms": k.not_before_ms,
                    "not_after_ms": k.not_after_ms,
                    "created_ms": k.created_ms,
                }))
                .collect::<Vec<_>>()),
        ),
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn create_key(req: &Request, app: &App) -> Response {
    let v = match json_body(req) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e.to_string()),
    };
    let label = match string_field(&v, "label") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let secret = match string_field(&v, "secret") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let now = app.clock.now_ms();
    let not_before = v.get("not_before_ms").and_then(|x| x.as_i64()).unwrap_or(now);
    let ttl_ms = v.get("ttl_ms").and_then(|x| x.as_i64()).unwrap_or(30 * 86_400_000);
    let not_after = v
        .get("not_after_ms")
        .and_then(|x| x.as_i64())
        .unwrap_or(not_before + ttl_ms);
    match app.create_signing_key(label, secret, not_before, not_after) {
        Ok(k) => Response::json(201, json!({"key_id": k.id, "not_before_ms": k.not_before_ms, "not_after_ms": k.not_after_ms})),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

fn enqueue_delivery(req: &Request, app: &App) -> Response {
    let v = match json_body(req) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e.to_string()),
    };
    let endpoint_id = match string_field(&v, "endpoint_id") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let idem_key = match string_field(&v, "idempotency_key") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let payload = match required(&v, "payload") {
        Ok(p) => p.clone(),
        Err(r) => return r,
    };
    if !payload.is_object() {
        return Response::error(400, "payload must be a JSON object");
    }
    if app.store.endpoint(endpoint_id).ok().flatten().is_none() {
        return Response::error(404, "endpoint not found");
    }
    let event_name = v.get("event_name").and_then(|x| x.as_str()).unwrap_or("API event");
    match app.publish(event_name, &payload, endpoint_id, idem_key) {
        Ok((event, crate::queue::EnqueueResult::Created(d))) => Response::json(
            201,
            json!({"result":"created","event_id":event.id,"delivery": delivery_json(&d)}),
        ),
        Ok((event, crate::queue::EnqueueResult::Replayed(d))) => Response::json(
            200,
            json!({"result":"replayed","event_id":event.id,"delivery": delivery_json(&d)}),
        ),
        Ok((_, crate::queue::EnqueueResult::Conflict { existing_generation })) => Response::json(
            409,
            json!({
                "error": "idempotency key reused with different content",
                "existing_generation": existing_generation,
            }),
        ),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

fn list_deliveries(app: &App, _params: &HashMap<String, String>) -> Response {
    match app.queue.list_deliveries() {
        Ok(rows) => {
            let mut out = Vec::new();
            for d in rows {
                let mut j = delivery_json(&d);
                if let Ok(attempts) = app.queue.attempts(&d.id) {
                    j["attempts"] = json!(attempts.iter().map(attempt_json).collect::<Vec<_>>());
                }
                out.push(j);
            }
            Response::json(200, json!(out))
        }
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn replay(req: &Request, app: &App) -> Response {
    let v = match json_body(req) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e.to_string()),
    };
    let original_id = match string_field(&v, "delivery_id") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let payload_override = match v.get("payload") {
        Some(Value::Null) | None => None,
        Some(p) => {
            let s = p.to_string();
            Some(s)
        }
    };
    match app.queue.manual_replay(original_id, payload_override.as_deref()) {
        Ok(d) => Response::json(201, json!({"result":"new_generation","delivery": delivery_json(&d)})),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

pub fn delivery_json(d: &crate::repo::DeliveryRow) -> Value {
    json!({
        "id": d.id,
        "event_id": d.event_id,
        "endpoint_id": d.endpoint_id,
        "idempotency_key": d.idem_key,
        "content_hash": d.content_hash,
        "generation": d.generation,
        "parent_id": d.parent_id,
        "root_id": d.root_id,
        "frozen_payload": serde_json::from_str::<Value>(&d.frozen_payload).unwrap_or(Value::Null),
        "frozen_key_id": d.frozen_key_id,
        "status": d.status,
        "final_reason": d.final_reason,
        "attempts_used": d.attempts_used,
        "next_after_ms": d.next_after_ms,
        "created_ms": d.created_ms,
    })
}

pub fn attempt_json(a: &crate::repo::AttemptRow) -> Value {
    json!({
        "id": a.id,
        "generation": a.generation,
        "attempt_no": a.attempt_no,
        "key_id": a.key_id,
        "signature_fingerprint": a.signature_hex.as_deref().map(fingerprint),
        "scheduled_ms": a.scheduled_ms,
        "lease_owner": a.lease_owner,
        "lease_expires_ms": a.lease_expires_ms,
        "state": a.state,
        "outcome_kind": a.outcome_kind,
        "http_status": a.http_status,
        "detail": a.detail,
        "response_excerpt": a.response_excerpt,
        "started_ms": a.started_ms,
        "finished_ms": a.finished_ms,
    })
}

fn fingerprint(hex_sig: &str) -> String {
    // Only a short, non-reversible prefix is ever displayed.
    format!("sha256:{}…", hex_sig.chars().take(10).collect::<String>())
}

// ---------------- HTML form actions ----------------

fn ui_create_endpoint(req: &Request, app: &App) -> Response {
    let f = urlencoded(&req.body);
    let name = f.get("name").map(|x| x.as_str()).unwrap_or("端点");
    let mode = f.get("mode").map(|x| x.as_str()).unwrap_or("success");
    let Some(mode) = crate::model::ReceiverMode::parse(mode) else {
        return Response::error(400, "invalid mode");
    };
    let fixed: i64 = f.get("fixed_status").and_then(|s| s.parse().ok()).unwrap_or(409);
    let retry_after: i64 = f.get("retry_after_secs").and_then(|s| s.parse().ok()).unwrap_or(3);
    let policy = RetryPolicy {
        max_attempts: f.get("max_attempts").and_then(|s| s.parse().ok()).unwrap_or(5),
        base_delay_ms: f.get("base_delay_ms").and_then(|s| s.parse().ok()).unwrap_or(1000),
        max_delay_ms: f.get("max_delay_ms").and_then(|s| s.parse().ok()).unwrap_or(30000),
        multiplier: f.get("multiplier").and_then(|s| s.parse().ok()).unwrap_or(2.0),
    };
    match app.create_endpoint(name, mode, fixed, retry_after, policy, None, true) {
        Ok(_) => Response::redirect("/"),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

fn ui_set_mode(req: &Request, app: &App) -> Response {
    let f = urlencoded(&req.body);
    let Some(id) = f.get("endpoint_id") else {
        return Response::error(400, "missing endpoint_id");
    };
    let Some(mode) = f.get("mode").and_then(|m| crate::model::ReceiverMode::parse(m)) else {
        return Response::error(400, "invalid mode");
    };
    let fixed: i64 = f.get("fixed_status").and_then(|s| s.parse().ok()).unwrap_or(409);
    let retry_after: i64 = f.get("retry_after_secs").and_then(|s| s.parse().ok()).unwrap_or(3);
    let policy = RetryPolicy {
        max_attempts: f.get("max_attempts").and_then(|s| s.parse().ok()).unwrap_or(5),
        base_delay_ms: f.get("base_delay_ms").and_then(|s| s.parse().ok()).unwrap_or(1000),
        max_delay_ms: f.get("max_delay_ms").and_then(|s| s.parse().ok()).unwrap_or(30000),
        multiplier: f.get("multiplier").and_then(|s| s.parse().ok()).unwrap_or(2.0),
    };
    match app.store.endpoint(id) {
        Ok(Some(e)) => {
            let name = f.get("name").map(|x| x.as_str()).unwrap_or(&e.name).to_string();
            match app.store.update_endpoint_config(
                id,
                &name,
                mode.as_str(),
                fixed,
                retry_after,
                &policy,
            ) {
                Ok(_) => Response::redirect("/"),
                Err(e) => Response::error(500, &e.to_string()),
            }
        }
        Ok(None) => Response::error(404, "endpoint not found"),
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn ui_publish(req: &Request, app: &App) -> Response {
    let f = urlencoded(&req.body);
    let Some(endpoint_id) = f.get("endpoint_id") else {
        return Response::error(400, "missing endpoint_id");
    };
    let Some(idem) = f.get("idempotency_key") else {
        return Response::error(400, "missing idempotency_key");
    };
    let name = f.get("name").map(|x| x.as_str()).unwrap_or("事件");
    let raw = f.get("payload").map(|x| x.as_str()).unwrap_or("{}");
    let payload: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &format!("invalid JSON: {e}")),
    };
    match app.publish(name, &payload, endpoint_id, idem) {
        Ok(_) => Response::redirect("/"),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

fn ui_edit_event(req: &Request, app: &App) -> Response {
    let f = urlencoded(&req.body);
    let Some(event_id) = f.get("event_id") else {
        return Response::error(400, "missing event_id");
    };
    let raw = f.get("payload").map(|x| x.as_str()).unwrap_or("{}");
    let payload: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => return Response::error(400, &format!("invalid JSON: {e}")),
    };
    match app
        .store
        .update_event_payload(event_id, &payload, app.clock.now_ms())
    {
        Ok(true) => Response::redirect("/"),
        Ok(false) => Response::error(404, "event not found"),
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn ui_create_key(req: &Request, app: &App) -> Response {
    let f = urlencoded(&req.body);
    let label = f.get("label").map(|x| x.as_str()).unwrap_or("签名密钥");
    let secret = f.get("secret").map(|x| x.as_str()).unwrap_or("secret");
    let now = app.clock.now_ms();
    let ttl_ms: i64 = f
        .get("ttl_seconds")
        .and_then(|s| s.parse::<i64>().ok())
        .map(|s| s * 1000)
        .unwrap_or(30 * 86_400_000);
    match app.create_signing_key(label, secret, now, now + ttl_ms) {
        Ok(_) => Response::redirect("/"),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

fn ui_replay(req: &Request, app: &App) -> Response {
    let f = urlencoded(&req.body);
    let Some(delivery_id) = f.get("delivery_id") else {
        return Response::error(400, "missing delivery_id");
    };
    let payload_override = f
        .get("payload")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s: &str| s);
    match app.queue.manual_replay(delivery_id, payload_override) {
        Ok(_) => Response::redirect("/"),
        Err(e) => Response::error(400, &e.to_string()),
    }
}

// ---------------- Operations page ----------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn fmt_ms(ts: i64) -> String {
    use std::time::SystemTime;
    if ts <= 0 {
        return "—".to_string();
    }
    let secs = ts / 1000;
    let millis = ts % 1000;
    let dt = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64);
    let _ = dt;
    format!("t={secs}.{millis:03}s")
}

fn page_index(app: &App) -> Response {
    let endpoints = app.store.list_endpoints().unwrap_or_default();
    let events = app.store.list_events().unwrap_or_default();
    let keys = app.store.list_keys().unwrap_or_default();
    let deliveries = app.queue.list_deliveries().unwrap_or_default();
    let audit = app.store.list_audit(60).unwrap_or_default();
    let now = app.clock.now_ms();

    let mut html = String::new();
    html.push_str(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Webhook 重放站</title>
<style>
:root{--bg:#0f172a;--panel:#1e293b;--line:#334155;--ink:#e2e8f0;--mut:#94a3b8;
--ok:#22c55e;--bad:#ef4444;--warn:#f59e0b;--accent:#38bdf8;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);line-height:1.5}
header{padding:20px 28px;border-bottom:1px solid var(--line);background:#111c33}
h1{margin:0;font-size:22px}.sub{color:var(--mut);font-size:13px;margin-top:4px}
main{padding:20px 28px;display:grid;gap:18px;max-width:1180px;margin:0 auto}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.card h2{margin:0 0 12px;font-size:15px;color:var(--accent)}
label{display:block;font-size:12px;color:var(--mut);margin:8px 0 3px}
input,select,textarea{width:100%;background:#0b1424;border:1px solid var(--line);color:var(--ink);
border-radius:6px;padding:7px 9px;font-size:13px;font-family:inherit}
textarea{min-height:64px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
button{margin-top:10px;background:var(--accent);color:#04222f;border:0;border-radius:6px;
padding:7px 14px;font-weight:600;font-size:13px;cursor:pointer}
button.ghost{background:#334155;color:var(--ink)}
.row{display:flex;gap:8px}.row>*{flex:1}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.03em}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700}
.p-queued{background:#334155;color:#cbd5e1}.p-sending{background:#78350f;color:#fde68a}
.p-succeeded{background:#064e3b;color:#6ee7b7}.p-failed{background:#7f1d1d;color:#fecaca}
details{margin-top:8px;border:1px solid var(--line);border-radius:8px;background:#0b1424}
summary{cursor:pointer;padding:8px 10px;font-size:13px;font-weight:600;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸ ";color:var(--accent)}
details[open] summary::before{content:"▾ "}
.attempts{padding:0 10px 10px}
.mut{color:var(--mut)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.small{font-size:11.5px;color:var(--mut)}
.inline{display:flex;gap:8px;align-items:end;flex-wrap:wrap}
.inline>div{min-width:120px}
.badge{font-size:10.5px;padding:1px 6px;border:1px solid var(--line);border-radius:5px;color:var(--mut)}
</style></head><body>
<header><h1>Webhook 重放站</h1>
<div class="sub">完全本地的 Webhook 投递复现实验室 · SQLite 持久化 · 可编程假接收器 · 虚拟时钟退避 · 租约队列 · 当前时钟 <span class="mono" id="now"></span></div>
</header><main>
"#,
    );
    html.push_str(&format!("<script>document.getElementById('now').textContent='{}';</script>", fmt_ms(now)));
    html.push_str(&render_forms(&endpoints, &events, &keys));
    html.push_str(&render_deliveries(app, &deliveries));
    html.push_str(&render_audit(&audit));
    html.push_str("</main></body></html>");
    Response::html(200, "OK", html)
}

fn render_forms(
    endpoints: &[crate::repo::Endpoint],
    events: &[crate::repo::EventRow],
    keys: &[crate::repo::SignKeyRow],
) -> String {
    let mut h = String::new();
    h.push_str("<section class=\"grid2\">");

    // Endpoint register + mode control
    h.push_str(r#"<div class="card"><h2>1. 登记端点 / 设置假接收器</h2>
<form method="post" action="/ui/endpoints">
  <label>名称</label><input name="name" value="我的接收端点" required>
  <div class="row"><div><label>接收器模式</label>
    <select name="mode">
      <option value="success">成功 (200)</option>
      <option value="timeout">超时 (不响应)</option>
      <option value="fail_twice" selected>前两次 503，之后成功</option>
      <option value="fixed_status">固定 409</option>
      <option value="rate_limited">429 + Retry-After</option>
    </select></div>
    <div><label>固定状态码</label><input name="fixed_status" value="409"></div>
    <div><label>Retry-After(秒,仅429)</label><input name="retry_after_secs" value="3"></div>
  </div>
  <div class="row">
    <div><label>最大尝试次数</label><input name="max_attempts" value="5"></div>
    <div><label>基础退避(ms)</label><input name="base_delay_ms" value="1000"></div>
    <div><label>最大退避(ms)</label><input name="max_delay_ms" value="30000"></div>
    <div><label>倍率</label><input name="multiplier" value="2"></div>
  </div>
  <button>登记端点</button>
</form>"#);
    h.push_str("<hr style='border-color:#334155;margin:14px 0'>");
    if endpoints.is_empty() {
        h.push_str("<p class='mut'>暂无端点。</p>");
    } else {
        for e in endpoints {
            h.push_str(&format!(
                "<details><summary>{} <span class='badge'>{}</span> <span class='small'>hits={}</span></summary><div style='padding:0 10px 10px'>",
                esc(&e.name), esc(&e.receiver_mode), e.hits
            ));
            h.push_str(&format!("<div class='small mono'>{}</div>", esc(&e.target_url)));
            h.push_str(&format!(
                "<form method='post' action='/ui/endpoints/mode' class='inline' style='margin-top:8px'>
                 <input type='hidden' name='endpoint_id' value='{}'>
                 <input type='hidden' name='name' value='{}'>
                 <div><label>模式</label><select name='mode'>
                 <option value='success'{}>成功</option>
                 <option value='timeout'{}>超时</option>
                 <option value='fail_twice'{}>前两次503</option>
                 <option value='fixed_status'{}>固定409</option>
                 <option value='rate_limited'{}>429</option>
                 </select></div>
                 <div><label>固定码</label><input name='fixed_status' value='{}'></div>
                 <div><label>Retry-After(s)</label><input name='retry_after_secs' value='{}'></div>
                 <div><label>最大尝试</label><input name='max_attempts' value='{}'></div>
                 <div><label>基础ms</label><input name='base_delay_ms' value='{}'></div>
                 <div><label>倍率</label><input name='multiplier' value='{}'></div>
                 <button class='ghost'>保存</button></form>",
                esc(&e.id), esc(&e.name),
                if e.receiver_mode=="success"{" selected"}else{""},
                if e.receiver_mode=="timeout"{" selected"}else{""},
                if e.receiver_mode=="fail_twice"{" selected"}else{""},
                if e.receiver_mode=="fixed_status"{" selected"}else{""},
                if e.receiver_mode=="rate_limited"{" selected"}else{""},
                e.fixed_status, e.retry_after_secs, e.policy.max_attempts,
                e.policy.base_delay_ms, e.policy.multiplier,
            ));
            h.push_str("</div></details>");
        }
    }
    h.push_str("</div>");

    // Event publish + signing keys
    h.push_str(r#"<div class="card"><h2>2. 创建带 JSON 载荷的事件并投递（幂等键）</h2>
<form method="post" action="/ui/events">
  <label>事件名</label><input name="name" value="订单已支付">
  <label>端点</label><select name="endpoint_id">"#);
    for e in endpoints {
        h.push_str(&format!("<option value='{}'>{}</option>", esc(&e.id), esc(&e.name)));
    }
    h.push_str(r#"</select>
  <label>幂等键</label><input name="idempotency_key" value="idem-0001">
  <label>JSON 载荷（投递时冻结字节）</label>
  <textarea name='payload'>{"order_id":"ord_0001","amount":12800,"currency":"CNY"}</textarea>
  <button>创建事件并入队</button>
</form>
<hr style="border-color:#334155;margin:14px 0">
<h2 style="margin-top:0">3. 签名密钥（有效期）</h2>
<form method="post" action="/ui/keys" class="inline">
  <div><label>标签</label><input name="label" value="轮换密钥"></div>
  <div><label>密钥原文（仅本地加密存储）</label><input name="secret" value="s3cr3t"></div>
  <div><label>有效期(秒)</label><input name="ttl_seconds" value="86400"></div>
  <button class="ghost">存入密钥</button>
</form>"#);
    h.push_str("<table style='margin-top:10px'><tr><th>key id（界面/日志仅此可见）</th><th>标签</th><th>生效</th><th>失效</th></tr>");
    for k in keys {
        h.push_str(&format!(
            "<tr><td class='mono'>{}</td><td>{}</td><td class='mono'>{}</td><td class='mono'>{}</td></tr>",
            esc(&k.id), esc(&k.label), fmt_ms(k.not_before_ms), fmt_ms(k.not_after_ms)
        ));
    }
    h.push_str("</table>");

    if !events.is_empty() {
        h.push_str("<h2 style='margin-top:14px'>编辑事件最新载荷</h2>");
        for ev in events.iter().take(3) {
            h.push_str(&format!(
                "<form method='post' action='/ui/events/edit' style='margin-bottom:8px'>
                 <input type='hidden' name='event_id' value='{}'>
                 <div class='small mut'>{} <span class='mono'>{}</span></div>
                 <textarea name='payload'>{}</textarea>
                 <button class='ghost'>更新（不影响已冻结投递）</button></form>",
                esc(&ev.id), esc(&ev.name), esc(&ev.id), esc(&ev.payload_json)
            ));
        }
    }
    h.push_str("</div></section>");
    h
}

fn render_deliveries(app: &App, deliveries: &[crate::repo::DeliveryRow]) -> String {
    let mut h = String::from("<section class=\"card\"><h2>投递队列（按根事件分组，可展开每次 attempt）</h2>");
    if deliveries.is_empty() {
        h.push_str("<p class='mut'>尚无投递。</p></section>");
        return h;
    }
    // Group by root_id to keep a delivery lineage together.
    let mut roots: Vec<String> = Vec::new();
    let mut by_root: std::collections::HashMap<String, Vec<&crate::repo::DeliveryRow>> =
        std::collections::HashMap::new();
    for d in deliveries {
        by_root.entry(d.root_id.clone()).or_default().push(d);
    }
    for d in deliveries {
        if !roots.contains(&d.root_id) {
            roots.push(d.root_id.clone());
        }
    }
    for root in roots {
        let mut gens = by_root.remove(&root).unwrap_or_default();
        gens.sort_by_key(|d| d.generation);
        let first = gens[0];
        h.push_str(&format!(
            "<details><summary><span class='pill p-{}'>{}</span> 根投递 <span class='mono'>{}</span> · 代次 {} · 幂等键 <span class='mono'>{}</span></summary><div class='attempts'>",
            esc(&first.status), esc(&first.status), esc(&root), gens.len(), esc(&first.idem_key)
        ));
        for d in &gens {
            h.push_str(&format!(
                "<div style='margin-top:10px;padding:8px;border-left:3px solid var(--accent)'>
                 <div><b>第 {} 代</b> <span class='pill p-{}'>{}</span>
                 <span class='mono small'>{}</span>
                 {}
                 </div>
                 <div class='small mut'>冻结 key_id：<span class='mono'>{}</span> · 下次可领取 t={} · 最终原因：{}</div>
                 <div class='small'>载荷：<code>{}</code></div>",
                d.generation, esc(&d.status), esc(&d.status), esc(&d.id),
                d.parent_id.as_ref().map(|p| format!("<span class='badge'>人工重放自 {}</span>", esc(p))).unwrap_or_default(),
                esc(d.frozen_key_id.as_deref().unwrap_or("<none>")),
                fmt_ms(d.next_after_ms),
                esc(d.final_reason.as_deref().unwrap_or("—")),
                esc(&d.frozen_payload),
            ));
            let attempts = app.queue.attempts(&d.id).unwrap_or_default();
            if attempts.is_empty() {
                h.push_str("<div class='small mut'>尚未生成 attempt。</div>");
            } else {
                h.push_str("<table><tr><th>#</th><th>请求摘要</th><th>key id</th><th>计划时间</th><th>状态/结果</th><th>最终原因/明细</th></tr>");
                for a in &attempts {
                    let result_text = match a.outcome_kind.as_deref() {
                        Some("success") => "<span class='ok'>2xx 成功</span>".to_string(),
                        Some("http_status") => format!(
                            "<span class='{}'>HTTP {}</span>",
                            if a.http_status.unwrap_or(0) == 429 || (500..600).contains(&a.http_status.unwrap_or(0)) {"warn"} else {"bad"},
                            a.http_status.unwrap_or(0)
                        ),
                        Some("timeout") => "<span class='warn'>超时</span>".to_string(),
                        Some("lease_lost") => "<span class='warn'>租约丢失/接管</span>".to_string(),
                        Some("error") => "<span class='bad'>传输错误</span>".to_string(),
                        _ => format!("<span class='mut'>{}</span>", esc(&a.state)),
                    };
                    let sig_fp = a
                        .signature_hex
                        .as_deref()
                        .map(fingerprint)
                        .unwrap_or_else(|| "—".to_string());
                    h.push_str(&format!(
                        "<tr><td>{}</td><td class='mono small'>POST application/json<br>X-Attempt: {}<br>签名: {}</td>
                         <td class='mono small'>{}</td>
                         <td class='mono small'>计划 {}<br>开始 {}<br>完成 {}</td>
                         <td>{}</td>
                         <td class='small'>{}</td></tr>",
                        a.attempt_no, a.attempt_no, esc(&sig_fp),
                        esc(a.key_id.as_deref().unwrap_or("<none>")),
                        fmt_ms(a.scheduled_ms),
                        a.started_ms.map(fmt_ms).unwrap_or_else(|| "—".into()),
                        a.finished_ms.map(fmt_ms).unwrap_or_else(|| "—".into()),
                        result_text,
                        esc(a.detail.as_deref().unwrap_or("—")),
                    ));
                }
                h.push_str("</table>");
            }
            h.push_str(&format!(
                "<form method='post' action='/ui/deliveries/replay' style='margin-top:6px'>
                 <input type='hidden' name='delivery_id' value='{}'>
                 <div class='inline'><div style='flex:2'><label>可选：新代次载荷（留空沿用冻结载荷）</label>
                 <input name='payload' placeholder='{{...}}'></div><div><button class='ghost'>人工重放（新建代次并链接原投递）</button></div></div>
                 </form>",
                esc(&d.id)
            ));
        }
        h.push_str("</div></details>");
    }
    h.push_str("</section>");
    h
}

fn render_audit(audit: &[(i64, String, String, String)]) -> String {
    let mut h = String::from("<section class=\"card\"><h2>事件留痕（含租约接管 / 崩溃恢复，密钥仅显示 key id）</h2>");
    h.push_str("<table><tr><th>时间</th><th>范围</th><th>引用</th><th>消息</th></tr>");
    for (at, scope, ref_id, msg) in audit {
        h.push_str(&format!(
            "<tr><td class='mono small'>{}</td><td><span class='badge'>{}</span></td><td class='mono small'>{}</td><td class='small'>{}</td></tr>",
            fmt_ms(*at), esc(scope), esc(ref_id), esc(msg)
        ));
    }
    h.push_str("</table></section>");
    h
}
