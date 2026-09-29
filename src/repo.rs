//! Data-access helpers over a shared SQLite connection.

use std::cell::RefCell;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::model::RetryPolicy;

thread_local! {
    static THREAD_CONN: RefCell<Option<Connection>> = const { RefCell::new(None) };
}

/// SQLite store backed by one database file. Each OS thread lazily opens its
/// own connection: rusqlite connections must stay on the thread that created
/// them, and moving one across threads can stall commits. The shared WAL plus
/// a busy timeout serializes writers across these connections.
pub struct Store {
    db_path: String,
}

/// Exclusive borrow of this thread's dedicated connection.
pub struct ConnGuard {
    conn: *mut Connection,
    _not_send: std::marker::PhantomData<Connection>,
}

impl std::ops::Deref for ConnGuard {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        // SAFETY: points into thread-local storage used only on this thread.
        unsafe { &*self.conn }
    }
}

impl std::ops::DerefMut for ConnGuard {
    fn deref_mut(&mut self) -> &mut Connection {
        // SAFETY: exclusive borrow on the owning thread for the guard's life.
        unsafe { &mut *self.conn }
    }
}


#[derive(Debug, Clone)]
pub struct Endpoint {
    pub id: String,
    pub name: String,
    pub target_url: String,
    pub use_fake: bool,
    pub receiver_token: String,
    pub receiver_mode: String,
    pub fixed_status: i64,
    pub retry_after_secs: i64,
    pub hits: i64,
    pub policy: RetryPolicy,
    pub created_ms: i64,
}

#[derive(Debug, Clone)]
pub struct EventRow {
    pub id: String,
    pub name: String,
    pub payload_json: String,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Debug, Clone)]
pub struct SignKeyRow {
    pub id: String,
    pub label: String,
    pub secret_enc_hex: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub created_ms: i64,
}

#[derive(Debug, Clone)]
pub struct DeliveryRow {
    pub id: String,
    pub event_id: String,
    pub endpoint_id: String,
    pub idem_key: String,
    pub content_hash: String,
    pub generation: i64,
    pub parent_id: Option<String>,
    pub root_id: String,
    pub frozen_payload: String,
    pub frozen_key_id: Option<String>,
    pub status: String,
    pub final_reason: Option<String>,
    pub attempts_used: i64,
    pub next_after_ms: i64,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Debug, Clone)]
pub struct AttemptRow {
    pub id: String,
    pub delivery_id: String,
    pub generation: i64,
    pub attempt_no: i64,
    pub key_id: Option<String>,
    pub signature_hex: Option<String>,
    pub scheduled_ms: i64,
    pub lease_owner: Option<String>,
    pub lease_expires_ms: Option<i64>,
    pub state: String,
    pub outcome_kind: Option<String>,
    pub http_status: Option<i64>,
    pub detail: Option<String>,
    pub response_excerpt: Option<String>,
    pub started_ms: Option<i64>,
    pub finished_ms: Option<i64>,
}

impl Store {
    pub fn new(conn: Connection) -> Self {
        // Discover the database file path for opening peer connections.
        let path = conn
            .query_row("PRAGMA database_list", [], |r| r.get::<_, String>(2))
            .unwrap_or_else(|_| ":memory:".to_string());
        THREAD_CONN.with(|c| *c.borrow_mut() = Some(conn));
        Self { db_path: path }
    }

    pub fn from_path(path: impl Into<String>) -> anyhow::Result<Self> {
        let conn = crate::db::connect(&path.into())?;
        Ok(Self::new(conn))
    }

    /// Access this thread's dedicated connection, opening it on first use.
    pub fn conn(&self) -> ConnGuard {
        THREAD_CONN.with(|c| {
            if c.borrow().is_none() {
                let opened = if self.db_path == ":memory:" {
                    crate::db::connect(":memory:").expect("open in-memory db")
                } else {
                    crate::db::connect_secondary(&self.db_path)
                        .expect("open thread db connection")
                };
                *c.borrow_mut() = Some(opened);
            }
            // SAFETY: thread-local, only accessed on this OS thread while the
            // guard lives; no nested conn() borrows occur in callers.
            let ptr = unsafe {
                c.as_ptr()
                    .cast::<Option<Connection>>()
                    .as_ref()
                    .expect("thread local valid")
                    .as_ref()
                    .expect("just initialized") as *const Connection as *mut Connection
            };
            ConnGuard {
                conn: ptr,
                _not_send: std::marker::PhantomData,
            }
        })
    }

    #[allow(dead_code)]
    fn _conn_unused(&self, _: *mut ()) {}

    pub fn meta_get(&self, key: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn();
        conn.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .map_err(Into::into)
    }

    pub fn meta_set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn create_endpoint(&self, e: &Endpoint) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO endpoints(id,name,target_url,use_fake,receiver_token,receiver_mode,
                fixed_status,retry_after_secs,hits,max_attempts,base_delay_ms,max_delay_ms,
                multiplier,created_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                e.id,
                e.name,
                e.target_url,
                e.use_fake as i64,
                e.receiver_token,
                e.receiver_mode,
                e.fixed_status,
                e.retry_after_secs,
                e.hits,
                e.policy.max_attempts,
                e.policy.base_delay_ms,
                e.policy.max_delay_ms,
                e.policy.multiplier,
                e.created_ms,
            ],
        )?;
        conn.execute(
            "INSERT INTO receiver_tokens(token,endpoint_id) VALUES(?1,?2)",
            params![e.receiver_token, e.id],
        )?;
        Ok(())
    }

    pub fn update_endpoint_config(
        &self,
        id: &str,
        name: &str,
        mode: &str,
        fixed_status: i64,
        retry_after_secs: i64,
        policy: &RetryPolicy,
    ) -> anyhow::Result<bool> {
        let conn = self.conn();
        let n = conn.execute(
            "UPDATE endpoints SET name=?2,receiver_mode=?3,fixed_status=?4,retry_after_secs=?5,
                max_attempts=?6,base_delay_ms=?7,max_delay_ms=?8,multiplier=?9 WHERE id=?1",
            params![
                id,
                name,
                mode,
                fixed_status,
                retry_after_secs,
                policy.max_attempts,
                policy.base_delay_ms,
                policy.max_delay_ms,
                policy.multiplier,
            ],
        )?;
        Ok(n == 1)
    }

    pub fn increment_hits(&self, endpoint_id: &str) -> anyhow::Result<i64> {
        let hits = {
            let conn = self.conn();
            conn.execute(
                "UPDATE endpoints SET hits = hits + 1 WHERE id=?1",
                params![endpoint_id],
            )?;
            conn.query_row(
                "SELECT hits FROM endpoints WHERE id=?1",
                params![endpoint_id],
                |r| r.get(0),
            )?
        };
        Ok(hits)
    }

    pub fn endpoint_by_token(&self, token: &str) -> anyhow::Result<Option<Endpoint>> {
        let conn = self.conn();
        conn.query_row(
            "SELECT e.* FROM endpoints e JOIN receiver_tokens t ON t.endpoint_id=e.id
             WHERE t.token=?1",
            params![token],
            map_endpoint,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn endpoint(&self, id: &str) -> anyhow::Result<Option<Endpoint>> {
        let conn = self.conn();
        conn.query_row("SELECT * FROM endpoints WHERE id=?1", params![id], map_endpoint)
            .optional()
            .map_err(Into::into)
    }

    pub fn list_endpoints(&self) -> anyhow::Result<Vec<Endpoint>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM endpoints ORDER BY created_ms,id")?;
        let rows = stmt.query_map([], map_endpoint)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn create_event(&self, e: &EventRow, payload: &Value) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO events(id,name,payload_json,created_ms,updated_ms)
             VALUES(?1,?2,?3,?4,?5)",
            params![e.id, e.name, payload.to_string(), e.created_ms, e.updated_ms],
        )?;
        Ok(())
    }

    pub fn update_event_payload(
        &self,
        id: &str,
        payload: &Value,
        updated_ms: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn();
        let n = conn.execute(
            "UPDATE events SET payload_json=?2,updated_ms=?3 WHERE id=?1",
            params![id, payload.to_string(), updated_ms],
        )?;
        Ok(n == 1)
    }

    pub fn event(&self, id: &str) -> anyhow::Result<Option<EventRow>> {
        let conn = self.conn();
        conn.query_row("SELECT * FROM events WHERE id=?1", params![id], |r| {
            Ok(EventRow {
                id: r.get(0)?,
                name: r.get(1)?,
                payload_json: r.get(2)?,
                created_ms: r.get(3)?,
                updated_ms: r.get(4)?,
            })
        })
        .optional()
        .map_err(Into::into)
    }

    pub fn list_events(&self) -> anyhow::Result<Vec<EventRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT * FROM events ORDER BY created_ms,id")?;
        let rows = stmt.query_map([], |r| {
            Ok(EventRow {
                id: r.get(0)?,
                name: r.get(1)?,
                payload_json: r.get(2)?,
                created_ms: r.get(3)?,
                updated_ms: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn create_key(&self, k: &SignKeyRow) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sign_keys(id,label,secret_enc_hex,not_before_ms,not_after_ms,created_ms)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                k.id,
                k.label,
                k.secret_enc_hex,
                k.not_before_ms,
                k.not_after_ms,
                k.created_ms
            ],
        )?;
        Ok(())
    }

    pub fn list_keys(&self) -> anyhow::Result<Vec<SignKeyRow>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT * FROM sign_keys ORDER BY not_before_ms,id")?;
        let rows = stmt.query_map([], |r| {
            Ok(SignKeyRow {
                id: r.get(0)?,
                label: r.get(1)?,
                secret_enc_hex: r.get(2)?,
                not_before_ms: r.get(3)?,
                not_after_ms: r.get(4)?,
                created_ms: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Select the signing key valid at `at_ms`: not_before <= at < not_after.
    /// Among matching keys the earliest created wins deterministically.
    pub fn key_valid_at(&self, at_ms: i64) -> anyhow::Result<Option<SignKeyRow>> {
        let conn = self.conn();
        conn.query_row(
            "SELECT * FROM sign_keys WHERE not_before_ms <= ?1 AND not_after_ms > ?1
             ORDER BY created_ms, id LIMIT 1",
            params![at_ms],
            |r| {
                Ok(SignKeyRow {
                    id: r.get(0)?,
                    label: r.get(1)?,
                    secret_enc_hex: r.get(2)?,
                    not_before_ms: r.get(3)?,
                    not_after_ms: r.get(4)?,
                    created_ms: r.get(5)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn audit(&self, scope: &str, ref_id: &str, message: &str, at_ms: i64) {
        if let Err(e) = (|| -> rusqlite::Result<()> {
            let conn = self.conn();
            conn.execute(
                "INSERT INTO audit(at_ms,scope,ref_id,message) VALUES(?1,?2,?3,?4)",
                params![at_ms, scope, ref_id, message],
            )?;
            Ok(())
        })() {
            eprintln!("audit write failed: {e}");
        }
    }

    pub fn list_audit(&self, limit: i64) -> anyhow::Result<Vec<(i64, String, String, String)>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT at_ms,scope,ref_id,message FROM audit ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn map_endpoint(r: &rusqlite::Row<'_>) -> rusqlite::Result<Endpoint> {
    Ok(Endpoint {
        id: r.get(0)?,
        name: r.get(1)?,
        target_url: r.get(2)?,
        use_fake: r.get::<_, i64>(3)? != 0,
        receiver_token: r.get(4)?,
        receiver_mode: r.get(5)?,
        fixed_status: r.get(6)?,
        retry_after_secs: r.get(7)?,
        hits: r.get(8)?,
        policy: RetryPolicy {
            max_attempts: r.get(9)?,
            base_delay_ms: r.get(10)?,
            max_delay_ms: r.get(11)?,
            multiplier: r.get(12)?,
        },
        created_ms: r.get(13)?,
    })
}

/// Canonicalize a JSON value so semantically equal create requests produce the
/// same content hash (key order independent).
pub fn canonical_content_hash(payload: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = canonicalize(payload);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

fn canonicalize(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", escape_str(k), canonicalize(&map[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonicalize).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

fn escape_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}
