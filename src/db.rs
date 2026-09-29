//! SQLite storage: schema, migrations and typed row models.

use rusqlite::Connection;

pub fn connect(path: &str) -> anyhow::Result<Connection> {
    // Retry the whole open+configure sequence. Under heavy parallel test
    // startup SQLite can transiently return SQLITE_BUSY or an fstat I/O error
    // on the host filesystem; these clear within milliseconds.
    let mut last: Option<anyhow::Error> = None;
    if path != ":memory:" {
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    for attempt in 0..100u32 {
        if path != ":memory:" {
            if let Some(parent) = std::path::Path::new(path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        match connect_once(path) {
            Ok(c) => return Ok(c),
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                let transient = msg.contains("locked")
                    || msg.contains("fstat")
                    || msg.contains("1802")
                    || msg.contains("i/o error")
                    || msg.contains("disk i/o")
                    || msg.contains("unable to open")
                    || msg.contains("code 14");
                last = Some(e);
                if transient && attempt < 99 {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
                break;
            }
        }
    }
    Err(last.unwrap())
}

fn connect_once(path: &str) -> anyhow::Result<Connection> {
    let conn = if path == ":memory:" {
        Connection::open_in_memory()?
    } else {
        Connection::open(path)?
    };
    conn.busy_timeout(std::time::Duration::from_secs(15))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    with_retry(|| conn.pragma_update(None, "journal_mode", "WAL"))?;
    migrate(&conn)?;
    Ok(conn)
}

fn with_retry<T>(mut f: impl FnMut() -> rusqlite::Result<T>) -> anyhow::Result<T> {
    let mut last = None;
    for attempt in 0..50u32 {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let busy = e.to_string().to_lowercase().contains("locked");
                last = Some(e);
                if busy && attempt < 99 {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
                break;
            }
        }
    }
    Err(last.unwrap().into())
}

/// Open another connection to the same database for use from a distinct OS
/// thread. rusqlite/SQLite connections have thread affinity: sharing one
/// connection between the worker thread and the receiver thread can block on
/// commit even when guarded by a Rust mutex, so the receiver gets its own.
pub fn connect_secondary(path: &str) -> anyhow::Result<Connection> {
    // No journal-mode change and no migration here: the primary connection has
    // already created the schema and set WAL. Flipping journal modes from a
    // second connection concurrently causes SQLITE_BUSY during test startup.
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(15))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "query_only", false)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    target_url       TEXT NOT NULL,
    use_fake         INTEGER NOT NULL DEFAULT 1,
    receiver_token   TEXT NOT NULL,
    receiver_mode    TEXT NOT NULL DEFAULT 'success',
    fixed_status     INTEGER NOT NULL DEFAULT 409,
    retry_after_secs INTEGER NOT NULL DEFAULT 3,
    hits             INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL,
    base_delay_ms    INTEGER NOT NULL,
    max_delay_ms     INTEGER NOT NULL,
    multiplier       REAL NOT NULL,
    created_ms       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    -- Last-edited JSON; historical deliveries hold their own frozen copy.
    payload_json TEXT NOT NULL,
    created_ms  INTEGER NOT NULL,
    updated_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sign_keys (
    id              TEXT PRIMARY KEY,
    label           TEXT NOT NULL,
    secret_enc_hex  TEXT NOT NULL,
    not_before_ms   INTEGER NOT NULL,
    not_after_ms    INTEGER NOT NULL,
    created_ms      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS deliveries (
    id             TEXT PRIMARY KEY,
    event_id       TEXT NOT NULL REFERENCES events(id),
    endpoint_id    TEXT NOT NULL REFERENCES endpoints(id),
    idem_key       TEXT NOT NULL,
    content_hash   TEXT NOT NULL,
    generation     INTEGER NOT NULL DEFAULT 1,
    parent_id      TEXT,
    root_id        TEXT NOT NULL,
    frozen_payload TEXT NOT NULL,
    frozen_key_id  TEXT,
    status         TEXT NOT NULL DEFAULT 'queued',
    final_reason   TEXT,
    attempts_used  INTEGER NOT NULL DEFAULT 0,
    next_after_ms  INTEGER NOT NULL DEFAULT 0,
    created_ms     INTEGER NOT NULL,
    updated_ms     INTEGER NOT NULL,
    UNIQUE(endpoint_id, idem_key, generation)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due
    ON deliveries(status, next_after_ms);
CREATE INDEX IF NOT EXISTS idx_deliveries_root ON deliveries(root_id);

CREATE TABLE IF NOT EXISTS attempts (
    id              TEXT PRIMARY KEY,
    delivery_id     TEXT NOT NULL REFERENCES deliveries(id),
    generation      INTEGER NOT NULL,
    attempt_no      INTEGER NOT NULL,
    key_id          TEXT,
    signature_hex   TEXT,
    scheduled_ms    INTEGER NOT NULL,
    lease_owner     TEXT,
    lease_expires_ms INTEGER,
    state           TEXT NOT NULL DEFAULT 'leased',
    outcome_kind    TEXT,
    http_status     INTEGER,
    detail          TEXT,
    response_excerpt TEXT,
    started_ms      INTEGER,
    finished_ms     INTEGER,
    UNIQUE(delivery_id, attempt_no)
);
CREATE INDEX IF NOT EXISTS idx_attempts_lease ON attempts(state, lease_expires_ms);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
            at_ms INTEGER NOT NULL,
    scope       TEXT NOT NULL,
    ref_id      TEXT NOT NULL,
    message     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receiver_tokens (
    token       TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id)
);
        "#,
    )?;
    Ok(())
}
