//! Programmable fake webhook receiver served over plain HTTP on loopback.
//!
//! No external network is needed for demos or tests. Each registered endpoint
//! owns an unguessable token and is addressed as `/recv/<token>`. The response
//! behavior is controlled per endpoint from the UI/API. The receiver echoes the
//! signature key id (never the secret) and verifies the HMAC when a key exists.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

static ALIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// In-memory mode counters for the programmable receiver. These are deliberately
// NOT durable: they model receiver behavior, and a fresh process starts from
// the first failure again (which keeps demos deterministic).
static FAIL_TWICE_HITS: std::sync::LazyLock<Mutex<HashMap<String, i64>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn fail_twice_hit(endpoint_id: &str) -> i64 {
    let mut m = FAIL_TWICE_HITS.lock().unwrap();
    let n = m.entry(endpoint_id.to_string()).or_insert(0);
    *n += 1;
    *n
}

/// Reset a receiver's in-memory behavior counters (used by tests/seeding).
pub fn reset_endpoint_counters(endpoint_id: &str) {
    FAIL_TWICE_HITS.lock().unwrap().remove(endpoint_id);
}

fn alive() -> bool {
    ALIVE.load(std::sync::atomic::Ordering::SeqCst)
}

use crate::crypto::Cipher;
use crate::model::ReceiverMode;
use crate::repo::Store;

pub struct ReceiverServer {
    pub addr: String,
    pub url_base: String,
    pub shutdown: Arc<std::sync::atomic::AtomicBool>,
    join: Mutex<Option<Vec<std::thread::JoinHandle<()>>>>,
}

impl ReceiverServer {
    /// Signal the accept and db loops to stop and wait for them to exit, so the
    /// receiver connection is released deterministically (important for tests
    /// that delete the database directory immediately afterwards).
    pub fn shutdown(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        ALIVE.store(false, std::sync::atomic::Ordering::SeqCst);
        // Bounded wait: a timeout-mode request keeps the db thread briefly
        // busy; never block shutdown indefinitely waiting for it.
        if let Some(handles) = self.join.lock().unwrap().take() {
            for h in handles {
                // Wait briefly for a clean exit; if a timeout-mode handler is
                // still lingering, detach instead of blocking teardown.
                for _ in 0..50 {
                    if h.is_finished() {
                        let _ = h.join();
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            }
        }
    }
}

impl Drop for ReceiverServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn url_for(url_base: &str, token: &str) -> String {
    format!("{}/recv/{token}", url_base.trim_end_matches('/'))
}

/// Handle an accepted socket on the single receiver thread.
fn serve_connection(mut sock: TcpStream, store: &Store, cipher: &Cipher) {
    if let Err(e) = handle(&mut sock, store, cipher) {
        eprintln!("receiver connection error: {e}");
    }
}

pub fn start(
    listen: &str,
    store: Arc<Store>,
    cipher: Cipher,
    db_path: &str,
) -> anyhow::Result<ReceiverServer> {
    let _ = store; // schema is already migrated on the primary connection
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    let local = listener.local_addr()?.to_string();
    let url_base = format!("http://{local}");
    ALIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // The receiver uses exactly ONE connection, owned by ONE dedicated thread.
    // Open it synchronously on that thread before we return so directory
    // lifetime races and migration ordering are deterministic.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<anyhow::Result<()>>();
    let (tx, rx) = std::sync::mpsc::channel::<TcpStream>();
    let recv_db_path = db_path.to_string();
    let recv_cipher = cipher.clone();
    let db_handle = std::thread::Builder::new()
        .name("fake-receiver-db".into())
        .spawn(move || {
            match Store::from_path(recv_db_path) {
                Ok(receiver_store) => {
                    ready_tx.send(Ok(())).ok();
                    for sock in rx {
                        serve_connection(sock, &receiver_store, &recv_cipher);
                    }
                }
                Err(e) => {
                    ready_tx.send(Err(e)).ok();
                }
            }
        })?;
    ready_rx.recv()??;
    let db_handle = db_handle;

    let shutdown_accept = Arc::clone(&shutdown);
    let accept_handle = std::thread::Builder::new()
        .name("fake-receiver-accept".into())
        .spawn(move || {
            while !shutdown_accept.load(std::sync::atomic::Ordering::SeqCst) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        if tx.send(sock).is_err() {
                            break;
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => {
                        eprintln!("receiver accept error: {e}");
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
            // Dropping the only sender closes the channel so the db thread
            // exits and releases its connection when the server shuts down.
            drop(tx);
        })?;

    Ok(ReceiverServer {
        addr: local,
        url_base,
        shutdown,
        join: Mutex::new(Some(vec![db_handle, accept_handle])),
    })
}

struct Parsed {
    path: String,
    key_id: Option<String>,
    signature: Option<String>,
    body: Vec<u8>,
}

fn handle(sock: &mut TcpStream, store: &Store, cipher: &Cipher) -> anyhow::Result<()> {
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header_end = None;
    // Read headers then honor Content-Length for the body.
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
        if raw.len() > 1_000_000 {
            break;
        }
    }
    let Some(header_end) = header_end else {
        write_response(sock, 400, "Bad Request", "incomplete request")?;
        return Ok(());
    };
    let header_text = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let _method = parts.next();
    let path = parts.next().unwrap_or("/").to_string();
    let mut key_id = None;
    let mut signature = None;
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim().to_lowercase(), v.trim().to_string());
            match k.as_str() {
                "x-webhook-key" => key_id = Some(v),
                "x-webhook-signature" => signature = Some(v),
                "content-length" => content_length = v.parse().unwrap_or(0),
                _ => {}
            }
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
    let body = raw[body_start..body_start + content_length.min(raw.len() - body_start)].to_vec();
    let parsed = Parsed {
        path,
        key_id,
        signature,
        body,
    };
    route(sock, store, cipher, parsed)
}

fn route(
    sock: &mut TcpStream,
    store: &Store,
    cipher: &Cipher,
    req: Parsed,
) -> anyhow::Result<()> {
    let Some(token) = req.path.strip_prefix("/recv/") else {
        write_response(sock, 404, "Not Found", "unknown path")?;
        return Ok(());
    };
    let token = token.split('?').next().unwrap_or(token);
    let Some(endpoint) = store.endpoint_by_token(token)? else {
        write_response(sock, 404, "Not Found", "no such receiver token")?;
        return Ok(());
    };

    // Verify signature against the key id the sender froze onto the attempt.
    if let Some(sig) = &req.signature {
        let mut valid = false;
        for k in store.list_keys()? {
            if req.key_id.as_deref() == Some(k.id.as_str()) {
                let secret = cipher.decrypt_hex(&k.secret_enc_hex)?;
                valid = crate::crypto::verify_payload(&secret, &req.body, sig);
                break;
            }
        }
        if !valid {
            write_response(sock, 401, "Unauthorized", "signature verification failed")?;
            eprintln!("receiver {} rejected bad signature", endpoint.id);
            return Ok(());
        }
    }

    let mode = ReceiverMode::parse(&endpoint.receiver_mode).unwrap_or(ReceiverMode::Success);
    match mode {
        ReceiverMode::Timeout => {
            // Hold the connection open without answering. The sender's read
            // deadline fires and it closes the socket; this thread notices
            // within a couple of seconds and exits instead of lingering for
            // the full timeout window. Clear the earlier blocking read timeout
            // so our own short probe timeout is the one that applies.
            let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = sock.set_nonblocking(false);
            let mut probe = [0u8; 16];
            let deadline = std::time::Instant::now() + Duration::from_millis(800);
            while alive() {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                match sock.read(&mut probe) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => break,
                }
            }
            let _ = write_response(sock, 200, "OK", "late");
        }
        ReceiverMode::FailTwice => {
            let hits = fail_twice_hit(&endpoint.id);
            if hits <= 2 {
                write_response(sock, 503, "Service Unavailable", "transient failure")?;
            } else {
                write_response(sock, 200, "OK", "accepted after two failures")?;
            }
        }
        ReceiverMode::FixedStatus => {
            let code = endpoint.fixed_status.clamp(100, 599) as u16;
            write_response(sock, code, "Conflict", "fixed status response")?;
        }
        ReceiverMode::RateLimited => {
            write_response_with_headers(
                sock,
                429,
                "Too Many Requests",
                "rate limited",
                &[("Retry-After", endpoint.retry_after_secs.max(0).to_string())],
            )?;
        }
        ReceiverMode::Success => {
            write_response(sock, 200, "OK", "accepted")?;
        }
    }
    Ok(())
}

fn write_response(
    sock: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    write_response_with_headers(sock, status, reason, body, &[])
}

fn write_response_with_headers(
    sock: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    extra: &[(&str, String)],
) -> std::io::Result<()> {
    let bytes = body.as_bytes();
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        bytes.len()
    );
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    sock.write_all(head.as_bytes())?;
    sock.write_all(bytes)?;
    sock.flush()
}


