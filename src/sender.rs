//! Minimal local-only HTTP/1.1 sender built on `std::net`.
//!
//! Deliveries always target the built-in fake receiver on loopback, so a full
//! HTTP client dependency is unnecessary. The sender pins the exact frozen
//! payload bytes and the signing key selected at enqueue time.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::model::AttemptOutcome;
use crate::queue::CallResult;
use crate::repo::{DeliveryRow, Endpoint};

pub struct SendOutcome {
    pub outcome: AttemptOutcome,
    pub excerpt: Option<String>,
}

/// Parse `http://host:port/path` into (host:port, path).
pub fn split_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    Some((authority.to_string(), path.to_string()))
}

pub fn send(
    endpoint: &Endpoint,
    delivery: &DeliveryRow,
    attempt_no: i64,
    signature_hex: Option<&str>,
    timeout: Duration,
) -> SendOutcome {
    let Some((authority, path)) = split_url(&endpoint.target_url) else {
        return SendOutcome {
            outcome: AttemptOutcome::Error(format!("invalid target URL {}", endpoint.target_url)),
            excerpt: None,
        };
    };

    let body = delivery.frozen_payload.as_bytes();
    let mut req = String::new();
    req.push_str(&format!("POST {path} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {authority}\r\n"));
    req.push_str("Content-Type: application/json\r\n");
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    req.push_str(&format!("X-Delivery-Id: {}\r\n", delivery.id));
    req.push_str(&format!("X-Delivery-Generation: {}\r\n", delivery.generation));
    req.push_str(&format!("X-Attempt-Number: {attempt_no}\r\n"));
    if let Some(key_id) = &delivery.frozen_key_id {
        req.push_str(&format!("X-Webhook-Key: {key_id}\r\n"));
    }
    if let Some(sig) = signature_hex {
        req.push_str(&format!("X-Webhook-Signature: {sig}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");

    let addr = match resolve_authority(&authority) {
        Some(a) => a,
        None => {
            return SendOutcome {
                outcome: AttemptOutcome::Error(format!("resolve failed for {authority}")),
                excerpt: None,
            }
        }
    };
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            return SendOutcome {
                outcome: if e.kind() == std::io::ErrorKind::TimedOut {
                    AttemptOutcome::Timeout
                } else {
                    AttemptOutcome::Error(format!("connect: {e}"))
                },
                excerpt: None,
            }
        }
    };

    // Drive the socket in non-blocking mode with an explicit monotonic
    // deadline. Relying on WouldBlock/TimedOut raw_os mappings is platform
    // dependent (macOS surfaces EAGAIN as Uncategorized), so a deadline makes
    // timeout behavior deterministic for the virtual-clock test suite.
    stream.set_nonblocking(true).ok();
    let deadline = std::time::Instant::now() + timeout;
    let mut written = 0usize;
    let all: Vec<u8> = req
        .as_bytes()
        .iter()
        .chain(body.iter())
        .copied()
        .collect();
    while written < all.len() {
        if std::time::Instant::now() >= deadline {
            return SendOutcome {
                outcome: AttemptOutcome::Timeout,
                excerpt: None,
            };
        }
        match stream.write(&all[written..]) {
            Ok(0) => {
                return SendOutcome {
                    outcome: AttemptOutcome::Error("write: unexpected EOF".into()),
                    excerpt: None,
                }
            }
            Ok(n) => written += n,
            Err(ref e) if would_block(e) => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => {
                return SendOutcome {
                    outcome: AttemptOutcome::Error(format!("write: {e}")),
                    excerpt: None,
                };
            }
        }
    }
    let _ = stream.flush();
    // Signal end of request so the receiver can finish writing its response.
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if std::time::Instant::now() >= deadline {
            return SendOutcome {
                outcome: AttemptOutcome::Timeout,
                excerpt: None,
            };
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(ref e) if would_block(e) => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => {
                return SendOutcome {
                    outcome: AttemptOutcome::Error(format!("read: {e}")),
                    excerpt: None,
                };
            }
        }
    }

    parse_http_response(&buf)
}

fn would_block(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn resolve_authority(authority: &str) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    authority.to_socket_addrs().ok()?.next()
}

fn parse_http_response(raw: &[u8]) -> SendOutcome {
    let text = String::from_utf8_lossy(raw);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok());
    let excerpt = excerpt_body(raw);
    match status {
        Some(code) => SendOutcome {
            outcome: AttemptOutcome::HttpStatus(code),
            excerpt,
        },
        None => SendOutcome {
            outcome: AttemptOutcome::Error(format!(
                "malformed response ({} bytes)",
                raw.len()
            )),
            excerpt: None,
        },
    }
}

fn excerpt_body(raw: &[u8]) -> Option<String> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let body = &raw[split + 4..];
    let text = String::from_utf8_lossy(body);
    let trimmed: String = text.chars().take(200).collect();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Convenience wrapper used by workers: stamps the finish time from a clock.
pub fn send_stamped(
    endpoint: &Endpoint,
    delivery: &DeliveryRow,
    attempt_no: i64,
    signature_hex: Option<&str>,
    timeout: Duration,
    finished_ms: i64,
) -> CallResult {
    let r = send(endpoint, delivery, attempt_no, signature_hex, timeout);
    CallResult {
        outcome: r.outcome,
        response_excerpt: r.excerpt,
        finished_ms,
    }
}
