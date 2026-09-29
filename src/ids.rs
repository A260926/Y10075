//! Human-readable prefixed random identifiers.

use rand::RngCore;

fn rand_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn endpoint_id() -> String {
    format!("ep_{}", rand_hex(8))
}
pub fn event_id() -> String {
    format!("ev_{}", rand_hex(8))
}
pub fn key_id() -> String {
    format!("key_{}", rand_hex(8))
}
pub fn delivery_id() -> String {
    format!("dlv_{}", rand_hex(10))
}
pub fn attempt_id() -> String {
    format!("att_{}", rand_hex(10))
}
pub fn receiver_token() -> String {
    format!("tok_{}", rand_hex(12))
}
pub fn worker_id() -> String {
    format!("wkr_{}", rand_hex(6))
}
