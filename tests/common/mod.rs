//! Shared test harness: virtual clock, file-backed SQLite, ephemeral
//! receiver and short request timeouts; nothing touches the network.

#![allow(dead_code)]

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

/// Tests share process-wide in-memory receiver state and random ephemeral
/// resources; serialize Harness construction/use to keep them deterministic.
static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn test_lock() -> MutexGuard<'static, ()> {
    TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

use webhook_replay::model::{Clock, FakeClock, ReceiverMode, RetryPolicy};
use webhook_replay::queue::Queue;
use webhook_replay::service::App;
use webhook_replay::worker::Worker;
use webhook_replay::{build, BuildOptions, BuiltApp};

pub struct Harness {
    pub built: BuiltApp,
    pub app: Arc<App>,
    pub clock: Arc<FakeClock>,
    pub dir: webhook_replay::tempfile_lite::TempDir,
}

impl Harness {
    pub fn new(lease_ms: i64) -> Self {
        let _g = test_lock();
        let clock = Arc::new(FakeClock::new(1_000_000));
        let dir = webhook_replay::tempfile_lite::tempdir().expect("tempdir");
        let db_path = dir.path().join("state.db");
        let key_path = dir.path().join("master.key");
        let built = build(BuildOptions {
            db_path: db_path.to_str().unwrap(),
            master_key_path: key_path.to_str().unwrap(),
            receiver_listen: "127.0.0.1:0",
            clock: Some(clock.clone()),
            lease_ms,
        })
        .expect("build app");
        let app = Arc::new(built.app.dup());
        Self { built, app, clock, dir }
    }

    pub fn queue(&self) -> Arc<Queue> {
        Arc::clone(&self.built.queue)
    }

    pub fn worker(&self) -> Worker {
        let b = &self.built;
        Worker::new(
            Arc::clone(&b.queue),
            Arc::clone(&b.store),
            Arc::clone(&b.clock),
            Duration::from_millis(300),
        )
    }

    pub fn base_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 6,
            base_delay_ms: 1_000,
            max_delay_ms: 60_000,
            multiplier: 2.0,
        }
    }

    pub fn make_endpoint(&self, mode: ReceiverMode) -> String {
        self.app
            .create_endpoint("ep", mode, 409, 3, Self::base_policy(), None, true)
            .unwrap()
            .endpoint
            .id
    }

    pub fn key(&self, label: &str, secret: &str, start_offset_ms: i64, ttl_ms: i64) -> String {
        let now = self.clock.now_ms();
        self.app
            .create_signing_key(label, secret, now + start_offset_ms, now + start_offset_ms + ttl_ms)
            .unwrap()
            .id
    }

    pub fn run_due(&self) -> usize {
        let w = self.worker();
        let mut n = 0;
        while w.tick().unwrap() {
            n += 1;
        }
        n
    }

    fn stop_receiver(&self) {
        // Joins the receiver threads, releasing their connection before the
        // temp database directory is removed.
        self.built.receiver.shutdown();
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop_receiver();
    }
}
