//! Webhook 重放站 (Webhook replay station): a fully local webhook delivery
//! lab with SQLite state, a programmable fake receiver, virtual-clock driven
//! retries, lease-based queue claiming and crash-safe attempt receipts.

pub mod crypto;
pub mod db;
pub mod ids;
pub mod model;
pub mod queue;
pub mod receiver;
pub mod repo;
pub mod sender;
pub mod service;
pub mod worker;

pub mod web;

use std::sync::Arc;

use crate::model::{Clock, SystemClock};

/// Wiring shared by the binary and tests.
pub struct BuiltApp {
    pub app: service::App,
    pub store: Arc<Store>,
    pub queue: Arc<queue::Queue>,
    pub receiver: receiver::ReceiverServer,
    pub cipher: crypto::Cipher,
    pub clock: Arc<dyn Clock>,
}

pub struct BuildOptions<'a> {
    pub db_path: &'a str,
    pub master_key_path: &'a str,
    pub receiver_listen: &'a str,
    pub clock: Option<Arc<dyn Clock>>,
    pub lease_ms: i64,
}

/// Build the full app and start the in-process fake receiver. `db_path` may be
/// ":memory:" (use a shared-cache style single connection; the Store holds one
/// connection guarded by a mutex, which is sufficient for this workload).
pub fn build(opts: BuildOptions) -> anyhow::Result<BuiltApp> {
    let master = crypto::load_or_create_master_key(std::path::Path::new(opts.master_key_path))?;
    let cipher = crypto::Cipher::new(master);
    let conn = db::connect(opts.db_path)?;
    let store = Arc::new(repo::Store::new(conn));
    let clock: Arc<dyn Clock> = opts.clock.unwrap_or_else(|| Arc::new(SystemClock));
    let qcfg = queue::QueueConfig {
        lease_ms: opts.lease_ms,
    };
    let q = Arc::new(queue::Queue::new(
        Arc::clone(&store),
        Arc::clone(&clock),
        cipher.clone(),
        qcfg,
    ));
    let receiver_server = receiver::start(opts.receiver_listen, Arc::clone(&store), cipher.clone(), opts.db_path)?;
    let app = service::App {
        store: Arc::clone(&store),
        queue: Arc::clone(&q),
        cipher: cipher.clone(),
        clock: Arc::clone(&clock),
        receiver_base: receiver_server.url_base.clone(),
    };
    // Reconcile anything left over from a previous (crashed) run before serving.
    q.recover_all()?;
    Ok(BuiltApp {
        app,
        store,
        queue: q,
        receiver: receiver_server,
        cipher,
        clock,
    })
}

/// Test helper: in-memory DB, ephemeral receiver port, fake clock.
pub fn build_test(clock: Arc<dyn Clock>, lease_ms: i64) -> (BuiltApp, tempfile_lite::TempDir) {
    let dir = tempfile_lite::tempdir().expect("tempdir");
    let db_path = dir.path().join("state.db");
    let key_path = dir.path().join("master.key");
    let built = build(BuildOptions {
        db_path: db_path.to_str().unwrap(),
        master_key_path: key_path.to_str().unwrap(),
        receiver_listen: "127.0.0.1:0",
        clock: Some(clock),
        lease_ms,
    })
    .expect("build app");
    (built, dir)
}

/// Minimal temp-dir support without pulling an extra crate.
pub mod tempfile_lite {
    use std::path::{Path, PathBuf};

    pub struct TempDir {
        path: PathBuf,
    }

    pub fn tempdir() -> std::io::Result<TempDir> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        let base = std::env::var("WEBHOOK_TEST_TMP")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::current_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
                    .join("target")
                    .join("test-tmp")
            });
        std::fs::create_dir_all(&base)?;
        let path = base.join(format!("webhook-replay-{pid}-{unique}"));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    impl TempDir {
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

pub use service::App;
pub use repo::Store;
