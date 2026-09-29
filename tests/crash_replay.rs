#[path="common/mod.rs"]
mod harness;

use std::sync::Arc;

use serde_json::json;

use webhook_replay::model::ReceiverMode;
use webhook_replay::queue::EnqueueResult;
use webhook_replay::worker::Worker;

use harness::Harness;

#[test]
fn restart_reconciles_dropped_receipt_without_duplicate_send() {
    // This test actually re-executes the test binary: the child creates a
    // delivery, receives the response (receipt committed), then exits via the
    // crash hook before finalizing. The parent reopens the same SQLite file,
    // reconciles the receipt and asserts no second HTTP attempt was made.
    let dir = match std::env::var("CRASH_DIR") {
        Ok(d) => std::path::PathBuf::from(d),
        Err(_) => std::env::temp_dir().join(format!(
            "webhook-crash-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )),
    };
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("crash.db");
    let mk = dir.join("master.key");

    if std::env::var("CRASH_CHILD").as_deref() == Ok("1") {
        let clock = Arc::new(webhook_replay::model::FakeClock::new(2_000_000));
        let built = webhook_replay::build(webhook_replay::BuildOptions {
            db_path: db.to_str().unwrap(),
            master_key_path: mk.to_str().unwrap(),
            receiver_listen: "127.0.0.1:0",
            clock: Some(clock),
            lease_ms: 15_000,
        })
        .unwrap();
        let ep = built
            .app
            .create_endpoint(
                "ep",
                ReceiverMode::FailTwice,
                409,
                3,
                Harness::base_policy(),
                None,
                true,
            )
            .unwrap();
        let (_e, r) = built
            .app
            .publish("e", &json!({"x": 1}), &ep.endpoint.id, "idem-crash")
            .unwrap();
        assert!(matches!(r, EnqueueResult::Created(_)));
        webhook_replay::queue::arm_crash_after_receipt();
        let worker = Worker::new(
            Arc::clone(&built.queue),
            Arc::clone(&built.store),
            Arc::clone(&built.clock),
            std::time::Duration::from_millis(300),
        );
        // First tick 503s: the hook exits after the FIRST receipt, so the
        // durable row is state='responded' but delivery is still 'sending'.
        let _ = worker.tick();
        panic!("child should have exited");
    }

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("restart_reconciles_dropped_receipt_without_duplicate_send")
        .arg("--exact")
        .arg("--nocapture")
        .env("CRASH_CHILD", "1")
        .env("CRASH_DIR", &dir)
        .status()
        .unwrap();
    assert!(!status.success(), "child should have been killed by exit(7)");

    // Reopen with a real filesystem-backed DB exactly like a restart.
    let clock2 = Arc::new(webhook_replay::model::FakeClock::new(2_000_000 + 500));
    let clock2_dyn: Arc<dyn webhook_replay::model::Clock> = clock2.clone();
    let built2 = webhook_replay::build(webhook_replay::BuildOptions {
        db_path: db.to_str().unwrap(),
        master_key_path: mk.to_str().unwrap(),
        receiver_listen: "127.0.0.1:0",
        clock: Some(clock2_dyn),
        lease_ms: 15_000,
    })
    .unwrap();

    let deliveries = built2.queue.list_deliveries().unwrap();
    assert_eq!(deliveries.len(), 1);
    let id = deliveries[0].id.clone();

    // Build() already ran recover_all: the receipt is reconciled to queued
    // (503 is retryable). Exactly one attempt row exists and it is done.
    let attempts = built2.queue.attempts(&id).unwrap();
    assert_eq!(attempts.len(), 1, "no duplicate send during recovery");
    assert_eq!(attempts[0].state, "done");
    assert_eq!(attempts[0].http_status, Some(503));
    let d = built2.queue.delivery(&id).unwrap().unwrap();
    assert_eq!(d.status, "queued");
    assert_eq!(d.attempts_used, 1);

    // Advancing the clock now sends attempt 2, not a repeat of attempt 1.
    clock2.advance(1_000);
    let worker2 = Worker::new(
        Arc::clone(&built2.queue),
        Arc::clone(&built2.store),
        Arc::clone(&built2.clock),
        std::time::Duration::from_millis(300),
    );
    assert!(worker2.tick().unwrap());
    let attempts = built2.queue.attempts(&id).unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].attempt_no, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manual_replay_creates_linked_generation_keeping_old_attempts() {
    let h = Harness::new(15_000);
    let ep = h.make_endpoint(ReceiverMode::FixedStatus);
    let id = {
        let (_e, r) = h
            .app
            .publish("e", &json!({"v": 1}), &ep, "idem-replay")
            .unwrap();
        match r {
            EnqueueResult::Created(d) => d.id,
            _ => panic!(),
        }
    };
    h.run_due(); // 409 terminal
    let original = h.queue().delivery(&id).unwrap().unwrap();
    assert_eq!(original.status, "failed");
    assert_eq!(original.generation, 1);
    assert_eq!(h.queue().attempts(&id).unwrap().len(), 1);

    // Replay with new payload -> new generation linked to the original; the
    // old attempt remains visible.
    let gen2 = h
        .queue()
        .manual_replay(&id, Some(r#"{"v":2}"#))
        .unwrap();
    assert_eq!(gen2.generation, 2);
    assert_eq!(gen2.parent_id.as_deref(), Some(id.as_str()));
    assert_eq!(gen2.root_id, original.root_id);
    assert_ne!(gen2.id, id);
    h.run_due();
    let gen2 = h.queue().delivery(&gen2.id).unwrap().unwrap();
    assert_eq!(gen2.status, "failed");

    let lineage = h.queue().deliveries_for_root(&original.root_id).unwrap();
    assert_eq!(lineage.len(), 2);
    assert_eq!(lineage[0].generation, 1);
    assert_eq!(lineage[1].generation, 2);
    // Original attempt untouched, not cleared.
    assert_eq!(h.queue().attempts(&id).unwrap().len(), 1);
    assert_eq!(h.queue().attempts(&gen2.id).unwrap().len(), 1);

    // Same idempotency key conflict still evaluated per generation: replaying
    // again with different content at generation 2 enqueues generation 3,
    // because manual replay always opens a fresh generation.
    let gen3 = h.queue().manual_replay(&gen2.id, None).unwrap();
    assert_eq!(gen3.generation, 3);
    assert_eq!(gen3.parent_id.as_deref(), Some(gen2.id.as_str()));
}
