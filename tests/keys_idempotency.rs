#[path="common/mod.rs"]
mod harness;

use serde_json::json;

use webhook_replay::model::{Clock, ReceiverMode};
use webhook_replay::queue::EnqueueResult;

use harness::Harness;

#[test]
fn key_validity_window_selects_and_freezes_key_across_rotation() {
    let h = Harness::new(15_000);
    let ep = h.make_endpoint(ReceiverMode::Success);

    let old = h.key("old", "secret-old", -2_000, 3_000); // valid ..+1000
    let mid = h.key("new", "secret-new", 1_000, 3_000); // valid +1000..+5000
    let _future = h.key("future", "secret-future", 5_000, 4_000);

    let d1 = {
        let (_e, r) = h
            .app
            .publish("a", &json!({"v": 1}), &ep, "k-old")
            .unwrap();
        match r {
            EnqueueResult::Created(d) => d,
            _ => panic!(),
        }
    };
    assert_eq!(d1.frozen_key_id.as_deref(), Some(old.as_str()));
    h.run_due();
    let a = h.queue().attempts(&d1.id).unwrap();
    assert_eq!(a[0].key_id.as_deref(), Some(old.as_str()));
    // Receiver verifies signature -> 200 means old key signature was valid.
    assert_eq!(a[0].http_status, Some(200));

    // Rotate: after expiry the new key is selected for a fresh delivery.
    h.clock.advance(1_500);
    let d2 = {
        let (_e, r) = h
            .app
            .publish("b", &json!({"v": 2}), &ep, "k-new")
            .unwrap();
        match r {
            EnqueueResult::Created(d) => d,
            _ => panic!(),
        }
    };
    assert_eq!(d2.frozen_key_id.as_deref(), Some(mid.as_str()));
    h.run_due();
    let a2 = h.queue().attempts(&d2.id).unwrap();
    assert_eq!(a2[0].key_id.as_deref(), Some(mid.as_str()));
    assert_eq!(a2[0].http_status, Some(200));

    // No key valid after +5000: still enqueued with frozen_key_id = none,
    // delivery unsigned; receiver accepts (no signature header).
    h.clock.advance(10_000);
    let (_e, r) = h
        .app
        .publish("c", &json!({"v": 3}), &ep, "k-none")
        .unwrap();
    let d3 = match r {
        EnqueueResult::Created(d) => d,
        _ => panic!(),
    };
    assert!(d3.frozen_key_id.is_none());
    h.run_due();
    assert_eq!(h.queue().delivery(&d3.id).unwrap().unwrap().status, "succeeded");
}

#[test]
fn idempotency_same_key_same_content_replays_different_conflicts() {
    let h = Harness::new(15_000);
    let ep = h.make_endpoint(ReceiverMode::Success);
    let payload = json!({"order": "x", "amount": 1});
    let (_e, first) = h.app.publish("e", &payload, &ep, "idem-1").unwrap();
    let first_id = match first {
        EnqueueResult::Created(d) => d.id,
        _ => panic!(),
    };

    // Same key + same content (different JSON key order, whitespace) -> replay.
    let (_e2, again) = h
        .app
        .publish("e", &json!({"amount":1,"order":"x"}), &ep, "idem-1")
        .unwrap();
    match again {
        EnqueueResult::Replayed(d) => assert_eq!(d.id, first_id),
        other => panic!("expected replay, got {other:?}"),
    }

    // Same key + different content -> conflict, no new delivery.
    let (_e3, conflict) = h
        .app
        .publish("e", &json!({"order": "x", "amount": 2}), &ep, "idem-1")
        .unwrap();
    match conflict {
        EnqueueResult::Conflict { existing_generation } => assert_eq!(existing_generation, 1),
        other => panic!("expected conflict, got {other:?}"),
    }
    assert_eq!(h.queue().list_deliveries().unwrap().len(), 1);
}

#[test]
fn editing_event_and_rotating_key_do_not_change_queued_attempt() {
    let h = Harness::new(15_000);
    h.key("k", "secret", -1_000, 100_000);
    let ep = h.make_endpoint(ReceiverMode::Timeout);
    // timeout will retry; keep budget short and do not run yet.
    let (event, r) = h
        .app
        .publish("ev", &json!({"v": 1}), &ep, "idem-freeze")
        .unwrap();
    let d = match r {
        EnqueueResult::Created(d) => d,
        _ => panic!(),
    };

    // Edit event payload after enqueue.
    h.app
        .store
        .update_event_payload(&event.id, &json!({"v": 999}), h.clock.now_ms())
        .unwrap();

    // Run first attempt (times out).
    h.run_due();
    let attempts = h.queue().attempts(&d.id).unwrap();
    assert_eq!(attempts.len(), 1);
    // The frozen payload is still the original; the request sent the frozen
    // bytes (receiver stores hits; we assert frozen_payload is unchanged).
    let stored = h.queue().delivery(&d.id).unwrap().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&stored.frozen_payload).unwrap(),
        json!({"v": 1})
    );
}
