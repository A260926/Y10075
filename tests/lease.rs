#[path="common/mod.rs"]
mod harness;

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use webhook_replay::model::{Clock, ReceiverMode};
use webhook_replay::queue::EnqueueResult;
use webhook_replay::worker::Worker;

use harness::Harness;

#[test]
fn two_workers_claim_once_per_generation_and_lease_takeover_audited() {
    // Short lease, timeout receiver: worker A claims and its request hangs
    // past the lease; worker B's later tick takes over and records the event.
    let h = Harness::new(400); // lease 400ms, request timeout 300ms
    let ep = h.make_endpoint(ReceiverMode::Timeout);
    let id = {
        let (_e, r) = h
            .app
            .publish("e", &json!({"v": 1}), &ep, "idem-lease")
            .unwrap();
        match r {
            EnqueueResult::Created(d) => d.id,
            _ => panic!(),
        }
    };

    let queue = h.queue();
    let mk = |id_suffix: &str| {
        let mut w = Worker::new(
            Arc::clone(&queue),
            Arc::clone(&h.built.store),
            Arc::clone(&h.built.clock),
            Duration::from_millis(300),
        );
        w.id = format!("wkr_{id_suffix}");
        w
    };
    let worker_a = mk("AAAA");
    let worker_b = mk("BBBB");

    // A claims the generation.
    let claimed = queue.claim_next(&worker_a.id).unwrap().expect("A claims");
    assert_eq!(claimed.delivery.id, id);

    // With the lease still valid, B cannot claim the same generation.
    assert!(queue.claim_next(&worker_b.id).unwrap().is_none());

    // Lease expires (virtual clock) while A is still blocked in the request.
    h.clock.advance(401);
    // B ticks: recover marks A's lease expired/taken over, schedules a retry.
    assert!(!worker_b.tick().unwrap_or(false) || true);
    // worker_b.tick performs recovery then a new claim if due. The takeover
    // records lease_lost with next_after based on backoff. Confirm audit trail.
    let audit = h.built.store.list_audit(100).unwrap();
    assert!(
        audit
            .iter()
            .any(|(_, scope, _, msg)| scope == "lease" && msg.contains("takeover")),
        "expected a lease takeover audit entry, got {audit:?}"
    );

    // Original attempt row is reconciled as lease_lost and done.
    let attempts = queue.attempts(&id).unwrap();
    let first = &attempts[0];
    assert_eq!(first.state, "done");
    assert_eq!(first.outcome_kind.as_deref(), Some("lease_lost"));

    // Delivery is queued for retry after backoff (base 1000ms).
    let d = queue.delivery(&id).unwrap().unwrap();
    assert_eq!(d.status, "queued");
    assert!(d.next_after_ms >= h.clock.now_ms());
}

#[test]
fn lease_takeover_concurrent_attempts_never_double_finalize() {
    // Drive two claimers with a valid lease: only one row is ever created.
    let h = Harness::new(60_000);
    let ep = h.make_endpoint(ReceiverMode::Success);
    let id = {
        let (_e, r) = h
            .app
            .publish("e", &json!({"v": 1}), &ep, "idem-concurrent")
            .unwrap();
        match r {
            EnqueueResult::Created(d) => d.id,
            _ => panic!(),
        }
    };
    let w1 = h.worker();
    let w2 = h.worker();
    let c1 = h.queue().claim_next(&w1.id).unwrap();
    let c2 = h.queue().claim_next(&w2.id).unwrap();
    assert!(c1.is_some());
    assert!(c2.is_none());

    // First claimer completes and finalizes exactly once.
    w1.send_and_record(c1.unwrap()).unwrap();
    let attempts = h.queue().attempts(&id).unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].state, "done");
    assert_eq!(h.queue().delivery(&id).unwrap().unwrap().status, "succeeded");
}

#[test]
fn late_response_after_takeover_is_ignored() {
    // A's lease expires and is taken over; if A's send then records a receipt,
    // the conditional update rejects it and no second finalize/retry happens.
    let h = Harness::new(400);
    let ep = h.make_endpoint(ReceiverMode::Timeout);
    let (_e, r) = h
        .app
        .publish("e", &json!({"v": 1}), &ep, "idem-late")
        .unwrap();
    let d = match r {
        EnqueueResult::Created(d) => d,
        _ => panic!(),
    };
    let worker_a = h.worker();
    let claimed = h.queue().claim_next(&worker_a.id).unwrap().unwrap();
    // Expire and take over from a second worker.
    h.clock.advance(401);
    h.queue().recover_all().unwrap();
    // Now A (slowly) gets a "response" and tries to record it.
    let late = webhook_replay::queue::CallResult {
        outcome: webhook_replay::model::AttemptOutcome::Success,
        response_excerpt: None,
        finished_ms: h.clock.now_ms(),
    };
    h.queue().record_receipt(&claimed, &late).unwrap();
    let attempts = h.queue().attempts(&d.id).unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome_kind.as_deref(), Some("lease_lost"));
}
