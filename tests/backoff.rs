#[path="common/mod.rs"]
mod harness;

use serde_json::json;

use webhook_replay::model::ReceiverMode;
use webhook_replay::queue::EnqueueResult;

use harness::Harness;

fn publish(h: &Harness, endpoint: &str, key: &str) -> String {
    let (_ev, res) = h
        .app
        .publish("e", &json!({"n": 1}), endpoint, key)
        .unwrap();
    match res {
        EnqueueResult::Created(d) => d.id,
        other => panic!("expected created, got {other:?}"),
    }
}

#[test]
fn fail_twice_then_success_uses_exponential_backoff_and_stable_order() {
    let h = Harness::new(15_000);
    let ep = h.make_endpoint(ReceiverMode::FailTwice);
    let id = publish(&h, &ep, "idem-backoff");

    // Attempt 1 at t0 -> 503, next scheduled at +1000.
    assert_eq!(h.run_due(), 1);
    let d = h.queue().delivery(&id).unwrap().unwrap();
    assert_eq!(d.status, "queued");
    assert_eq!(d.attempts_used, 1);
    let a1 = h.queue().attempts(&id).unwrap();
    assert_eq!(a1.len(), 1);
    assert_eq!(a1[0].attempt_no, 1);
    assert_eq!(a1[0].http_status, Some(503));

    // Not due before backoff elapses.
    h.clock.advance(999);
    assert_eq!(h.run_due(), 0);
    h.clock.advance(1);
    assert_eq!(h.run_due(), 1); // attempt 2 -> 503, scheduled +2000
    let d = h.queue().delivery(&id).unwrap().unwrap();
    assert_eq!(d.attempts_used, 2);

    h.clock.advance(1_999);
    assert_eq!(h.run_due(), 0);
    h.clock.advance(1);
    assert_eq!(h.run_due(), 1); // attempt 3 -> 200

    let d = h.queue().delivery(&id).unwrap().unwrap();
    assert_eq!(d.status, "succeeded");
    assert_eq!(d.final_reason.as_deref(), Some("delivered"));

    let attempts = h.queue().attempts(&id).unwrap();
    let statuses: Vec<Option<i64>> = attempts.iter().map(|a| a.http_status).collect();
    assert_eq!(statuses, vec![Some(503), Some(503), Some(200)]);
    // Scheduled gaps follow 1s, 2s exponential backoff.
    let s: Vec<i64> = attempts.iter().map(|a| a.scheduled_ms).collect();
    assert_eq!(s[1] - s[0], 1_000);
    assert_eq!(s[2] - s[1], 2_000);
}

#[test]
fn fixed_409_is_terminal_and_429_uses_retry_after_per_delivery() {
    let h = Harness::new(15_000);
    let ep = h.make_endpoint(ReceiverMode::FixedStatus);
    let id = publish(&h, &ep, "idem-409");
    h.run_due();
    let d = h.queue().delivery(&id).unwrap().unwrap();
    assert_eq!(d.status, "failed");
    assert!(d.final_reason.as_deref().unwrap().contains("terminal HTTP 409"));
    assert_eq!(h.queue().attempts(&id).unwrap().len(), 1);

    let h2 = Harness::new(15_000);
    let ep2 = h2.make_endpoint(ReceiverMode::RateLimited);
    let id2 = publish(&h2, &ep2, "idem-429");
    h2.run_due(); // 429, retry_after_secs=3
    let d = h2.queue().delivery(&id2).unwrap().unwrap();
    assert_eq!(d.status, "queued");
    let sched_gap = {
        let a = h2.queue().attempts(&id2).unwrap();
        d.next_after_ms - a[0].finished_ms.unwrap()
    };
    assert_eq!(sched_gap, 3_000);
}

