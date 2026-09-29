//! Delivery workers. A tick claims one due delivery (lease), performs the HTTP
//! call against the local fake receiver, and records the receipt.

use std::sync::Arc;
use std::time::Duration;

use crate::model::Clock;
use crate::queue::{ClaimedAttempt, Queue};
use crate::repo::Store;

pub struct Worker {
    pub id: String,
    pub queue: Arc<Queue>,
    pub store: Arc<Store>,
    pub clock: Arc<dyn Clock>,
    pub request_timeout: Duration,
}

impl Worker {
    pub fn new(
        queue: Arc<Queue>,
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        request_timeout: Duration,
    ) -> Self {
        Self {
            id: crate::ids::worker_id(),
            queue,
            store,
            clock,
            request_timeout,
        }
    }

    /// One claim/send/record cycle. Returns true if work was claimed.
    pub fn tick(&self) -> anyhow::Result<bool> {
        let claimed_opt = self.queue.claim_next(&self.id)?;
        let Some(claimed) = claimed_opt else {
            return Ok(false);
        };
        self.store.audit(
            "lease",
            &claimed.attempt.id,
            &format!(
                "worker {} claimed generation {} attempt {}",
                self.id, claimed.delivery.generation, claimed.attempt.attempt_no
            ),
            self.clock.now_ms(),
        );
        self.send_and_record(claimed)
    }

    /// Exposed for tests that drive sending explicitly after a claim.
    pub fn send_and_record(&self, claimed: ClaimedAttempt) -> anyhow::Result<bool> {
        let endpoint = self
            .store
            .endpoint(&claimed.delivery.endpoint_id)?
            .ok_or_else(|| anyhow::anyhow!("endpoint missing"))?;

        let outcome = crate::sender::send(
            &endpoint,
            &claimed.delivery,
            claimed.attempt.attempt_no,
            claimed.attempt.signature_hex.as_deref(),
            self.request_timeout,
        );
        let finished = self.clock.now_ms();
        let result = crate::queue::CallResult {
            outcome: outcome.outcome,
            response_excerpt: outcome.excerpt,
            finished_ms: finished,
        };
        self.queue.record_receipt(&claimed, &result)?;
        Ok(true)
    }
}

/// Run a background pump loop. With a real clock it sleeps; the virtual clock
/// cannot wake it, so tests call `Worker::tick` directly.
pub fn spawn_pump(worker: Arc<Worker>, interval: Duration) {
    std::thread::Builder::new()
        .name(format!("worker-{}", worker.id))
        .spawn(move || loop {
            match worker.tick() {
                Ok(true) => continue,
                Ok(false) => std::thread::sleep(interval),
                Err(e) => {
                    eprintln!("worker {} tick error: {e}", worker.id);
                    std::thread::sleep(interval);
                }
            }
        })
        .expect("spawn worker");
}
