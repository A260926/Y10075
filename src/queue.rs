//! Delivery queue: freezing, idempotent enqueue, lease claiming, receipt
//! reconciliation and retry scheduling.
//!
//! Crash-safety design
//! -------------------
//! 1. An attempt row is inserted and claimed under a lease *before* the HTTP
//!    request leaves the process.
//! 2. Once a response arrives, the receipt (state='responded', outcome, http
//!    status, timing) is committed first.
//! 3. Delivery-level status / next schedule is written afterwards, and the
//!    attempt is marked 'done'.
//!
//! A process dying between steps 2 and 3 leaves a 'responded' row. On restart
//! reconciliation re-applies the durable outcome deterministically and never
//! sends the HTTP request again. A process dying during the request (no receipt)
//! leaves an expired 'leased' row; the outcome is genuinely unknown, so the
//! attempt is recorded as lease_lost and (budget permitting) retried.

use std::sync::{Arc, Mutex};

use rusqlite::{params, OptionalExtension};

use crate::model::{is_retryable, AttemptOutcome, Clock, DeliveryStatus};
use crate::repo::{canonical_content_hash, DeliveryRow, Store};

use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

static CRASH_AFTER_RECEIPT: AtomicBool = AtomicBool::new(false);

/// Arm the crash-window simulation: the next committed response receipt exits
/// the process before delivery-level finalization runs.
pub fn arm_crash_after_receipt() {
    CRASH_AFTER_RECEIPT.store(true, AtomicOrdering::SeqCst);
}

#[derive(Clone)]
pub struct QueueConfig {
    pub lease_ms: i64,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self { lease_ms: 15_000 }
    }
}

pub struct Queue {
    pub store: Arc<Store>,
    pub clock: Arc<dyn Clock>,
    pub cipher: crate::crypto::Cipher,
    pub config: QueueConfig,
    /// Serializes recovery + claiming so two workers never claim the same
    /// generation concurrently.
    pub dispatch_gate: Mutex<()>,
}

#[derive(Debug, Clone)]
pub enum EnqueueResult {
    Created(DeliveryRow),
    Replayed(DeliveryRow),
    Conflict { existing_generation: i64 },
}

#[derive(Debug, Clone)]
pub struct ClaimedAttempt {
    pub attempt: crate::repo::AttemptRow,
    pub delivery: DeliveryRow,
}

impl Queue {
    pub fn new(
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        cipher: crate::crypto::Cipher,
        config: QueueConfig,
    ) -> Self {
        Self {
            store,
            clock,
            cipher,
            config,
            dispatch_gate: Mutex::new(()),
        }
    }

    /// Enqueue one delivery for (event, endpoint). `idem_key` + content hash
    /// provide idempotency within the same generation: identical content
    /// returns the existing delivery, different content conflicts.
    pub fn enqueue(
        &self,
        event_id: &str,
        endpoint_id: &str,
        idem_key: &str,
        payload_json: &str,
        generation: i64,
        parent_id: Option<&str>,
    ) -> anyhow::Result<EnqueueResult> {
        let now = self.clock.now_ms();
        let content = canonical_content_hash(
            &serde_json::from_str(payload_json)
                .map_err(|e| anyhow::anyhow!("invalid JSON payload: {e}"))?,
        );
        let id = crate::ids::delivery_id();

        // Freeze payload bytes and select the key valid at enqueue time. Rotated
        // keys or later event edits never touch this row.
        let key = self.store.key_valid_at(now)?;
        let key_id = key.as_ref().map(|k| k.id.clone());
        let root_id = match parent_id {
            Some(pid) => self.root_of(pid)?,
            None => id.clone(),
        };

        let mut conn = self.store.conn();
        let tx = conn.transaction()?;
        let existing = tx
            .query_row(
                "SELECT id,generation FROM deliveries
                 WHERE endpoint_id=?1 AND idem_key=?2 AND generation=?3",
                params![endpoint_id, idem_key, generation],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .ok();

        if let Some((existing_id, existing_gen)) = existing {
            let same = tx.query_row(
                "SELECT content_hash=?2 FROM deliveries WHERE id=?1",
                params![existing_id, content],
                |r| r.get::<_, bool>(0),
            )?;
            drop(tx);
            if same {
                let row = self.delivery(&existing_id)?.expect("delivery exists");
                return Ok(EnqueueResult::Replayed(row));
            } else {
                return Ok(EnqueueResult::Conflict {
                    existing_generation: existing_gen,
                });
            }
        }

        tx.execute(
            "INSERT INTO deliveries(id,event_id,endpoint_id,idem_key,content_hash,generation,
                parent_id,root_id,frozen_payload,frozen_key_id,status,final_reason,attempts_used,
                next_after_ms,created_ms,updated_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'queued',NULL,0,?11,?11,?11)",
            params![
                id,
                event_id,
                endpoint_id,
                idem_key,
                content,
                generation,
                parent_id,
                root_id,
                payload_json,
                key_id,
                now,
            ],
        )?;
        tx.commit()?;
        drop(conn);

        self.store.audit(
            "delivery",
            &id,
            &format!(
                "enqueued generation {generation} (payload frozen, key_id={})",
                key_id.as_deref().unwrap_or("<none>")
            ),
            now,
        );
        let row = self.delivery(&id)?.expect("delivery exists");
        Ok(EnqueueResult::Created(row))
    }

    pub fn root_of(&self, delivery_id: &str) -> anyhow::Result<String> {
        let conn = self.store.conn();
        conn.query_row(
            "SELECT root_id FROM deliveries WHERE id=?1",
            params![delivery_id],
            |r| r.get(0),
        )
        .map_err(Into::into)
    }

    /// Create a new generation linked to an existing delivery, carrying over
    /// the same idempotency key but freezing a fresh payload/key snapshot. Old
    /// attempts remain untouched.
    pub fn manual_replay(
        &self,
        original_id: &str,
        new_payload_json: Option<&str>,
    ) -> anyhow::Result<DeliveryRow> {
        let original = self
            .delivery(original_id)?
            .ok_or_else(|| anyhow::anyhow!("delivery not found"))?;
        let payload = new_payload_json.unwrap_or(&original.frozen_payload).to_string();
        let next_gen = self.max_generation(&original.root_id)? + 1;
        match self.enqueue(
            &original.event_id,
            &original.endpoint_id,
            &original.idem_key,
            &payload,
            next_gen,
            Some(original_id),
        )? {
            EnqueueResult::Created(row) | EnqueueResult::Replayed(row) => Ok(row),
            EnqueueResult::Conflict { .. } => {
                anyhow::bail!("internal replay conflict")
            }
        }
    }

    fn max_generation(&self, root_id: &str) -> anyhow::Result<i64> {
        let conn = self.store.conn();
        conn.query_row(
            "SELECT COALESCE(MAX(generation),0) FROM deliveries WHERE root_id=?1",
            params![root_id],
            |r| r.get(0),
        )
        .map_err(Into::into)
    }
}

impl Queue {
    pub fn delivery(&self, id: &str) -> anyhow::Result<Option<DeliveryRow>> {
        let conn = self.store.conn();
        Self::map_delivery_conn(&conn, id)
    }

    fn map_delivery_conn(
        conn: &rusqlite::Connection,
        id: &str,
    ) -> anyhow::Result<Option<DeliveryRow>> {
        conn.query_row("SELECT * FROM deliveries WHERE id=?1", params![id], |r| {
            Ok(DeliveryRow {
                id: r.get(0)?,
                event_id: r.get(1)?,
                endpoint_id: r.get(2)?,
                idem_key: r.get(3)?,
                content_hash: r.get(4)?,
                generation: r.get(5)?,
                parent_id: r.get(6)?,
                root_id: r.get(7)?,
                frozen_payload: r.get(8)?,
                frozen_key_id: r.get(9)?,
                status: r.get(10)?,
                final_reason: r.get(11)?,
                attempts_used: r.get(12)?,
                next_after_ms: r.get(13)?,
                created_ms: r.get(14)?,
                updated_ms: r.get(15)?,
            })
        })
        .optional()
        .map_err(Into::into)
    }

    pub fn list_deliveries(&self) -> anyhow::Result<Vec<DeliveryRow>> {
        let conn = self.store.conn();
        let mut stmt = conn.prepare(
            "SELECT * FROM deliveries ORDER BY created_ms DESC, root_id, generation, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(DeliveryRow {
                id: r.get(0)?,
                event_id: r.get(1)?,
                endpoint_id: r.get(2)?,
                idem_key: r.get(3)?,
                content_hash: r.get(4)?,
                generation: r.get(5)?,
                parent_id: r.get(6)?,
                root_id: r.get(7)?,
                frozen_payload: r.get(8)?,
                frozen_key_id: r.get(9)?,
                status: r.get(10)?,
                final_reason: r.get(11)?,
                attempts_used: r.get(12)?,
                next_after_ms: r.get(13)?,
                created_ms: r.get(14)?,
                updated_ms: r.get(15)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn deliveries_for_root(&self, root_id: &str) -> anyhow::Result<Vec<DeliveryRow>> {
        let conn = self.store.conn();
        let mut stmt = conn.prepare(
            "SELECT * FROM deliveries WHERE root_id=?1 ORDER BY generation",
        )?;
        let rows = stmt.query_map(params![root_id], |r| {
            Ok(DeliveryRow {
                id: r.get(0)?,
                event_id: r.get(1)?,
                endpoint_id: r.get(2)?,
                idem_key: r.get(3)?,
                content_hash: r.get(4)?,
                generation: r.get(5)?,
                parent_id: r.get(6)?,
                root_id: r.get(7)?,
                frozen_payload: r.get(8)?,
                frozen_key_id: r.get(9)?,
                status: r.get(10)?,
                final_reason: r.get(11)?,
                attempts_used: r.get(12)?,
                next_after_ms: r.get(13)?,
                created_ms: r.get(14)?,
                updated_ms: r.get(15)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn attempts(&self, delivery_id: &str) -> anyhow::Result<Vec<crate::repo::AttemptRow>> {
        let conn = self.store.conn();
        let mut stmt = conn.prepare(
            "SELECT * FROM attempts WHERE delivery_id=?1 ORDER BY attempt_no",
        )?;
        let rows = stmt.query_map(params![delivery_id], map_attempt)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn all_attempts_for_root(
        &self,
        root_id: &str,
    ) -> anyhow::Result<Vec<(DeliveryRow, crate::repo::AttemptRow)>> {
        let conn = self.store.conn();
        let mut stmt = conn.prepare(
            "SELECT d.*, a.id,a.delivery_id,a.generation,a.attempt_no,a.key_id,a.signature_hex,
                    a.scheduled_ms,a.lease_owner,a.lease_expires_ms,a.state,a.outcome_kind,
                    a.http_status,a.detail,a.response_excerpt,a.started_ms,a.finished_ms
             FROM deliveries d JOIN attempts a ON a.delivery_id=d.id
             WHERE d.root_id=?1
             ORDER BY d.generation, a.attempt_no",
        )?;
        let rows = stmt.query_map(params![root_id], |r| {
            let delivery = DeliveryRow {
                id: r.get(0)?,
                event_id: r.get(1)?,
                endpoint_id: r.get(2)?,
                idem_key: r.get(3)?,
                content_hash: r.get(4)?,
                generation: r.get(5)?,
                parent_id: r.get(6)?,
                root_id: r.get(7)?,
                frozen_payload: r.get(8)?,
                frozen_key_id: r.get(9)?,
                status: r.get(10)?,
                final_reason: r.get(11)?,
                attempts_used: r.get(12)?,
                next_after_ms: r.get(13)?,
                created_ms: r.get(14)?,
                updated_ms: r.get(15)?,
            };
            // attempt columns start at index 16; delivery_id duplicates index 17
            let attempt = crate::repo::AttemptRow {
                id: r.get(16)?,
                delivery_id: r.get(17)?,
                generation: r.get(18)?,
                attempt_no: r.get(19)?,
                key_id: r.get(20)?,
                signature_hex: r.get(21)?,
                scheduled_ms: r.get(22)?,
                lease_owner: r.get(23)?,
                lease_expires_ms: r.get(24)?,
                state: r.get(25)?,
                outcome_kind: r.get(26)?,
                http_status: r.get(27)?,
                detail: r.get(28)?,
                response_excerpt: r.get(29)?,
                started_ms: r.get(30)?,
                finished_ms: r.get(31)?,
            };
            Ok((delivery, attempt))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Atomically claim the next due delivery for this worker. Returns None
    /// when nothing is runnable.
    pub fn claim_next(&self, worker_id: &str) -> anyhow::Result<Option<ClaimedAttempt>> {
        // Recovery must precede every claim; both run under the dispatch gate
        // so two workers cannot observe the same due generation.
        let _gate = self.dispatch_gate.lock().unwrap();
        self.recover_all_inner()?;
        let now = self.clock.now_ms();
        let expires = now + self.config.lease_ms;
        let mut conn = self.store.conn();
        let tx =
            conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let candidate: Option<(String, i64)> = tx
            .query_row(
                "SELECT d.id, d.attempts_used FROM deliveries d
                 WHERE d.status IN ('queued','sending') AND d.next_after_ms <= ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM attempts a
                       WHERE a.delivery_id=d.id AND a.state='leased'
                         AND a.lease_expires_ms > ?1
                   )
                 ORDER BY d.next_after_ms, d.id LIMIT 1",
                params![now],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .ok();

        let Some((delivery_id, attempts_used)) = candidate else {
            drop(tx);
            drop(conn);
            return Ok(None);
        };
        let delivery = tx.query_row(
            "SELECT * FROM deliveries WHERE id=?1",
            params![delivery_id],
            |r| {
                Ok(DeliveryRow {
                    id: r.get(0)?,
                    event_id: r.get(1)?,
                    endpoint_id: r.get(2)?,
                    idem_key: r.get(3)?,
                    content_hash: r.get(4)?,
                    generation: r.get(5)?,
                    parent_id: r.get(6)?,
                    root_id: r.get(7)?,
                    frozen_payload: r.get(8)?,
                    frozen_key_id: r.get(9)?,
                    status: r.get(10)?,
                    final_reason: r.get(11)?,
                    attempts_used: r.get(12)?,
                    next_after_ms: r.get(13)?,
                    created_ms: r.get(14)?,
                    updated_ms: r.get(15)?,
                })
            },
        )?;

        let attempt_no = attempts_used + 1;
        let attempt_id = crate::ids::attempt_id();
        let sig = signature_for_conn(&self.cipher, &tx, &delivery)?;

        tx.execute(
            "INSERT INTO attempts(id,delivery_id,generation,attempt_no,key_id,signature_hex,
                scheduled_ms,lease_owner,lease_expires_ms,state,started_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'leased',?7)",
            params![
                attempt_id,
                delivery_id,
                delivery.generation,
                attempt_no,
                delivery.frozen_key_id,
                sig,
                now,
                worker_id,
                expires,
            ],
        )?;
        tx.execute(
            "UPDATE deliveries SET status='sending', attempts_used=?2, updated_ms=?3 WHERE id=?1",
            params![delivery_id, attempt_no, now],
        )?;
        tx.commit()?;
        drop(conn);
        drop(_gate);

        let attempt = self
            .attempts(&delivery_id)?
            .into_iter()
            .find(|a| a.id == attempt_id)
            .expect("inserted attempt exists");
        Ok(Some(ClaimedAttempt { attempt, delivery }))
    }
}

fn signature_for_conn(
    cipher: &crate::crypto::Cipher,
    conn: &rusqlite::Connection,
    delivery: &DeliveryRow,
) -> anyhow::Result<Option<String>> {
    let Some(key_id) = &delivery.frozen_key_id else {
        return Ok(None);
    };
    let enc: String = conn.query_row(
        "SELECT secret_enc_hex FROM sign_keys WHERE id=?1",
        params![key_id],
        |r| r.get(0),
    )?;
    let secret = cipher.decrypt_hex(&enc)?;
    Ok(Some(crate::crypto::sign_payload(
        &secret,
        delivery.frozen_payload.as_bytes(),
    )?))
}

fn map_attempt(r: &rusqlite::Row<'_>) -> rusqlite::Result<crate::repo::AttemptRow> {
    Ok(crate::repo::AttemptRow {
        id: r.get(0)?,
        delivery_id: r.get(1)?,
        generation: r.get(2)?,
        attempt_no: r.get(3)?,
        key_id: r.get(4)?,
        signature_hex: r.get(5)?,
        scheduled_ms: r.get(6)?,
        lease_owner: r.get(7)?,
        lease_expires_ms: r.get(8)?,
        state: r.get(9)?,
        outcome_kind: r.get(10)?,
        http_status: r.get(11)?,
        detail: r.get(12)?,
        response_excerpt: r.get(13)?,
        started_ms: r.get(14)?,
        finished_ms: r.get(15)?,
    })
}

/// Result of performing the actual HTTP call, handed back to the queue after
/// the request returns (or fails).
#[derive(Debug, Clone)]
pub struct CallResult {
    pub outcome: AttemptOutcome,
    pub response_excerpt: Option<String>,
    pub finished_ms: i64,
}

impl Queue {
    /// Persist the response receipt first (state='responded'), then finalize
    /// delivery state (state='done'). A crash in between is repaired on restart
    /// by `recover_all`; the request is never sent twice.
    pub fn record_receipt(&self, claimed: &ClaimedAttempt, result: &CallResult) -> anyhow::Result<()> {
        let now = result.finished_ms;
        let claimed_rows = {
            let mut conn = self.store.conn();
            let tx = conn.transaction()?;
            let n = tx.execute(
                "UPDATE attempts SET state='responded', outcome_kind=?2, http_status=?3,
                    detail=?4, response_excerpt=?5, finished_ms=?6
                 WHERE id=?1 AND state='leased'",
                params![
                    claimed.attempt.id,
                    result.outcome.kind(),
                    result.outcome.http_status(),
                    result.outcome.detail(),
                    result.response_excerpt,
                    now,
                ],
            )?;
            tx.commit()?;
            n
        };
        if claimed_rows == 0 {
            // The lease expired and another worker took over while this request
            // was in flight. Do not finalize twice and do not create retries.
            self.store.audit(
                "lease",
                &claimed.attempt.id,
                "ignored late response: lease already taken over by another worker",
                now,
            );
            return Ok(());
        }

        // Crash-window hook: the receipt is durable at this point while
        // delivery-level state is not finalized yet.
        if CRASH_AFTER_RECEIPT.swap(false, AtomicOrdering::SeqCst) {
            eprintln!(
                "simulated crash after durable receipt for {} (before finalize)",
                claimed.delivery.id
            );
            std::process::exit(7);
        }

        self.finalize_after_receipt(claimed, result)?;
        Ok(())
    }

    /// Apply the durable receipt to delivery-level state and mark the attempt
    /// done. Deterministic so it can run again during recovery.
    fn finalize_after_receipt(
        &self,
        claimed: &ClaimedAttempt,
        result: &CallResult,
    ) -> anyhow::Result<()> {
        let now = result.finished_ms;
        let delivery = claimed.delivery.clone();
        let endpoint = self
            .store
            .endpoint(&delivery.endpoint_id)?
            .ok_or_else(|| anyhow::anyhow!("endpoint vanished"))?;
        let max_attempts = endpoint.policy.max_attempts;
        let attempt_no = claimed.attempt.attempt_no;

        let delay_ms = match result.outcome {
            // Retry-After on 429 affects only this delivery.
            AttemptOutcome::HttpStatus(429) => endpoint.retry_after_secs.max(0) * 1000,
            // Everything else retryable uses the endpoint exponential backoff,
            // scheduled for the *next* attempt number.
            _ => endpoint.policy.delay_for_attempt(attempt_no + 1),
        };
        let retry = is_retryable(&result.outcome) && attempt_no < max_attempts;

        let mut conn = self.store.conn();
        let tx = conn.transaction()?;
        if retry {
            let next = now + delay_ms;
            tx.execute(
                "UPDATE deliveries SET status='queued', next_after_ms=?2, final_reason=NULL,
                    updated_ms=?3 WHERE id=?1",
                params![delivery.id, next, now],
            )?;
            tx.execute(
                "UPDATE attempts SET state='done' WHERE id=?1",
                params![claimed.attempt.id],
            )?;
        } else {
            let (status, reason) = if matches!(result.outcome, AttemptOutcome::HttpStatus(c) if (200..300).contains(&c)) {
                (DeliveryStatus::Succeeded, "delivered".to_string())
            } else if is_retryable(&result.outcome) && attempt_no >= max_attempts {
                (
                    DeliveryStatus::Failed,
                    format!("exhausted {} attempts: {}", max_attempts, result.outcome.detail()),
                )
            } else if matches!(result.outcome, AttemptOutcome::HttpStatus(s) if !(429..599).contains(&s))
            {
                (
                    DeliveryStatus::Failed,
                    format!("terminal HTTP {}: no retry", result.outcome.detail()),
                )
            } else {
                (
                    DeliveryStatus::Failed,
                    format!("stopped: {}", result.outcome.detail()),
                )
            };
            tx.execute(
                "UPDATE deliveries SET status=?2, final_reason=?3, next_after_ms=?4,
                    updated_ms=?5 WHERE id=?1",
                params![delivery.id, status.as_str(), reason, now, now],
            )?;
            tx.execute(
                "UPDATE attempts SET state='done' WHERE id=?1",
                params![claimed.attempt.id],
            )?;
        }
        tx.commit()?;

        let kind = result.outcome.kind();
        self.store.audit(
            "attempt",
            &claimed.attempt.id,
            &format!("attempt {attempt_no} settled: {kind}"),
            now,
        );
        Ok(())
    }
    /// Cleanly abandon an unresponded claim (shutdown). Nothing was received,
    /// so the provisional attempt row is removed and the budget restored.
    pub fn release_claim(&self, attempt_id: &str) -> anyhow::Result<()> {
        let mut conn = self.store.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE deliveries SET attempts_used = MAX(0, attempts_used-1), status='queued'
             WHERE id=(SELECT delivery_id FROM attempts WHERE id=?1 AND state='leased')",
            params![attempt_id],
        )?;
        tx.execute("DELETE FROM attempts WHERE id=?1 AND state='leased'", params![attempt_id])?;
        tx.commit()?;
        Ok(())
    }

    /// Run at startup and periodically before claiming:
    /// 1. Reconcile 'responded' rows whose delivery finalization never ran
    ///    (crash after receipt). Applies the durable outcome again.
    /// 2. Take over 'leased' rows whose lease has expired (dead/slow worker).
    pub fn recover_all(&self) -> anyhow::Result<RecoverReport> {
        // When invoked directly (startup) take the gate; claim_next already
        // holds it, so use a non-blocking re-entrancy helper.
        self.recover_all_inner()
    }

    fn recover_all_inner(&self) -> anyhow::Result<RecoverReport> {
        let now = self.clock.now_ms();
        let mut report = RecoverReport::default();

        // 1. Receipts landed but delivery never finalized.
        let pending: Vec<crate::repo::AttemptRow> = {
            let conn = self.store.conn();
            let mut stmt = conn.prepare(
                "SELECT * FROM attempts WHERE state='responded' ORDER BY scheduled_ms,id",
            )?;
            let rows = stmt.query_map([], map_attempt)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            out
        };
        for attempt in pending {
            let delivery = self
                .delivery(&attempt.delivery_id)?
                .ok_or_else(|| anyhow::anyhow!("delivery missing for responded attempt"))?;
            let outcome = outcome_from_row(&attempt);
            let result = CallResult {
                outcome,
                response_excerpt: attempt.response_excerpt.clone(),
                finished_ms: attempt.finished_ms.unwrap_or(now),
            };
            let claimed = ClaimedAttempt {
                attempt: attempt.clone(),
                delivery,
            };
            self.finalize_after_receipt(&claimed, &result)?;
            report.responded_reconciled += 1;
            self.store.audit(
                "recover",
                &attempt.id,
                "reconciled durable attempt receipt after restart; no duplicate send",
                now,
            );
        }

        // 2. Expired leases: the in-flight result is unknown. Record a
        // lease_lost receipt, audit the takeover, and schedule a retry.
        let expired: Vec<crate::repo::AttemptRow> = {
            let conn = self.store.conn();
            let mut stmt = conn.prepare(
                "SELECT * FROM attempts
                 WHERE state='leased' AND lease_expires_ms IS NOT NULL
                   AND lease_expires_ms <= ?1 ORDER BY scheduled_ms,id",
            )?;
            let rows = stmt.query_map(params![now], map_attempt)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            out
        };
        for attempt in expired {
            {
                let mut conn = self.store.conn();
                let tx = conn.transaction()?;
                tx.execute(
                    "UPDATE attempts SET state='responded', outcome_kind='lease_lost',
                        detail='lease expired; in-flight result unknown', finished_ms=?2
                     WHERE id=?1",
                    params![attempt.id, now],
                )?;
                tx.commit()?;
            }
            self.store.audit(
                "lease",
                &attempt.id,
                &format!(
                    "lease expired at {now}; takeover from owner {} (generation {}, attempt {})",
                    attempt.lease_owner.as_deref().unwrap_or("?"),
                    attempt.generation,
                    attempt.attempt_no
                ),
                now,
            );
            let delivery = self.delivery(&attempt.delivery_id)?.expect("delivery exists");
            let result = CallResult {
                outcome: AttemptOutcome::LeaseLost,
                response_excerpt: None,
                finished_ms: now,
            };
            let claimed = ClaimedAttempt { attempt, delivery };
            self.finalize_after_receipt(&claimed, &result)?;
            report.leases_taken_over += 1;
        }

        Ok(report)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RecoverReport {
    pub responded_reconciled: usize,
    pub leases_taken_over: usize,
}

fn outcome_from_row(a: &crate::repo::AttemptRow) -> AttemptOutcome {
    match a.outcome_kind.as_deref() {
        Some("success") => AttemptOutcome::Success,
        Some("http_status") => AttemptOutcome::HttpStatus(a.http_status.unwrap_or(0) as u16),
        Some("timeout") => AttemptOutcome::Timeout,
        Some("lease_lost") => AttemptOutcome::LeaseLost,
        Some("error") => AttemptOutcome::Error(
            a.detail.clone().unwrap_or_else(|| "transport error".to_string()),
        ),
        _ => AttemptOutcome::Error("unknown recorded outcome".to_string()),
    }
}
