//! High-level operations used by both the HTTP layer and tests.

use std::sync::Arc;

use serde_json::Value;

use crate::crypto::Cipher;
use crate::model::{Clock, ReceiverMode, RetryPolicy};
use crate::queue::{EnqueueResult, Queue};
use crate::repo::{Endpoint, EventRow, SignKeyRow, Store};

pub struct App {
    pub store: Arc<Store>,
    pub queue: Arc<Queue>,
    pub cipher: Cipher,
    pub clock: Arc<dyn Clock>,
    pub receiver_base: String,
}

pub struct CreatedEndpoint {
    pub endpoint: Endpoint,
    pub target_url: String,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    pub fn create_endpoint(
        &self,
        name: &str,
        mode: ReceiverMode,
        fixed_status: i64,
        retry_after_secs: i64,
        policy: RetryPolicy,
        target_url: Option<&str>,
        use_fake: bool,
    ) -> anyhow::Result<CreatedEndpoint> {
        let now = self.clock.now_ms();
        let token = crate::ids::receiver_token();
        let id = crate::ids::endpoint_id();
        let fake_url = crate::receiver::url_for(&self.receiver_base, &token);
        let target = target_url
            .map(str::to_string)
            .unwrap_or_else(|| fake_url.clone());
        let endpoint = Endpoint {
            id,
            name: name.to_string(),
            target_url: target.clone(),
            use_fake,
            receiver_token: token,
            receiver_mode: mode.as_str().to_string(),
            fixed_status,
            retry_after_secs,
            hits: 0,
            policy,
            created_ms: now,
        };
        self.store.create_endpoint(&endpoint)?;
        self.store.audit(
            "endpoint",
            &endpoint.id,
            &format!("registered endpoint (mode={})", mode.as_str()),
            now,
        );
        Ok(CreatedEndpoint {
            endpoint,
            target_url: target,
        })
    }

    pub fn create_event(&self, name: &str, payload: &Value) -> anyhow::Result<EventRow> {
        let now = self.clock.now_ms();
        let event = EventRow {
            id: crate::ids::event_id(),
            name: name.to_string(),
            payload_json: payload.to_string(),
            created_ms: now,
            updated_ms: now,
        };
        self.store.create_event(&event, payload)?;
        Ok(event)
    }

    pub fn create_signing_key(
        &self,
        label: &str,
        secret: &str,
        not_before_ms: i64,
        not_after_ms: i64,
    ) -> anyhow::Result<SignKeyRow> {
        if not_after_ms <= not_before_ms {
            anyhow::bail!("not_after must be greater than not_before");
        }
        let now = self.clock.now_ms();
        let enc = self.cipher.encrypt_to_hex(secret.as_bytes())?;
        let key = SignKeyRow {
            id: crate::ids::key_id(),
            label: label.to_string(),
            secret_enc_hex: enc,
            not_before_ms,
            not_after_ms,
            created_ms: now,
        };
        self.store.create_key(&key)?;
        self.store.audit(
            "key",
            &key.id,
            &format!("stored signing key (secret encrypted at rest) valid {}..{}",
                not_before_ms, not_after_ms),
            now,
        );
        Ok(key)
    }

    /// Create an event and enqueue one delivery to the endpoint with an
    /// idempotency key. Reusing the key returns / conflicts as specified.
    pub fn publish(
        &self,
        event_name: &str,
        payload: &Value,
        endpoint_id: &str,
        idem_key: &str,
    ) -> anyhow::Result<(EventRow, EnqueueResult)> {
        let event = self.create_event(event_name, payload)?;
        let result = self.queue.enqueue(
            &event.id,
            endpoint_id,
            idem_key,
            &payload.to_string(),
            1,
            None,
        )?;
        Ok((event, result))
    }
}

/// Build the deterministic demo scenario:
/// key valid for a wide window, endpoint in fail_twice mode, one event with a
/// delivery that 503s twice and succeeds on the third attempt.
pub fn seed_demo(app: &App) -> anyhow::Result<()> {
    let now = app.clock.now_ms();
    app.create_signing_key("primary signing key", "demo-secret", now - 60_000, now + 365 * 86_400_000)?;
    let policy = RetryPolicy {
        max_attempts: 5,
        base_delay_ms: 1_000,
        max_delay_ms: 30_000,
        multiplier: 2.0,
    };
    let created = app.create_endpoint(
        "演示接收端点（前两次 503，第三次成功）",
        ReceiverMode::FailTwice,
        409,
        3,
        policy,
        None,
        true,
    )?;
    let payload = serde_json::json!({
        "order_id": "ord_demo_0001",
        "amount": 12800,
        "currency": "CNY",
        "note": "预置场景：前两次投递失败，第三次成功",
    });
    let (_event, res) = app.publish("订单已支付", &payload, &created.endpoint.id, "idem-demo-order-0001")?;
    match res {
        EnqueueResult::Created(d) | EnqueueResult::Replayed(d) => {
            app.store
                .audit("demo", &d.id, "demo scenario seeded: 503,503,200 expected", now);
        }
        EnqueueResult::Conflict { .. } => anyhow::bail!("demo seed conflict"),
    }
    Ok(())
}

impl App {
    /// Cheaply reconstruct an equivalent handle (all fields are cheap to
    /// clone; used by tests and after wiring).
    pub fn dup(&self) -> App {
        App {
            store: Arc::clone(&self.store),
            queue: Arc::clone(&self.queue),
            cipher: self.cipher.clone(),
            clock: Arc::clone(&self.clock),
            receiver_base: self.receiver_base.clone(),
        }
    }
}
