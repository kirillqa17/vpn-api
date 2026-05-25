//! Web Push (VAPID) sender for browser support-chat notifications.
//!
//! Stores `web_push_subscriptions` rows keyed by `telegram_id` (negative
//! for anonymous web sessions — see `session_to_telegram_id`). When
//! `admin_reply_chat` lands a reply, we spawn `send_to_telegram_id` —
//! same pattern as `crate::push::send_to_user` for mobile FCM.
//!
//! VAPID env: VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT.
//! If any is missing, calls are silent no-ops (logged once).

use sqlx::{PgPool, Row};
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, SubscriptionKeys,
    VapidSignatureBuilder, WebPushClient, WebPushMessageBuilder, URL_SAFE_NO_PAD,
};

/// One row from web_push_subscriptions.
pub struct Subscription {
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

impl Subscription {
    fn to_info(&self) -> SubscriptionInfo {
        SubscriptionInfo {
            endpoint: self.endpoint.clone(),
            keys: SubscriptionKeys {
                p256dh: self.p256dh.clone(),
                auth: self.auth.clone(),
            },
        }
    }
}

/// Send one push. Returns Err(status_code) on non-2xx so caller can prune
/// dead tokens (404/410).
pub async fn send_one(
    sub: &Subscription,
    private_key_b64url: &str,
    subject: &str,
    payload: &serde_json::Value,
) -> Result<(), u16> {
    let info = sub.to_info();
    let mut sig_builder =
        VapidSignatureBuilder::from_base64(private_key_b64url, URL_SAFE_NO_PAD, &info).map_err(
            |e| {
                log::error!("[push_web] VAPID sig build: {}", e);
                500u16
            },
        )?;
    sig_builder.add_claim("sub", subject);
    let sig = sig_builder.build().map_err(|e| {
        log::error!("[push_web] VAPID sig: {}", e);
        500u16
    })?;

    let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let mut msg = WebPushMessageBuilder::new(&info);
    msg.set_vapid_signature(sig);
    msg.set_payload(ContentEncoding::Aes128Gcm, &payload_bytes);

    let client = IsahcWebPushClient::new().map_err(|e| {
        log::error!("[push_web] client init: {}", e);
        500u16
    })?;
    match client
        .send(msg.build().map_err(|e| {
            log::error!("[push_web] build msg: {}", e);
            500u16
        })?)
        .await
    {
        Ok(_) => Ok(()),
        Err(web_push::WebPushError::EndpointNotFound) => Err(404),
        Err(web_push::WebPushError::EndpointNotValid) => Err(410),
        Err(e) => {
            log::error!("[push_web] send: {}", e);
            Err(500)
        }
    }
}

async fn prune(pool: &PgPool, endpoint: &str) {
    let _ = sqlx::query("DELETE FROM web_push_subscriptions WHERE endpoint = $1")
        .bind(endpoint)
        .execute(pool)
        .await;
}

/// Send a push to every subscription belonging to one user.
/// Fire-and-forget — caller already spawned us.
pub async fn send_to_telegram_id(pool: PgPool, telegram_id: i64, title: String, body: String) {
    let private = match std::env::var("VAPID_PRIVATE_KEY") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            log::warn!("[push_web] VAPID_PRIVATE_KEY unset — skipping push");
            return;
        }
    };
    let subject = std::env::var("VAPID_SUBJECT")
        .unwrap_or_else(|_| "mailto:noreply@example.com".to_string());

    let rows = match sqlx::query(
        "SELECT endpoint, p256dh, auth FROM web_push_subscriptions WHERE telegram_id = $1",
    )
    .bind(telegram_id)
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("[push_web] db query for {}: {}", telegram_id, e);
            return;
        }
    };
    if rows.is_empty() {
        return;
    }
    let payload = serde_json::json!({ "title": title, "body": body, "url": "/" });
    let total = rows.len();
    let mut ok = 0usize;
    for row in rows {
        let sub = Subscription {
            endpoint: row.get::<String, _>("endpoint"),
            p256dh: row.get::<String, _>("p256dh"),
            auth: row.get::<String, _>("auth"),
        };
        match send_one(&sub, &private, &subject, &payload).await {
            Ok(()) => ok += 1,
            Err(code) if code == 404 || code == 410 => {
                prune(&pool, &sub.endpoint).await;
            }
            Err(_) => {}
        }
    }
    log::info!("[push_web] tg={} {}/{} delivered", telegram_id, ok, total);
}
