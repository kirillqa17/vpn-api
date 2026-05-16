//! Firebase Cloud Messaging (HTTP v1) sender.
//!
//! No extra crates: the OAuth2 service-account flow is done by hand with
//! `jsonwebtoken` (already a dep) + `reqwest`. The service-account JSON is
//! read from the path in `FCM_SERVICE_ACCOUNT_PATH` at runtime — so the
//! binary builds and deploys fine before the secret exists; push calls
//! just log-and-noop until the file is present.
//!
//! Public surface:
//!   - [`send_to_user`]  — every device of one user (support reply).
//!   - [`blast_news`]    — every news-opted device (channel post).
//!   - [`register_device`] is the HTTP handler, in web_handlers.rs; this
//!     module is only the dispatch side.

use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    token_uri: String,
    project_id: String,
}

/// Cached OAuth2 access token + unix-epoch expiry (seconds). FCM access
/// tokens live 3600s; we refresh ~5 min early.
static TOKEN_CACHE: Mutex<Option<(String, u64)>> = Mutex::new(None);

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn load_service_account() -> Option<ServiceAccount> {
    let path = std::env::var("FCM_SERVICE_ACCOUNT_PATH").ok()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<ServiceAccount>(&raw) {
        Ok(sa) => Some(sa),
        Err(e) => {
            log::error!("[push] service-account JSON parse failed: {}", e);
            None
        }
    }
}

#[derive(serde::Serialize)]
struct OAuthClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

/// Mint (or reuse cached) an FCM access token via the service-account
/// JWT-bearer grant.
async fn access_token(sa: &ServiceAccount) -> Result<String, String> {
    if let Ok(guard) = TOKEN_CACHE.lock() {
        if let Some((tok, exp)) = guard.as_ref() {
            if *exp > now_secs() + 300 {
                return Ok(tok.clone());
            }
        }
    }

    let iat = now_secs();
    let exp = iat + 3600;
    let claims = OAuthClaims {
        iss: &sa.client_email,
        scope: "https://www.googleapis.com/auth/firebase.messaging",
        aud: &sa.token_uri,
        iat,
        exp,
    };
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
        .map_err(|e| format!("bad private_key: {}", e))?;
    let assertion = jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| format!("jwt encode: {}", e))?;

    let client = reqwest::Client::new();
    let resp = client
        .post(&sa.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ])
        .send()
        .await
        .map_err(|e| format!("token req: {}", e))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| format!("token body: {}", e))?;
    if !status.is_success() {
        return Err(format!("token endpoint {}: {}", status, body));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("token json: {}", e))?;
    let tok = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("no access_token in {}", body))?
        .to_string();

    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        *guard = Some((tok.clone(), exp));
    }
    Ok(tok)
}

/// POST one message to FCM v1. Returns Err with the FCM body on non-2xx so
/// the caller can decide whether the token is dead (404/UNREGISTERED).
async fn send_one(
    sa: &ServiceAccount,
    access: &str,
    device_token: &str,
    title: &str,
    body: &str,
    category: &str,
) -> Result<(), (reqwest::StatusCode, String)> {
    let url = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        sa.project_id
    );
    let payload = json!({
        "message": {
            "token": device_token,
            "notification": { "title": title, "body": body },
            // data travels in the silent payload so the app can route the
            // tap (open Support vs News) without parsing the visible text.
            "data": { "category": category },
            "android": {
                "priority": "high",
                "notification": { "channel_id": "svoi_default" }
            }
        }
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(access)
        .json(&payload)
        .send()
        .await
        .map_err(|e| (reqwest::StatusCode::BAD_GATEWAY, e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let txt = resp.text().await.unwrap_or_default();
    Err((status, txt))
}

/// Delete a token row that FCM reported as permanently invalid so the
/// table doesn't accumulate dead devices.
async fn prune_token(pool: &PgPool, device_token: &str) {
    let _ = sqlx::query("DELETE FROM device_tokens WHERE token = $1")
        .bind(device_token)
        .execute(pool)
        .await;
}

async fn dispatch(
    pool: &PgPool,
    rows: Vec<String>,
    title: &str,
    body: &str,
    category: &str,
) {
    if rows.is_empty() {
        return;
    }
    let sa = match load_service_account() {
        Some(s) => s,
        None => {
            log::warn!(
                "[push] FCM_SERVICE_ACCOUNT_PATH unset/unreadable — \
                 skipping {} {} push(es)",
                rows.len(),
                category
            );
            return;
        }
    };
    let access = match access_token(&sa).await {
        Ok(t) => t,
        Err(e) => {
            log::error!("[push] could not get access token: {}", e);
            return;
        }
    };
    let mut ok = 0usize;
    for device_token in rows {
        match send_one(&sa, &access, &device_token, title, body, category).await {
            Ok(()) => ok += 1,
            Err((code, txt)) => {
                // 404 NOT_FOUND / 400 with UNREGISTERED → token is dead.
                if code.as_u16() == 404
                    || (code.as_u16() == 400 && txt.contains("UNREGISTERED"))
                    || txt.contains("\"status\": \"NOT_FOUND\"")
                {
                    prune_token(pool, &device_token).await;
                } else {
                    log::error!("[push] send failed {}: {}", code, txt);
                }
            }
        }
    }
    log::info!("[push] {} {}/{} delivered", category, ok, ok);
}

/// Push to every device of one user, gated by the per-category opt-in.
/// `category` is "support" or "news".
pub async fn send_to_user(
    pool: &PgPool,
    telegram_id: i64,
    title: &str,
    body: &str,
    category: &str,
) {
    let col = if category == "news" {
        "notify_news"
    } else {
        "notify_support"
    };
    let q = format!(
        "SELECT token FROM device_tokens WHERE telegram_id = $1 AND {} = TRUE",
        col
    );
    let rows = match sqlx::query(&q).bind(telegram_id).fetch_all(pool).await {
        Ok(r) => r.iter().map(|row| row.get::<String, _>("token")).collect(),
        Err(e) => {
            log::error!("[push] token query failed: {}", e);
            return;
        }
    };
    dispatch(pool, rows, title, body, category).await;
}

/// Push a news post to every news-opted device across all users.
pub async fn blast_news(pool: &PgPool, title: &str, body: &str) {
    let rows = match sqlx::query(
        "SELECT token FROM device_tokens WHERE notify_news = TRUE",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r.iter().map(|row| row.get::<String, _>("token")).collect(),
        Err(e) => {
            log::error!("[push] news token query failed: {}", e);
            return;
        }
    };
    dispatch(pool, rows, title, body, "news").await;
}
