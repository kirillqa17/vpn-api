use actix_web::{web, HttpRequest, HttpResponse};
use actix_multipart::Multipart;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use sqlx::postgres::PgPool;
use sqlx::Row;
use log::{info, error, warn};
use std::collections::HashMap;
use std::sync::Arc;

use crate::jwt;
use crate::models::{User, SupportChatRequest, InternalSupportChatRequest, InternalSupportEscalateRequest};
use chrono::Utc;
use uuid::Uuid;

// === Security key validation ===
//
// Fail-closed authentication for /admin/* and /internal/* endpoints.
//
// Both keys MUST be set in the process environment before startup, otherwise
// `init_auth_keys()` panics — see main.rs. There is no "empty key bypass"
// and no AUTH_ENFORCE escape hatch (those were P0 vulnerabilities).
// Comparison is constant-time via the `subtle` crate.

use subtle::ConstantTimeEq;

lazy_static::lazy_static! {
    static ref ADMIN_KEY: String = std::env::var("ADMIN_KEY").unwrap_or_default();
    static ref INTERNAL_KEY: String = std::env::var("INTERNAL_KEY").unwrap_or_default();
}

/// Validate that ADMIN_KEY / INTERNAL_KEY are non-empty and reasonably long.
/// Call once at startup; panic if missing — production must never start with
/// open admin endpoints.
pub fn init_auth_keys() {
    if ADMIN_KEY.len() < 32 {
        panic!(
            "ADMIN_KEY env var must be set to at least 32 characters \
             before starting the API. Aborting."
        );
    }
    if INTERNAL_KEY.len() < 32 {
        panic!(
            "INTERNAL_KEY env var must be set to at least 32 characters \
             before starting the API. Aborting."
        );
    }
    info!("[AUTH] Admin/internal keys loaded (lengths {} / {})", ADMIN_KEY.len(), INTERNAL_KEY.len());
}

#[inline]
fn ct_eq(a: &str, b: &str) -> bool {
    // Constant-time compare. Length mismatch is leaked via the early return,
    // which is acceptable since the secrets we compare have a fixed length.
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Check admin key. Returns Some(403) if missing or wrong.
pub fn check_admin_key(req: &HttpRequest) -> Option<HttpResponse> {
    let provided = req.headers().get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct_eq(provided, ADMIN_KEY.as_str()) {
        return None;
    }
    warn!("[AUTH] Invalid admin key from {:?} path={}", req.peer_addr(), req.path());
    Some(HttpResponse::Forbidden().json(json!({"error": "forbidden"})))
}

/// Check internal key. Returns Some(403) if missing or wrong.
fn check_internal_key(req: &HttpRequest) -> Option<HttpResponse> {
    let provided = req.headers().get("X-Internal-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct_eq(provided, INTERNAL_KEY.as_str()) {
        return None;
    }
    warn!("[AUTH] Invalid internal key from {:?} path={}", req.peer_addr(), req.path());
    Some(HttpResponse::Forbidden().json(json!({"error": "forbidden"})))
}

// === Auth endpoints ===

#[derive(Deserialize)]
pub struct TelegramAuthRequest {
    #[serde(rename = "initData")]
    init_data: String,
}

/// Auto-register a new user (same logic as create_user in main.rs)
async fn auto_register_user(pool: &PgPool, telegram_id: i64, username: Option<String>, referral_id: Option<i64>) -> Result<(), HttpResponse> {
    let raw_username = username.unwrap_or_else(|| format!("user_{}", telegram_id));
    // Remnawave only accepts [a-zA-Z0-9_-] — sanitize username
    let username: String = raw_username.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let username = if username.is_empty() { format!("user_{}", telegram_id) } else { username };
    info!("[auto_register] Creating user {} ({}) referral={:?}", telegram_id, username, referral_id);

    // Create in Remnawave
    let api_response = HTTP_CLIENT
        .post(&format!("{}/users", *REMNAWAVE_API_BASE))
        .headers(remnawave_headers())
        .json(&json!({
            "username": username,
            "status": "DISABLED",
            "trafficLimitBytes": 0,
            "trafficLimitStrategy": "MONTH",
            "expireAt": Utc::now(),
            "createdAt": Utc::now(),
            "telegramId": telegram_id,
            "hwidDeviceLimit": 2,
            "activeInternalSquads": ["514a5e22-c599-4f72-81a5-e646f0391db7"],
        }))
        .send()
        .await
        .map_err(|e| {
            error!("[auto_register] Remnawave API failed for {}: {}", telegram_id, e);
            { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) }
        })?;

    if !api_response.status().is_success() {
        let status = api_response.status();
        let body = api_response.text().await.unwrap_or_default();
        error!("[auto_register] Remnawave error for {} ({}): {}", telegram_id, status, body);
        if body.contains("already exists") {
            return Err(HttpResponse::Conflict().json(json!({"error": "Ошибка регистрации. Попробуйте снова через минуту."})));
        }
        return Err(HttpResponse::InternalServerError().json(json!({"error": "Ошибка при создании аккаунта. Попробуйте позже."})));
    }

    let json_response: serde_json::Value = api_response.json().await.map_err(|e| {
        error!("[auto_register] Failed to parse Remnawave response: {}", e);
        { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) }
    })?;

    let uuid_str = json_response["response"]["uuid"].as_str()
        .ok_or_else(|| HttpResponse::InternalServerError().body("Missing uuid in Remnawave response"))?;
    let uuid = Uuid::parse_str(uuid_str)
        .map_err(|_| HttpResponse::InternalServerError().body("Invalid uuid"))?;
    let sub_url = json_response["response"]["subscriptionUrl"].as_str().unwrap_or("").to_string();

    sqlx::query(
        "INSERT INTO users (telegram_id, uuid, subscription_end, is_active, created_at, is_used_trial, game_points, is_used_ref_bonus, game_attempts, username, sub_link, payed_refs, is_pro, referral_id) \
         VALUES ($1, $2, NOW(), 0, NOW(), false, 0, false, 0, $3, $4, 0, false, $5)"
    )
    .bind(telegram_id)
    .bind(uuid)
    .bind(&username)
    .bind(&sub_url)
    .bind(referral_id)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("[auto_register] DB insert failed for {}: {}", telegram_id, e);
        { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) }
    })?;

    // Add to referrer's referrals array
    if let Some(ref_id) = referral_id {
        let _ = sqlx::query("UPDATE users SET referrals = array_append(referrals, $1) WHERE telegram_id = $2")
            .bind(telegram_id)
            .bind(ref_id)
            .execute(pool)
            .await;
        info!("[auto_register] Added {} to referrer {}'s referrals", telegram_id, ref_id);
    }

    info!("[auto_register] Successfully created user {} (uuid={})", telegram_id, uuid);
    Ok(())
}

pub async fn auth_telegram(
    pool: web::Data<PgPool>,
    data: web::Json<TelegramAuthRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::validate_init_data(&data.init_data) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().body("Invalid initData"),
    };

    // Check if user exists, auto-register if not
    let exists = sqlx::query("SELECT telegram_id FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await;

    match exists {
        Ok(Some(_)) => {}
        Ok(None) => {
            // Extract username from initData
            let username = jwt::extract_username_from_init_data(&data.init_data);
            if let Err(resp) = auto_register_user(pool.get_ref(), telegram_id, username, None).await {
                return resp;
            }
        }
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }

    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "Ошибка авторизации. Попробуйте позже."})),
    };

    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": telegram_id }))
}

// auth_telegram_login (Widget) — REMOVED, replaced by bot-based flow

// === Email auth ===

#[derive(Deserialize)]
pub struct EmailRegisterRequest {
    email: String,
    password: String,
    referral_id: Option<i64>,
}

#[derive(Deserialize)]
pub struct EmailLoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    email: String,
    code: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    email: String,
    code: String,
    new_password: String,
}

fn generate_6digit_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1000000))
}

async fn check_rate_limit(pool: &PgPool, email: &str) -> bool {
    let recent = sqlx::query(
        "SELECT id FROM email_verification_codes WHERE email = $1 AND created_at > NOW() - INTERVAL '60 seconds' LIMIT 1"
    )
    .bind(email)
    .fetch_optional(pool)
    .await;
    matches!(recent, Ok(Some(_)))
}

pub async fn auth_email_register(
    pool: web::Data<PgPool>,
    data: web::Json<EmailRegisterRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();
    let password = &data.password;

    if !email.contains('@') || email.len() < 5 {
        return HttpResponse::BadRequest().json(json!({"error": "Введите корректный email адрес"}));
    }
    if password.len() < 6 {
        return HttpResponse::BadRequest().json(json!({"error": "Пароль должен быть не менее 6 символов"}));
    }

    // Check if email already taken and verified
    let exists = sqlx::query("SELECT email_verified FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await;

    match &exists {
        Ok(Some(row)) => {
            let verified: bool = row.get("email_verified");
            if verified {
                return HttpResponse::Conflict().json(json!({"error": "Аккаунт с этим email уже зарегистрирован. Войдите или восстановите пароль."}));
            }
            // Not verified — delete old unverified account so they can re-register
            // Clean up from user_credentials, users table, AND Remnawave
            if let Ok(Some(old_row)) = sqlx::query("SELECT telegram_id, uuid FROM user_credentials uc JOIN users u ON uc.telegram_id = u.telegram_id WHERE uc.email = $1 AND uc.email_verified = FALSE")
                .bind(&email)
                .fetch_optional(pool.get_ref())
                .await
            {
                let old_tg_id: i64 = old_row.get("telegram_id");
                let old_uuid: uuid::Uuid = old_row.get("uuid");

                // Delete from Remnawave
                let _ = HTTP_CLIENT
                    .delete(&format!("{}/users/{}", *REMNAWAVE_API_BASE, old_uuid))
                    .headers(remnawave_headers())
                    .send()
                    .await;
                info!("[auth_email_register] Deleted Remnawave user {} (uuid={})", old_tg_id, old_uuid);

                let _ = sqlx::query("DELETE FROM user_credentials WHERE email = $1 AND email_verified = FALSE")
                    .bind(&email)
                    .execute(pool.get_ref())
                    .await;
                let _ = sqlx::query("DELETE FROM users WHERE telegram_id = $1")
                    .bind(old_tg_id)
                    .execute(pool.get_ref())
                    .await;
                info!("[auth_email_register] Cleaned up unverified account for {} (tg_id={})", email, old_tg_id);
            } else if let Ok(Some(_)) = sqlx::query("SELECT telegram_id FROM user_credentials WHERE email = $1 AND email_verified = FALSE")
                .bind(&email)
                .fetch_optional(pool.get_ref())
                .await
            {
                // Fallback: no users row (maybe failed earlier), just clean credentials
                let _ = sqlx::query("DELETE FROM user_credentials WHERE email = $1 AND email_verified = FALSE")
                    .bind(&email)
                    .execute(pool.get_ref())
                    .await;
            }
        }
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
        _ => {}
    }

    // Rate limit
    if check_rate_limit(pool.get_ref(), &email).await {
        return HttpResponse::TooManyRequests().json(json!({"error": "Код уже отправлен. Подождите 60 секунд перед повторной отправкой."}));
    }

    // Generate synthetic negative telegram_id
    let synthetic_id: i64 = match sqlx::query_scalar::<_, i64>("SELECT -nextval('email_user_id_seq')")
        .fetch_one(pool.get_ref())
        .await
    {
        Ok(id) => id,
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal server error"})) },
    };

    // Hash password
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "Ошибка при создании аккаунта. Попробуйте позже."})),
    };

    // Create user in Remnawave + DB (sanitize email for Remnawave username)
    let username = email.replace('@', "_at_").replace('.', "_");
    if let Err(resp) = auto_register_user(pool.get_ref(), synthetic_id, Some(username), data.referral_id).await {
        return resp;
    }

    // Save credentials (unverified)
    let result = sqlx::query(
        "INSERT INTO user_credentials (telegram_id, email, password_hash, email_verified) VALUES ($1, $2, $3, FALSE)"
    )
    .bind(synthetic_id)
    .bind(&email)
    .bind(&password_hash)
    .execute(pool.get_ref())
    .await;

    if let Err(e) = result {
        error!("[auth_email_register] Failed to save credentials: {}", e);
        return HttpResponse::InternalServerError().json(json!({"error": "Ошибка при сохранении данных. Попробуйте позже."}));
    }

    // Generate verification code
    let code = generate_6digit_code();
    let _ = sqlx::query(
        "INSERT INTO email_verification_codes (email, code, purpose, expires_at) VALUES ($1, $2, 'register', NOW() + INTERVAL '30 minutes')"
    )
    .bind(&email)
    .bind(&code)
    .execute(pool.get_ref())
    .await;

    // Send email
    if let Err(e) = crate::email::send_verification_code(&email, &code).await {
        error!("[auth_email_register] Failed to send verification email: {}", e);
        return HttpResponse::InternalServerError().json(json!({"error": "Не удалось отправить код на email. Проверьте адрес и попробуйте позже."}));
    }

    info!("[auth_email_register] Verification code sent to {} (id={})", email, synthetic_id);
    HttpResponse::Ok().json(json!({ "message": "Код подтверждения отправлен на email" }))
}

pub async fn auth_verify_email(
    pool: web::Data<PgPool>,
    data: web::Json<VerifyEmailRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();
    let code = data.code.trim();

    // Find valid code
    let row = match sqlx::query(
        "SELECT id FROM email_verification_codes WHERE email = $1 AND code = $2 AND purpose = 'register' AND used = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&email)
    .bind(code)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::BadRequest().json(json!({"error": "Неверный или просроченный код"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let code_id: i64 = row.get("id");

    // Mark code as used
    let _ = sqlx::query("UPDATE email_verification_codes SET used = TRUE WHERE id = $1")
        .bind(code_id)
        .execute(pool.get_ref())
        .await;

    // Set email_verified = true
    let _ = sqlx::query("UPDATE user_credentials SET email_verified = TRUE WHERE email = $1")
        .bind(&email)
        .execute(pool.get_ref())
        .await;

    // Get telegram_id and generate JWT
    let cred_row = match sqlx::query("SELECT telegram_id FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "Пользователь не найден"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let telegram_id: i64 = cred_row.get("telegram_id");
    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "Ошибка авторизации. Попробуйте позже."})),
    };

    info!("[auth_verify_email] Email verified: {} (id={})", email, telegram_id);
    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": telegram_id }))
}

pub async fn auth_email_login(
    pool: web::Data<PgPool>,
    data: web::Json<EmailLoginRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();

    let row = match sqlx::query("SELECT telegram_id, password_hash, email_verified FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::Unauthorized().json(json!({"error": "Неверный email или пароль"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let telegram_id: i64 = row.get("telegram_id");
    let stored_hash: String = row.get("password_hash");
    let verified: bool = row.get("email_verified");

    // Verify password
    use argon2::{Argon2, PasswordVerifier};
    use argon2::password_hash::PasswordHash;

    let parsed_hash = match PasswordHash::new(&stored_hash) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "Ошибка авторизации. Попробуйте позже."})),
    };

    if Argon2::default().verify_password(data.password.as_bytes(), &parsed_hash).is_err() {
        return HttpResponse::Unauthorized().json(json!({"error": "Неверный email или пароль"}));
    }

    if !verified {
        return HttpResponse::Forbidden().json(json!({"error": "Email не подтверждён", "needs_verification": true}));
    }

    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "Ошибка авторизации. Попробуйте позже."})),
    };

    info!("[auth_email_login] Email login: {} (id={})", email, telegram_id);
    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": telegram_id }))
}

pub async fn auth_forgot_password(
    pool: web::Data<PgPool>,
    data: web::Json<ForgotPasswordRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();

    // Check if email exists and is verified
    let row = sqlx::query("SELECT email_verified FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await;

    match row {
        Ok(None) => {
            info!("[auth_forgot_password] Email not registered: {}", email);
            return HttpResponse::BadRequest().json(json!({
                "error": "Этот email не зарегистрирован. Зарегистрируйтесь на сайте или войдите через Telegram."
            }));
        }
        Ok(Some(r)) => {
            let verified: bool = r.get("email_verified");
            if !verified {
                info!("[auth_forgot_password] Email not verified: {}", email);
                return HttpResponse::BadRequest().json(json!({
                    "error": "Email не подтверждён. Войдите через Telegram и подтвердите email в настройках."
                }));
            }
        }
        Err(e) => {
            error!("[auth_forgot_password] DB error: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"}));
        }
    }

    if check_rate_limit(pool.get_ref(), &email).await {
        return HttpResponse::TooManyRequests().json(json!({
            "error": "Код уже отправлен. Подождите несколько минут перед повторной отправкой."
        }));
    }

    let code = generate_6digit_code();
    let _ = sqlx::query(
        "INSERT INTO email_verification_codes (email, code, purpose, expires_at) VALUES ($1, $2, 'reset_password', NOW() + INTERVAL '30 minutes')"
    )
    .bind(&email)
    .bind(&code)
    .execute(pool.get_ref())
    .await;

    if let Err(e) = crate::email::send_reset_code(&email, &code).await {
        error!("[auth_forgot_password] Failed to send reset email: {}", e);
    }

    info!("[auth_forgot_password] Reset code sent to {}", email);
    HttpResponse::Ok().json(json!({ "message": "Код для сброса пароля отправлен на вашу почту" }))
}

pub async fn auth_reset_password(
    pool: web::Data<PgPool>,
    data: web::Json<ResetPasswordRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();
    let code = data.code.trim();
    let new_password = &data.new_password;

    if new_password.len() < 6 {
        return HttpResponse::BadRequest().json(json!({"error": "Пароль должен быть не менее 6 символов"}));
    }

    // Find valid code
    let row = match sqlx::query(
        "SELECT id FROM email_verification_codes WHERE email = $1 AND code = $2 AND purpose = 'reset_password' AND used = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&email)
    .bind(code)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::BadRequest().json(json!({"error": "Неверный или просроченный код"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let code_id: i64 = row.get("id");

    // Hash new password
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "Ошибка при смене пароля. Попробуйте позже."})),
    };

    // Update password
    let _ = sqlx::query("UPDATE user_credentials SET password_hash = $1 WHERE email = $2")
        .bind(&password_hash)
        .bind(&email)
        .execute(pool.get_ref())
        .await;

    // Mark code as used
    let _ = sqlx::query("UPDATE email_verification_codes SET used = TRUE WHERE id = $1")
        .bind(code_id)
        .execute(pool.get_ref())
        .await;

    info!("[auth_reset_password] Password reset for {}", email);
    HttpResponse::Ok().json(json!({ "message": "Пароль успешно изменён" }))
}

// === Telegram auth from mobile app ===

pub async fn auth_telegram_init(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    use rand::Rng;
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    // If user is already logged in (has JWT), save their current id for account migration
    let initiated_by: Option<i64> = jwt::extract_telegram_id(&req).ok();

    let result = sqlx::query(
        "INSERT INTO telegram_auth_codes (code, expires_at, initiated_by) VALUES ($1, NOW() + INTERVAL '5 minutes', $2)"
    )
    .bind(&code)
    .bind(initiated_by)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            info!("[auth_telegram_init] Created auth code: {}", code);
            HttpResponse::Ok().json(json!({ "code": code }))
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

pub async fn auth_telegram_check(
    pool: web::Data<PgPool>,
    path: web::Path<String>,
) -> HttpResponse {
    let code = path.into_inner();

    let row = match sqlx::query(
        "SELECT telegram_id, initiated_by FROM telegram_auth_codes WHERE code = $1 AND expires_at > NOW()"
    )
    .bind(&code)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "Code expired or not found"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let tg_id: Option<i64> = row.get("telegram_id");
    let initiated_by: Option<i64> = row.get("initiated_by");

    match tg_id {
        Some(id) => {
            // Confirmed — generate JWT and cleanup
            let _ = sqlx::query("DELETE FROM telegram_auth_codes WHERE code = $1")
                .bind(&code)
                .execute(pool.get_ref())
                .await;

            // If initiated by an email account (negative synthetic_id), migrate account to real telegram_id
            if let Some(old_id) = initiated_by {
                if old_id < 0 && old_id != id {
                    // Check if old account exists and real tg account doesn't
                    let old_exists = sqlx::query("SELECT telegram_id FROM users WHERE telegram_id = $1")
                        .bind(old_id).fetch_optional(pool.get_ref()).await.ok().flatten().is_some();
                    let new_exists = sqlx::query("SELECT telegram_id FROM users WHERE telegram_id = $1")
                        .bind(id).fetch_optional(pool.get_ref()).await.ok().flatten().is_some();

                    if old_exists && !new_exists {
                        // Migrate: update users table from old synthetic_id to real telegram_id
                        let _ = sqlx::query("UPDATE users SET telegram_id = $1 WHERE telegram_id = $2")
                            .bind(id).bind(old_id).execute(pool.get_ref()).await;
                        // Migrate credentials
                        let _ = sqlx::query("UPDATE user_credentials SET telegram_id = $1 WHERE telegram_id = $2")
                            .bind(id).bind(old_id).execute(pool.get_ref()).await;
                        // Migrate support chats
                        let _ = sqlx::query("UPDATE support_chats SET telegram_id = $1 WHERE telegram_id = $2")
                            .bind(id).bind(old_id).execute(pool.get_ref()).await;
                        info!("[auth_telegram_check] Migrated account {} -> {} (email user linked TG)", old_id, id);
                    } else if old_exists && new_exists {
                        // Both accounts exist — link email credentials to existing TG account, keep TG subscription
                        let _ = sqlx::query("UPDATE user_credentials SET telegram_id = $1 WHERE telegram_id = $2")
                            .bind(id).bind(old_id).execute(pool.get_ref()).await;
                        info!("[auth_telegram_check] Linked email credentials from {} to existing TG account {}", old_id, id);
                    }
                }
            }

            let token = match jwt::create_token(id) {
                Ok(t) => t,
                Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "Ошибка авторизации. Попробуйте позже."})),
            };

            info!("[auth_telegram_check] Auth confirmed for tg_id={}", id);
            HttpResponse::Ok().json(json!({ "token": token, "telegram_id": id }))
        }
        None => {
            // Not yet confirmed — still pending
            HttpResponse::Accepted().json(json!({ "status": "pending" }))
        }
    }
}

#[derive(Deserialize)]
pub struct TelegramConfirmRequest {
    pub code: String,
    pub telegram_id: i64,
}

pub async fn auth_telegram_confirm(
    pool: web::Data<PgPool>,
    data: web::Json<TelegramConfirmRequest>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let result = sqlx::query(
        "UPDATE telegram_auth_codes SET telegram_id = $1 WHERE code = $2 AND expires_at > NOW() AND telegram_id IS NULL"
    )
    .bind(data.telegram_id)
    .bind(&data.code)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!("[auth_telegram_confirm] Code {} confirmed by tg_id={}", data.code, data.telegram_id);
            HttpResponse::Ok().json(json!({ "status": "ok" }))
        }
        Ok(_) => HttpResponse::NotFound().body("Code not found or expired"),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

pub async fn auth_link_email(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    data: web::Json<EmailRegisterRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let email = data.email.trim().to_lowercase();
    let password = &data.password;

    if !email.contains('@') || email.len() < 5 {
        return HttpResponse::BadRequest().body("Invalid email");
    }
    if password.len() < 8 {
        return HttpResponse::BadRequest().body("Password must be at least 8 characters");
    }

    // Check email not taken
    let exists = sqlx::query("SELECT id FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await;

    match exists {
        Ok(Some(_)) => return HttpResponse::Conflict().body("Email already taken"),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
        _ => {}
    }

    // Check user doesn't already have credentials
    let has_creds = sqlx::query("SELECT id FROM user_credentials WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await;

    if let Ok(Some(_)) = has_creds {
        return HttpResponse::Conflict().body("Account already has email linked");
    }

    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return HttpResponse::InternalServerError().body("Failed to hash password"),
    };

    let result = sqlx::query(
        "INSERT INTO user_credentials (telegram_id, email, password_hash) VALUES ($1, $2, $3)"
    )
    .bind(telegram_id)
    .bind(&email)
    .bind(&password_hash)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            info!("[auth_link_email] Linked email {} to user {}", email, telegram_id);
            HttpResponse::Ok().json(json!({"status": "ok"}))
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === Account linking ===

pub async fn internal_link_account(
    pool: web::Data<PgPool>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }

    let tg_id = match body.get("tg_id").and_then(|v| v.as_i64()) {
        Some(id) => id,
        None => return HttpResponse::BadRequest().json(json!({"error": "tg_id required"})),
    };
    let email = match body.get("email").and_then(|v| v.as_str()) {
        Some(e) => e.trim().to_lowercase(),
        None => return HttpResponse::BadRequest().json(json!({"error": "email required"})),
    };
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(json!({"error": "password required"})),
    };

    // Check if TG user already has linked email
    let existing_link = sqlx::query("SELECT email FROM user_credentials WHERE telegram_id = $1 AND email_verified = TRUE")
        .bind(tg_id)
        .fetch_optional(pool.get_ref())
        .await;
    if let Ok(Some(row)) = &existing_link {
        let linked_email: String = row.get("email");
        return HttpResponse::Conflict().json(json!({"error": format!("Аккаунт уже привязан к {}", linked_email)}));
    }

    // Verify email credentials
    let cred_row = match sqlx::query("SELECT telegram_id, password_hash, email_verified FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::Unauthorized().json(json!({"error": "Неверный email или пароль"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let email_tg_id: i64 = cred_row.get("telegram_id");
    let stored_hash: String = cred_row.get("password_hash");
    let verified: bool = cred_row.get("email_verified");

    // Verify password
    use argon2::{Argon2, PasswordVerifier};
    use argon2::password_hash::PasswordHash;
    let parsed_hash = match PasswordHash::new(&stored_hash) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "internal server error"})),
    };
    if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_err() {
        return HttpResponse::Unauthorized().json(json!({"error": "Неверный email или пароль"}));
    }
    if !verified {
        return HttpResponse::BadRequest().json(json!({"error": "Email не подтверждён. Сначала подтвердите email на сайте."}));
    }

    // If email is already linked to this same TG user
    if email_tg_id == tg_id {
        return HttpResponse::Ok().json(json!({"status": "already_linked", "email": email}));
    }

    // Get both users' subscription info
    let tg_user = sqlx::query("SELECT uuid, subscription_end, sub_link, plan, is_active, device_limit, is_pro FROM users WHERE telegram_id = $1")
        .bind(tg_id).fetch_optional(pool.get_ref()).await.ok().flatten();
    let email_user = sqlx::query("SELECT uuid, subscription_end, sub_link, plan, is_active, device_limit, is_pro FROM users WHERE telegram_id = $1")
        .bind(email_tg_id).fetch_optional(pool.get_ref()).await.ok().flatten();

    // Determine which subscription is better (longer expiry)
    let tg_sub_end: Option<chrono::DateTime<chrono::Utc>> = tg_user.as_ref().and_then(|r| r.try_get("subscription_end").ok());
    let email_sub_end: Option<chrono::DateTime<chrono::Utc>> = email_user.as_ref().and_then(|r| r.try_get("subscription_end").ok());

    let keep_email_sub = match (tg_sub_end, email_sub_end) {
        (Some(tg), Some(em)) => em > tg,
        (None, Some(_)) => true,
        _ => false,
    };

    // Winner = account with longer subscription, loser = the other one
    // After merge: winner's Remnawave user (sub_link) stays, loser's gets deleted
    let tg_uuid: Option<uuid::Uuid> = tg_user.as_ref().and_then(|r| r.try_get("uuid").ok());
    let email_uuid: Option<uuid::Uuid> = email_user.as_ref().and_then(|r| r.try_get("uuid").ok());

    if keep_email_sub {
        // Email account wins — take its sub_link, plan, settings; delete TG's Remnawave user
        if let Some(email_row) = &email_user {
            let email_sub_link: String = email_row.try_get("sub_link").unwrap_or_default();
            let email_plan: Option<String> = email_row.try_get("plan").ok();
            let email_is_active: i32 = email_row.try_get("is_active").unwrap_or(0);
            let email_device_limit: i32 = email_row.try_get("device_limit").unwrap_or(2);
            let email_is_pro: bool = email_row.try_get("is_pro").unwrap_or(false);

            // Update TG user's DB record with email account's subscription data
            let _ = sqlx::query(
                "UPDATE users SET subscription_end = $1, sub_link = $2, uuid = $3, plan = $4, is_active = $5, device_limit = $6, is_pro = $7 WHERE telegram_id = $8"
            )
            .bind(email_sub_end.unwrap())
            .bind(&email_sub_link)
            .bind(email_uuid.unwrap())
            .bind(&email_plan)
            .bind(email_is_active)
            .bind(email_device_limit)
            .bind(email_is_pro)
            .bind(tg_id)
            .execute(pool.get_ref())
            .await;

            // Update winner's Remnawave user telegramId to the real TG id
            let expire_str = email_sub_end.unwrap().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
            let _ = HTTP_CLIENT
                .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
                .headers(remnawave_headers())
                .json(&json!({
                    "uuid": email_uuid.unwrap().to_string(),
                    "telegramId": tg_id,
                    "status": "ACTIVE",
                    "expireAt": expire_str
                }))
                .send()
                .await;

            // Delete loser's Remnawave user (TG's old one)
            if let Some(loser_uuid) = tg_uuid {
                let _ = HTTP_CLIENT
                    .delete(&format!("{}/users/{}", *REMNAWAVE_API_BASE, loser_uuid))
                    .headers(remnawave_headers())
                    .send()
                    .await;
                info!("[internal_link_account] Deleted loser Remnawave user (TG) uuid={}", loser_uuid);
            }

            info!("[internal_link_account] Email wins: migrated sub+plan from {} to {}", email_tg_id, tg_id);
        }
    } else {
        // TG account wins — keep its sub_link; delete email's Remnawave user
        if let Some(loser_uuid) = email_uuid {
            let _ = HTTP_CLIENT
                .delete(&format!("{}/users/{}", *REMNAWAVE_API_BASE, loser_uuid))
                .headers(remnawave_headers())
                .send()
                .await;
            info!("[internal_link_account] Deleted loser Remnawave user (email) uuid={}", loser_uuid);
        }
    }

    // Move email credentials to TG account
    let _ = sqlx::query("UPDATE user_credentials SET telegram_id = $1 WHERE email = $2")
        .bind(tg_id)
        .bind(&email)
        .execute(pool.get_ref())
        .await;

    // Clean up email user's DB record (always — their Remnawave user was already handled above)
    if email_tg_id != tg_id {
        let _ = sqlx::query("DELETE FROM users WHERE telegram_id = $1")
            .bind(email_tg_id)
            .execute(pool.get_ref())
            .await;
    }

    info!("[internal_link_account] Linked email {} to TG user {} (was {})", email, tg_id, email_tg_id);
    HttpResponse::Ok().json(json!({
        "status": "linked",
        "email": email,
        "subscription_migrated": keep_email_sub
    }))
}

// === User info ===

pub async fn web_get_me(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let user = sqlx::query(
        "SELECT telegram_id, uuid, subscription_end, is_active, created_at, referrals, referral_id, \
         is_used_trial, is_used_ref_bonus, username, plan, sub_link, payed_refs, device_limit, \
         auto_renew, payment_method_id, auto_renew_plan, auto_renew_duration, is_pro, card_last4, \
         first_purchase_bonus_used, first_purchase_bonus_deadline \
         FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await;

    // Get linked email if exists
    let email_row = sqlx::query("SELECT email FROM user_credentials WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await
        .ok()
        .flatten();

    let email: Option<String> = email_row.map(|r| r.get("email"));

    match user {
        Ok(Some(row)) => {
            let referrals: Option<Vec<i64>> = row.get("referrals");
            let is_used_trial: bool = row.get("is_used_trial");
            let bonus_used: bool = row.get("first_purchase_bonus_used");
            let bonus_deadline: Option<chrono::DateTime<chrono::Utc>> = row.get("first_purchase_bonus_deadline");
            let now = chrono::Utc::now();
            let (bonus_eligible, bonus_days_left) = match bonus_deadline {
                Some(deadline) if is_used_trial && !bonus_used && deadline > now => {
                    let secs = (deadline - now).num_seconds();
                    let days = (secs + 86399) / 86400;
                    (true, Some(days))
                }
                _ => (false, None),
            };

            HttpResponse::Ok().json(json!({
                "telegram_id": row.get::<i64, _>("telegram_id"),
                "uuid": row.get::<uuid::Uuid, _>("uuid").to_string(),
                "subscription_end": row.get::<chrono::DateTime<chrono::Utc>, _>("subscription_end").to_rfc3339(),
                "is_active": row.get::<i32, _>("is_active"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                "referrals": referrals.unwrap_or_default(),
                "referral_id": row.get::<Option<i64>, _>("referral_id"),
                "is_used_trial": is_used_trial,
                "is_used_ref_bonus": row.get::<bool, _>("is_used_ref_bonus"),
                "username": row.get::<Option<String>, _>("username").unwrap_or_default(),
                "plan": row.get::<String, _>("plan"),
                "sub_link": row.get::<String, _>("sub_link"),
                "payed_refs": row.get::<i64, _>("payed_refs"),
                "device_limit": row.get::<i64, _>("device_limit"),
                "auto_renew": row.get::<bool, _>("auto_renew"),
                "payment_method_id": row.get::<Option<String>, _>("payment_method_id").unwrap_or_default(),
                "auto_renew_plan": row.get::<Option<String>, _>("auto_renew_plan").unwrap_or_default(),
                "auto_renew_duration": row.get::<Option<String>, _>("auto_renew_duration").unwrap_or_default(),
                "is_pro": row.get::<bool, _>("is_pro"),
                "card_last4": row.get::<Option<String>, _>("card_last4").unwrap_or_default(),
                "email": email,
                "first_purchase_bonus_eligible": bonus_eligible,
                "first_purchase_bonus_days_left": bonus_days_left,
            }))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found"),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === Devices ===

lazy_static::lazy_static! {
    static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::new();
    static ref REMNAWAVE_API_BASE: String = std::env::var("REMNAWAVE_API_BASE").unwrap_or_else(|_| "http://localhost:3000/api".to_string());
    static ref REMNAWAVE_API_KEY: String = std::env::var("REMNAWAVE_API_KEY").expect("REMNAWAVE_API_KEY must be set");
    static ref PROXYAPI_KEY: String = std::env::var("PROXYAPI_KEY")
        .expect("PROXYAPI_KEY must be set");
    static ref PROXYAPI_BASE_URL: String = std::env::var("PROXYAPI_BASE_URL")
        .unwrap_or_else(|_| "https://openai.api.proxyapi.ru/v1".to_string());
    static ref SUPPORT_BOT_TOKEN: String = std::env::var("SUPPORT_BOT_TOKEN")
        .expect("SUPPORT_BOT_TOKEN must be set");
    static ref ADMIN_IDS: Vec<i64> = std::env::var("ADMIN_IDS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
}

fn remnawave_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert("Authorization", format!("Bearer {}", *REMNAWAVE_API_KEY).parse().unwrap());
    h.insert("Content-Type", "application/json".parse().unwrap());
    h.insert("X-Forwarded-For", "127.0.0.1".parse().unwrap());
    h.insert("X-Forwarded-Proto", "https".parse().unwrap());
    h
}

async fn get_user_uuid(pool: &PgPool, telegram_id: i64) -> Result<String, HttpResponse> {
    let row = sqlx::query("SELECT uuid FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) })?
        .ok_or_else(|| HttpResponse::NotFound().body("User not found"))?;

    Ok(row.get::<uuid::Uuid, _>("uuid").to_string())
}

pub async fn web_get_devices(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let uuid = match get_user_uuid(pool.get_ref(), telegram_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let resp = HTTP_CLIENT
        .get(&format!("{}/hwid/devices/{}", *REMNAWAVE_API_BASE, uuid))
        .headers(remnawave_headers())
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(json) => {
                    let devices = json["response"]["devices"].clone();
                    HttpResponse::Ok().json(json!({ "devices": devices }))
                }
                Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
            }
        }
        Ok(r) => HttpResponse::InternalServerError().json(json!({"error": "internal server error"})),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

pub async fn web_delete_device(pool: web::Data<PgPool>, req: HttpRequest, hwid: web::Path<String>) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let uuid = match get_user_uuid(pool.get_ref(), telegram_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let resp = HTTP_CLIENT
        .post(&format!("{}/hwid/devices/delete", *REMNAWAVE_API_BASE))
        .headers(remnawave_headers())
        .json(&json!({ "userUuid": uuid, "hwid": hwid.into_inner() }))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => HttpResponse::Ok().json(json!({"status": "ok"})),
        Ok(r) => HttpResponse::InternalServerError().json(json!({"error": "internal server error"})),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === Connection check ===

pub async fn web_check_connection(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let uuid = match get_user_uuid(pool.get_ref(), telegram_id).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let resp = HTTP_CLIENT
        .get(&format!("{}/hwid/devices/{}", *REMNAWAVE_API_BASE, uuid))
        .headers(remnawave_headers())
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(json) => {
                    let total = json["response"]["total"].as_u64().unwrap_or(0);
                    HttpResponse::Ok().json(json!({ "connected": total > 0 }))
                }
                Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
            }
        }
        Ok(_) => HttpResponse::Ok().json(json!({ "connected": false })),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === Subscription prices ===

pub async fn web_get_prices() -> HttpResponse {
    let bs_month_only = std::env::var("BS_MONTH_ONLY")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true");
    let prices = json!({
        "bs_month_only": bs_month_only,
        "base": {
            "1m": std::env::var("BASE_MONTH").unwrap_or_else(|_| "150".to_string()).parse::<i64>().unwrap_or(150),
            "3m": std::env::var("BASE_3_MONTH").unwrap_or_else(|_| "430".to_string()).parse::<i64>().unwrap_or(430),
            "1y": std::env::var("BASE_YEAR").unwrap_or_else(|_| "1500".to_string()).parse::<i64>().unwrap_or(1500),
        },
        "family": {
            "1m": std::env::var("FAMILY_MONTH").unwrap_or_else(|_| "250".to_string()).parse::<i64>().unwrap_or(250),
            "3m": std::env::var("FAMILY_3_MONTH").unwrap_or_else(|_| "700".to_string()).parse::<i64>().unwrap_or(700),
            "1y": std::env::var("FAMILY_YEAR").unwrap_or_else(|_| "2200".to_string()).parse::<i64>().unwrap_or(2200),
        },
        "bsbase": {
            "1m": std::env::var("BSBASE_MONTH").unwrap_or_else(|_| "450".to_string()).parse::<i64>().unwrap_or(450),
            "3m": std::env::var("BSBASE_3_MONTH").unwrap_or_else(|_| "1250".to_string()).parse::<i64>().unwrap_or(1250),
            "1y": std::env::var("BSBASE_YEAR").unwrap_or_else(|_| "4500".to_string()).parse::<i64>().unwrap_or(4500),
        },
        "bsfamily": {
            "1m": std::env::var("BSFAMILY_MONTH").unwrap_or_else(|_| "750".to_string()).parse::<i64>().unwrap_or(750),
            "3m": std::env::var("BSFAMILY_3_MONTH").unwrap_or_else(|_| "2100".to_string()).parse::<i64>().unwrap_or(2100),
            "1y": std::env::var("BSFAMILY_YEAR").unwrap_or_else(|_| "7500".to_string()).parse::<i64>().unwrap_or(7500),
        }
    });

    HttpResponse::Ok().json(prices)
}

// === Trial ===

pub async fn web_activate_trial(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Check if trial already used
    let user = sqlx::query("SELECT is_used_trial, uuid FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await;

    let row = match user {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "Пользователь не найден"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    if row.get::<bool, _>("is_used_trial") {
        return HttpResponse::BadRequest().body("Trial already used");
    }

    // All users get 7 days trial (email verified via 2FA)
    let interval_sql = "INTERVAL '7 days'";
    let duration = chrono::Duration::days(7);

    let result = sqlx::query(&format!(
        "UPDATE users SET is_used_trial = true, is_active = 1, plan = 'trial', \
         subscription_end = GREATEST(subscription_end, NOW()) + {} \
         WHERE telegram_id = $1", interval_sql
    ))
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    if let Err(e) = result {
        return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
    }

    // Update Remnawave
    let uuid = row.get::<uuid::Uuid, _>("uuid");
    let new_expire = chrono::Utc::now() + duration;

    let _ = HTTP_CLIENT
        .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
        .headers(remnawave_headers())
        .json(&json!({
            "uuid": uuid.to_string(),
            "status": "ACTIVE",
            "trafficLimitBytes": 0,
            "trafficLimitStrategy": "NO_RESET",
            "expireAt": new_expire.to_rfc3339(),
            "hwidDeviceLimit": 2,
            "tag": "TRIAL",
        }))
        .send()
        .await;

    HttpResponse::Ok().json(json!({"status": "ok"}))
}

// === Payment creation ===

#[derive(Deserialize)]
pub struct CreatePaymentRequest {
    tariff: String,
    duration: String,
    promo_code: Option<String>,
    save_payment_method: Option<bool>,
}

pub async fn web_create_payment(pool: web::Data<PgPool>, req: HttpRequest, data: web::Json<CreatePaymentRequest>) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    info!("[web_create_payment] telegram_id={}, tariff={}, duration={}", telegram_id, data.tariff, data.duration);

    // Temporary restriction: bypass tariffs sold only for 1 month
    let bs_month_only = std::env::var("BS_MONTH_ONLY")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true");
    if bs_month_only
        && (data.tariff == "bsbase" || data.tariff == "bsfamily")
        && data.duration != "1m"
    {
        return HttpResponse::BadRequest().body("Bypass tariffs are temporarily available only for 1 month");
    }

    // Get price
    let prices = get_price_map();
    let key = format!("{}_{}", data.tariff, data.duration);
    let mut price = match prices.get(&key) {
        Some(p) => *p,
        None => return HttpResponse::BadRequest().body("Invalid tariff/duration combination"),
    };

    // Apply promo discount
    if let Some(ref code) = data.promo_code {
        let promo = sqlx::query(
            "SELECT discount_percent FROM promo_codes WHERE code = $1 AND is_active = true"
        )
        .bind(code)
        .fetch_optional(pool.get_ref())
        .await;

        if let Ok(Some(row)) = promo {
            let discount: i32 = row.get("discount_percent");
            price = (price as f64 * (1.0 - discount as f64 / 100.0)).round() as i64;
        }
    }

    let tariff_name = match data.tariff.as_str() {
        "base" => "Базовый",
        "family" => "Семейный",
        "bsbase" => "Обход БС (Базовый)",
        "bsfamily" => "Обход БС (Семейный)",
        _ => "Подписка",
    };
    let duration_name = match data.duration.as_str() {
        "1m" => "1 месяц",
        "3m" => "3 месяца",
        "1y" => "1 год",
        _ => "",
    };

    // Create YooKassa payment
    let yookassa_shop_id = std::env::var("YOOKASSA_SHOP_ID").unwrap_or_default();
    let yookassa_secret = std::env::var("YOOKASSA_SECRET_KEY").unwrap_or_default();

    // Only save payment method if user has auto_renew enabled (otherwise SBP available)
    let save_method = sqlx::query_scalar::<_, bool>("SELECT auto_renew FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await
        .ok()
        .flatten()
        .unwrap_or(false);

    // Map duration code to Russian plan name (must match webhook's subscription_mapping)
    let plan_name = match data.duration.as_str() {
        "1m" => "1 месяц",
        "3m" => "3 месяца",
        "1y" => "1 год",
        _ => "1 месяц",
    };

    // Get username and email for receipt
    let username = sqlx::query_scalar::<_, Option<String>>("SELECT username FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await
        .ok()
        .flatten()
        .flatten()
        .unwrap_or_else(|| format!("{}", telegram_id));

    let user_email = sqlx::query_scalar::<_, String>("SELECT email FROM user_credentials WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await
        .ok()
        .flatten();

    // Email users (negative ID) show email, TG users show @username
    let description = if telegram_id < 0 {
        let email_str = user_email.unwrap_or_else(|| username.clone());
        format!("SvoiVPN {} {} ({}) [Сайт]", tariff_name, duration_name, email_str)
    } else {
        format!("SvoiVPN {} {} (@{}) [Сайт]", tariff_name, duration_name, username)
    };
    let receipt_email = std::env::var("RECEIPT_EMAIL").unwrap_or_else(|_| "receipt@svoi-connect.ru".to_string());

    let payment_body = json!({
        "amount": {
            "value": format!("{}.00", price),
            "currency": "RUB"
        },
        "confirmation": {
            "type": "redirect",
            "return_url": format!("https://svoiweb.ru/?payment_status=success")
        },
        "capture": true,
        "description": description,
        "save_payment_method": save_method,
        "receipt": {
            "customer": {
                "email": receipt_email
            },
            "items": [{
                "description": description,
                "quantity": "1.00",
                "amount": {
                    "value": format!("{}.00", price),
                    "currency": "RUB"
                },
                "vat_code": 1,
                "payment_subject": "service",
                "payment_mode": "full_payment"
            }]
        },
        "metadata": {
            "telegram_id": telegram_id.to_string(),
            "tariff": data.tariff,
            "plan": plan_name,
            "duration": data.duration,
            "promo_code": data.promo_code.clone().unwrap_or_default(),
        }
    });

    let resp = HTTP_CLIENT
        .post("https://api.yookassa.ru/v3/payments")
        .basic_auth(&yookassa_shop_id, Some(&yookassa_secret))
        .header("Idempotence-Key", uuid::Uuid::new_v4().to_string())
        .header("Content-Type", "application/json")
        .json(&payment_body)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(json) => {
                    let payment_url = json["confirmation"]["confirmation_url"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let payment_id = json["id"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    HttpResponse::Ok().json(json!({
                        "payment_url": payment_url,
                        "payment_id": payment_id,
                    }))
                }
                Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal server error"})) },
            }
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            error!("[web_create_payment] YooKassa error {}: {}", status, body);
            HttpResponse::InternalServerError().json(json!({"error": "internal server error"}))
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal server error"})) },
    }
}

fn get_price_map() -> HashMap<String, i64> {
    let mut m = HashMap::new();
    let pairs = [
        ("base_1m", "BASE_MONTH", 150),
        ("base_3m", "BASE_3_MONTH", 430),
        ("base_1y", "BASE_YEAR", 1500),
        ("family_1m", "FAMILY_MONTH", 250),
        ("family_3m", "FAMILY_3_MONTH", 700),
        ("family_1y", "FAMILY_YEAR", 2200),
        ("bsbase_1m", "BSBASE_MONTH", 450),
        ("bsbase_3m", "BSBASE_3_MONTH", 1250),
        ("bsbase_1y", "BSBASE_YEAR", 4500),
        ("bsfamily_1m", "BSFAMILY_MONTH", 750),
        ("bsfamily_3m", "BSFAMILY_3_MONTH", 2100),
        ("bsfamily_1y", "BSFAMILY_YEAR", 7500),
    ];
    for (key, env, default) in pairs {
        let val = std::env::var(env)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default);
        m.insert(key.to_string(), val);
    }
    m
}

// === Payment status ===

pub async fn web_payment_status(payment_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    // Verify auth
    if jwt::extract_telegram_id(&req).is_err() {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }

    let yookassa_shop_id = std::env::var("YOOKASSA_SHOP_ID").unwrap_or_default();
    let yookassa_secret = std::env::var("YOOKASSA_SECRET_KEY").unwrap_or_default();

    let resp = HTTP_CLIENT
        .get(&format!("https://api.yookassa.ru/v3/payments/{}", payment_id.into_inner()))
        .basic_auth(&yookassa_shop_id, Some(&yookassa_secret))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(json) => {
                    let status = json["status"].as_str().unwrap_or("unknown").to_string();
                    HttpResponse::Ok().json(json!({ "status": status }))
                }
                Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
            }
        }
        Ok(r) => HttpResponse::InternalServerError().json(json!({"error": "internal server error"})),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === Crypto payment ===

#[derive(Deserialize)]
pub struct CreateCryptoPaymentRequest {
    tariff: String,
    duration: String,
    currency: String,
    promo_code: Option<String>,
}

pub async fn web_create_crypto_payment(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    data: web::Json<CreateCryptoPaymentRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    info!("[web_create_crypto_payment] telegram_id={}, tariff={}, currency={}", telegram_id, data.tariff, data.currency);

    let bs_month_only = std::env::var("BS_MONTH_ONLY")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true");
    if bs_month_only
        && (data.tariff == "bsbase" || data.tariff == "bsfamily")
        && data.duration != "1m"
    {
        return HttpResponse::BadRequest().body("Bypass tariffs are temporarily available only for 1 month");
    }

    let prices = get_price_map();
    let key = format!("{}_{}", data.tariff, data.duration);
    let mut price_rub = match prices.get(&key) {
        Some(p) => *p,
        None => return HttpResponse::BadRequest().body("Invalid tariff/duration"),
    };

    if let Some(ref code) = data.promo_code {
        let promo = sqlx::query("SELECT discount_percent FROM promo_codes WHERE code = $1 AND is_active = true")
            .bind(code)
            .fetch_optional(pool.get_ref())
            .await;
        if let Ok(Some(row)) = promo {
            let discount: i32 = row.get("discount_percent");
            price_rub = (price_rub as f64 * (1.0 - discount as f64 / 100.0)).round() as i64;
        }
    }

    let crypto_bot_token = std::env::var("CRYPTO_BOT_TOKEN").unwrap_or_default();
    if crypto_bot_token.is_empty() {
        return HttpResponse::InternalServerError().body("Crypto payments not configured");
    }

    // Convert RUB to crypto via CoinMarketCap
    let cmc_key = std::env::var("CMC_API_KEY").unwrap_or_default();
    let crypto_amount = convert_rub_to_crypto(price_rub as f64, &data.currency, &cmc_key).await;
    let crypto_amount = match crypto_amount {
        Some(a) => a,
        None => return HttpResponse::InternalServerError().body("Failed to convert currency"),
    };

    // Create CryptoPay invoice
    let resp = HTTP_CLIENT
        .post("https://pay.crypt.bot/api/createInvoice")
        .header("Crypto-Pay-API-Token", &crypto_bot_token)
        .json(&json!({
            "currency_type": "crypto",
            "asset": data.currency,
            "amount": format!("{:.8}", crypto_amount),
            "description": format!("SvoiVPN {} {} [Сайт]", data.tariff, data.duration),
            "payload": format!("{}:{}:{}", telegram_id, data.tariff, data.duration),
        }))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(json) => {
                    if json["ok"].as_bool() == Some(true) {
                        let invoice_url = json["result"]["bot_invoice_url"].as_str().unwrap_or("").to_string();
                        let invoice_id = json["result"]["invoice_id"].as_i64().unwrap_or(0);
                        HttpResponse::Ok().json(json!({
                            "invoice_url": invoice_url,
                            "invoice_id": invoice_id.to_string(),
                        }))
                    } else {
                        HttpResponse::InternalServerError().body("CryptoPay error")
                    }
                }
                Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
            }
        }
        Ok(r) => HttpResponse::InternalServerError().json(json!({"error": "internal server error"})),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

async fn convert_rub_to_crypto(rub: f64, currency: &str, cmc_key: &str) -> Option<f64> {
    if cmc_key.is_empty() {
        return None;
    }

    // Get USD/RUB rate
    let resp = HTTP_CLIENT
        .get("https://pro-api.coinmarketcap.com/v1/tools/price-conversion")
        .header("X-CMC_PRO_API_KEY", cmc_key)
        .query(&[("amount", "1"), ("symbol", "USD"), ("convert", "RUB")])
        .send()
        .await
        .ok()?;

    let json = resp.json::<serde_json::Value>().await.ok()?;
    let usd_to_rub = json["data"]["quote"]["RUB"]["price"].as_f64()?;
    let usd_amount = rub / usd_to_rub;

    // Get crypto/USD rate
    let resp = HTTP_CLIENT
        .get("https://pro-api.coinmarketcap.com/v1/tools/price-conversion")
        .header("X-CMC_PRO_API_KEY", cmc_key)
        .query(&[("amount", &format!("{}", usd_amount)), ("symbol", &"USD".to_string()), ("convert", &currency.to_string())])
        .send()
        .await
        .ok()?;

    let json = resp.json::<serde_json::Value>().await.ok()?;
    json["data"]["quote"][currency]["price"].as_f64()
}

// === Promo validation ===

#[derive(Deserialize)]
pub struct WebValidatePromoRequest {
    code: String,
    tariff: String,
}

pub async fn web_validate_promo(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    data: web::Json<WebValidatePromoRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let promo = sqlx::query(
        "SELECT id, discount_percent, applicable_tariffs, max_uses, current_uses, is_active \
         FROM promo_codes WHERE code = $1"
    )
    .bind(&data.code)
    .fetch_optional(pool.get_ref())
    .await;

    let row = match promo {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::Ok().json(json!({"valid": false, "reason": "Промокод не найден"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let is_active: bool = row.get("is_active");
    if !is_active {
        return HttpResponse::Ok().json(json!({"valid": false, "reason": "Промокод деактивирован"}));
    }

    let max_uses: i32 = row.get("max_uses");
    let current_uses: i32 = row.get("current_uses");
    if current_uses >= max_uses {
        return HttpResponse::Ok().json(json!({"valid": false, "reason": "Промокод исчерпан"}));
    }

    let applicable: Vec<String> = row.get("applicable_tariffs");
    if !data.tariff.is_empty() && !applicable.contains(&data.tariff) {
        return HttpResponse::Ok().json(json!({"valid": false, "reason": "Промокод не применим к этому тарифу"}));
    }

    let promo_id: i32 = row.get("id");
    let already_used: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM promo_usages WHERE promo_code_id = $1 AND telegram_id = $2"
    )
    .bind(promo_id)
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    if already_used.is_some() {
        return HttpResponse::Ok().json(json!({"valid": false, "reason": "Вы уже использовали этот промокод"}));
    }

    let discount: i32 = row.get("discount_percent");
    HttpResponse::Ok().json(json!({"valid": true, "discount_percent": discount}))
}

// === Settings ===

#[derive(Deserialize)]
pub struct WebToggleAutoRenewRequest {
    auto_renew: bool,
    plan: Option<String>,
    duration: Option<String>,
}

pub async fn web_toggle_auto_renew(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    data: web::Json<WebToggleAutoRenewRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let result = if data.auto_renew {
        sqlx::query(
            "UPDATE users SET auto_renew = true, auto_renew_plan = COALESCE($1, auto_renew_plan), \
             auto_renew_duration = COALESCE($2, auto_renew_duration) WHERE telegram_id = $3"
        )
        .bind(&data.plan)
        .bind(&data.duration)
        .bind(telegram_id)
        .execute(pool.get_ref())
        .await
    } else {
        sqlx::query("UPDATE users SET auto_renew = false WHERE telegram_id = $1")
            .bind(telegram_id)
            .execute(pool.get_ref())
            .await
    };

    match result {
        Ok(_) => HttpResponse::Ok().json(json!({"status": "ok"})),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

#[derive(Deserialize)]
pub struct WebToggleProRequest {
    is_pro: bool,
}

pub async fn web_toggle_pro(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    data: web::Json<WebToggleProRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let user = sqlx::query("SELECT uuid, is_pro FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await;

    let row = match user {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "Пользователь не найден"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let uuid: uuid::Uuid = row.get("uuid");
    let pro_squad = "b6a4e86b-b769-4c86-a2d9-f31bbe645029";

    // Get current squads from Remnawave
    let get_resp = HTTP_CLIENT
        .get(&format!("{}/users/by-telegram-id/{}", *REMNAWAVE_API_BASE, telegram_id))
        .headers(remnawave_headers())
        .send()
        .await;

    let mut squad_list: Vec<String> = match get_resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(json) => json["response"][0]["activeInternalSquads"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|s| s["uuid"].as_str().map(|v| v.to_string())).collect())
                    .unwrap_or_default(),
                Err(_) => vec![],
            }
        }
        _ => vec![],
    };

    if data.is_pro {
        if !squad_list.contains(&pro_squad.to_string()) {
            squad_list.push(pro_squad.to_string());
        }
    } else {
        squad_list.retain(|s| s != pro_squad);
    }

    // Update Remnawave
    let _ = HTTP_CLIENT
        .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
        .headers(remnawave_headers())
        .json(&json!({
            "uuid": uuid.to_string(),
            "activeInternalSquads": squad_list,
        }))
        .send()
        .await;

    // Update DB
    let _ = sqlx::query("UPDATE users SET is_pro = $1 WHERE telegram_id = $2")
        .bind(data.is_pro)
        .bind(telegram_id)
        .execute(pool.get_ref())
        .await;

    HttpResponse::Ok().json(json!({"status": "ok"}))
}

pub async fn web_unbind_card(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let result = sqlx::query(
        "UPDATE users SET payment_method_id = NULL, auto_renew = false WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().json(json!({"status": "ok"})),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === Referral info ===

pub async fn web_referral_info(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let user = sqlx::query(
        "SELECT referrals, payed_refs FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await;

    match user {
        Ok(Some(row)) => {
            let referrals: Option<Vec<i64>> = row.get("referrals");
            let refs_count = referrals.as_ref().map(|r| r.len()).unwrap_or(0);
            let payed_refs: i64 = row.get("payed_refs");

            // Fetch referral details (username, is_active, plan)
            let mut referral_list = vec![];
            if let Some(ref ref_ids) = referrals {
                if !ref_ids.is_empty() {
                    let rows = sqlx::query(
                        "SELECT telegram_id, username, is_active, plan FROM users WHERE telegram_id = ANY($1)"
                    )
                    .bind(ref_ids)
                    .fetch_all(pool.get_ref())
                    .await
                    .unwrap_or_default();

                    for r in rows {
                        let is_active: i32 = r.get("is_active");
                        let plan: String = r.get("plan");
                        let has_paid = is_active > 0 && plan != "trial" && plan != "free";
                        referral_list.push(json!({
                            "telegram_id": r.get::<i64, _>("telegram_id"),
                            "username": r.get::<Option<String>, _>("username").unwrap_or_default(),
                            "is_active": is_active > 0,
                            "has_paid": has_paid,
                            "plan": plan,
                        }));
                    }
                }
            }

            HttpResponse::Ok().json(json!({
                "invite_link": format!("https://t.me/svoivless_bot?start={}", telegram_id),
                "web_invite_link": format!("https://svoiweb.ru/?ref={}", telegram_id),
                "referrals_count": refs_count,
                "payed_refs": payed_refs,
                "referrals": referral_list,
            }))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found"),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === AI Support endpoints ===

pub async fn web_support_history(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Pull the `id` and attachment columns so the client can hydrate
    // per-message thumbnails / download buttons without an N+1 round
    // trip. Attachment columns nullable — old text-only rows stay
    // unaffected.
    let rows = sqlx::query(
        "SELECT id, role, content, created_at, attachment_file_id, \
                attachment_filename, attachment_mime, attachment_size, \
                attachment_kind \
         FROM support_chats \
         WHERE telegram_id = $1 AND role != 'system' AND content NOT LIKE '[SYSTEM]%' \
         ORDER BY created_at ASC LIMIT 100"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await;

    // Check for active ticket
    let escalated = sqlx::query(
        "SELECT telegram_id FROM support_tickets WHERE telegram_id = $1 AND status = 'open' LIMIT 1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None)
    .is_some();

    match rows {
        Ok(rows) => {
            let messages: Vec<serde_json::Value> = rows.iter().map(|r| {
                let id: i64 = r.get("id");
                let role: String = r.get("role");
                let content: String = r.get("content");
                let created_at: chrono::DateTime<chrono::Utc> = r.get("created_at");
                let mut obj = json!({
                    "id": id,
                    "role": if role == "assistant" { "ai".to_string() } else { role },
                    "content": content,
                    "created_at": created_at.to_rfc3339(),
                });
                // Attach the attachment metadata block only when present
                // — keeps the JSON skinny for the common (text-only) row.
                let att_file_id: Option<String> = r.get("attachment_file_id");
                if let Some(file_id) = att_file_id.as_deref().filter(|s| !s.is_empty()) {
                    let _ = file_id; // file_id stays server-side; client uses /attachment/{id}
                    let filename: Option<String> = r.get("attachment_filename");
                    let mime: Option<String> = r.get("attachment_mime");
                    let size: Option<i64> = r.get("attachment_size");
                    let kind: Option<String> = r.get("attachment_kind");
                    obj.as_object_mut().unwrap().insert(
                        "attachment".to_string(),
                        json!({
                            "id": id,
                            "kind": kind.unwrap_or_else(|| "document".to_string()),
                            "filename": filename.unwrap_or_default(),
                            "mime": mime.unwrap_or_else(|| "application/octet-stream".to_string()),
                            "size": size.unwrap_or(0),
                        }),
                    );
                }
                obj
            }).collect();
            HttpResponse::Ok().json(json!({ "messages": messages, "escalated": escalated }))
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

pub async fn web_support_chat(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    body: web::Json<SupportChatRequest>,
    system_prompt: web::Data<Arc<String>>,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Input validation
    let user_message = body.message.trim();
    if user_message.is_empty() {
        return HttpResponse::BadRequest().body("Message cannot be empty");
    }

    // 1. Fetch user context from DB
    let user_row = sqlx::query(
        "SELECT plan, subscription_end, is_active, device_limit, is_pro FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await;

    let user_context = match user_row {
        Ok(Some(row)) => format!(
            "Контекст пользователя: тариф={}, подписка_до={}, активен={}, лимит_устройств={}, PRO={}",
            row.get::<String, _>("plan"),
            row.get::<chrono::DateTime<chrono::Utc>, _>("subscription_end").to_rfc3339(),
            row.get::<i32, _>("is_active"),
            row.get::<i64, _>("device_limit"),
            row.get::<bool, _>("is_pro"),
        ),
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "Пользователь не найден"})),
        Err(e) => {
            error!("[support_chat] DB error fetching user {}: {}", telegram_id, e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
    };

    // 2. Check for active ticket — skip AI if escalated
    let has_ticket = sqlx::query(
        "SELECT telegram_id FROM support_tickets WHERE telegram_id = $1 AND status = 'open' LIMIT 1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None)
    .is_some();

    if has_ticket {
        // Save user message but don't call AI
        let _ = sqlx::query(
            "INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'user', $2)"
        )
        .bind(telegram_id)
        .bind(user_message)
        .execute(pool.get_ref())
        .await;

        info!("[support_chat] User {} has open ticket, skipping AI", telegram_id);
        return HttpResponse::Ok().json(json!({"response": null, "escalated": true}));
    }

    // 3. Fetch last 40 messages from support_chats
    let history = sqlx::query(
        "SELECT role, content FROM support_chats WHERE telegram_id = $1 ORDER BY created_at DESC LIMIT 40"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // 4. Build messages array for ProxyAPI
    let mut messages: Vec<serde_json::Value> = Vec::new();
    messages.push(json!({"role": "system", "content": system_prompt.as_str()}));
    messages.push(json!({"role": "system", "content": "ВАЖНО: Пользователь пишет через сайт svoiweb.ru, а НЕ через Telegram. \
        Правила для сайта: \
        1) НИКОГДА не упоминайте Telegram-бота @svoivless_bot. Вместо этого говорите 'на сайте svoiweb.ru'. \
        2) Вместо 'в боте' говорите 'на сайте' или 'в личном кабинете'. \
        3) Оплата: 'на сайте svoiweb.ru в разделе Тарифы'. \
        4) Установка: 'на сайте svoiweb.ru в разделе Установка'. \
        5) Реферальная программа: 'на сайте svoiweb.ru в разделе Рефералы'. \
        6) Настройки: 'на сайте svoiweb.ru в разделе Настройки'. \
        7) Для связи с оператором: 'нажмите кнопку Оператор вверху чата'. \
        8) НЕ предлагайте написать в Telegram. Пользователь УЖЕ на сайте."}));
    messages.push(json!({"role": "system", "content": user_context}));

    // First message: disclose AI identity
    if history.is_empty() {
        messages.push(json!({
            "role": "assistant",
            "content": "Здравствуйте! Я — ИИ-ассистент службы поддержки SvoiVPN. Чем могу Вам помочь?"
        }));
    } else {
        // Add history in chronological order (reverse the DESC result)
        let hist_messages: Vec<serde_json::Value> = history.iter().rev().map(|row| {
            json!({
                "role": row.get::<String, _>("role"),
                "content": row.get::<String, _>("content")
            })
        }).collect();
        messages.extend(hist_messages);
    }

    messages.push(json!({"role": "user", "content": user_message}));

    // 4. Call ProxyAPI
    let api_result = HTTP_CLIENT
        .post(format!("{}/chat/completions", *PROXYAPI_BASE_URL))
        .header("Authorization", format!("Bearer {}", *PROXYAPI_KEY))
        .header("Content-Type", "application/json")
        .json(&json!({
            "model": "gemini/gemini-2.0-flash",
            "temperature": 0.3,
            "messages": messages
        }))
        .send()
        .await;

    let ai_response = match api_result {
        Err(e) => {
            warn!("[support_chat] ProxyAPI call failed: {}, retrying...", e);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match HTTP_CLIENT.post(format!("{}/chat/completions", *PROXYAPI_BASE_URL))
                .header("Authorization", format!("Bearer {}", *PROXYAPI_KEY))
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({"model":"gemini/gemini-2.0-flash","temperature":0.3,"messages":messages}))
                .send().await {
                Ok(resp) if resp.status().is_success() => resp.json::<serde_json::Value>().await
                    .map(|v| v["choices"][0]["message"]["content"].as_str().unwrap_or("Извините, не удалось получить ответ.").to_string())
                    .unwrap_or_else(|_| { return "Извините, не удалось получить ответ.".to_string() }),
                _ => { error!("[support_chat] ProxyAPI retry also failed"); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
            }
        }
        Ok(resp) if !resp.status().is_success() => {
            let status = resp.status();
            warn!("[support_chat] ProxyAPI error: {}, retrying...", status);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match HTTP_CLIENT.post(format!("{}/chat/completions", *PROXYAPI_BASE_URL))
                .header("Authorization", format!("Bearer {}", *PROXYAPI_KEY))
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({"model":"gemini/gemini-2.0-flash","temperature":0.3,"messages":messages}))
                .send().await {
                Ok(resp) if resp.status().is_success() => resp.json::<serde_json::Value>().await
                    .map(|v| v["choices"][0]["message"]["content"].as_str().unwrap_or("Извините, не удалось получить ответ.").to_string())
                    .unwrap_or_else(|_| { return "Извините, не удалось получить ответ.".to_string() }),
                _ => { error!("[support_chat] ProxyAPI retry also failed"); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
            }
        }
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(v) => v["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or("Извините, не удалось получить ответ.")
                .to_string(),
            Err(e) => {
                error!("[support_chat] Failed to parse ProxyAPI response: {}", e);
                return HttpResponse::ServiceUnavailable().body("service temporarily unavailable");
            }
        }
    };

    // 5. Persist user message and AI response
    let _ = sqlx::query(
        "INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'user', $2)"
    )
    .bind(telegram_id)
    .bind(user_message)
    .execute(pool.get_ref())
    .await;

    let _ = sqlx::query(
        "INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'assistant', $2)"
    )
    .bind(telegram_id)
    .bind(&ai_response)
    .execute(pool.get_ref())
    .await;

    HttpResponse::Ok().json(json!({"response": ai_response}))
}

// === Public support chat (no JWT required) ===

#[derive(Deserialize)]
pub struct PublicChatRequest {
    pub session_id: String,
    pub message: String,
}

fn session_to_telegram_id(session_id: &str) -> i64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    session_id.hash(&mut hasher);
    let hash = hasher.finish();
    -((hash % 9_000_000 + 3_000_000) as i64) // -3M to -12M range
}

pub async fn public_support_history(
    pool: web::Data<PgPool>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let session_id = match query.get("session_id") {
        Some(s) if !s.is_empty() => s,
        _ => return HttpResponse::BadRequest().json(json!({"error": "session_id required"})),
    };
    let telegram_id = session_to_telegram_id(session_id);

    let rows = sqlx::query(
        "SELECT role, content, created_at FROM support_chats WHERE telegram_id = $1 AND role != 'system' AND content NOT LIKE '[SYSTEM]%' ORDER BY created_at ASC LIMIT 100"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(rows) => {
            let messages: Vec<serde_json::Value> = rows.iter().map(|r| {
                let role: String = r.get("role");
                let content: String = r.get("content");
                let created_at: chrono::DateTime<chrono::Utc> = r.get("created_at");
                json!({
                    "role": if role == "assistant" { "ai".to_string() } else { role },
                    "content": content,
                    "created_at": created_at.to_rfc3339()
                })
            }).collect();
            HttpResponse::Ok().json(json!({ "messages": messages, "escalated": false }))
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) }
    }
}

pub async fn public_support_chat(
    pool: web::Data<PgPool>,
    body: web::Json<PublicChatRequest>,
    system_prompt: web::Data<Arc<String>>,
) -> HttpResponse {
    let session_id = body.session_id.trim();
    if session_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({"error": "session_id required"}));
    }
    let user_message = body.message.trim();
    if user_message.is_empty() {
        return HttpResponse::BadRequest().body("Message cannot be empty");
    }

    let telegram_id = session_to_telegram_id(session_id);
    let user_context = "Контекст: анонимный пользователь с сайта (не авторизован)".to_string();

    // Fetch history
    let history = sqlx::query(
        "SELECT role, content FROM support_chats WHERE telegram_id = $1 ORDER BY created_at DESC LIMIT 40"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Build messages for AI
    let mut messages: Vec<serde_json::Value> = Vec::new();
    messages.push(json!({"role": "system", "content": system_prompt.as_str()}));
    messages.push(json!({"role": "system", "content": "ВАЖНО: Пользователь пишет через сайт svoiweb.ru, НЕ авторизован. \
        Правила: \
        1) НИКОГДА не упоминайте Telegram-бота. Говорите 'на сайте svoiweb.ru'. \
        2) У анонимного пользователя нет подписки — НЕ вызывайте get_user_info. \
        3) Для покупки: 'зарегистрируйтесь на сайте svoiweb.ru и выберите тариф'. \
        4) Для связи с оператором: 'нажмите кнопку Оператор вверху чата'. \
        5) НЕ предлагайте написать в Telegram. Пользователь на сайте."}));
    messages.push(json!({"role": "system", "content": user_context}));

    if history.is_empty() {
        messages.push(json!({"role": "assistant", "content": "Здравствуйте! Я — ИИ-ассистент службы поддержки SvoiVPN. Чем могу Вам помочь?"}));
    } else {
        let hist_messages: Vec<serde_json::Value> = history.iter().rev().map(|row| {
            json!({"role": row.get::<String, _>("role"), "content": row.get::<String, _>("content")})
        }).collect();
        messages.extend(hist_messages);
    }
    messages.push(json!({"role": "user", "content": user_message}));

    // Call AI
    let api_result = HTTP_CLIENT
        .post(format!("{}/chat/completions", *PROXYAPI_BASE_URL))
        .header("Authorization", format!("Bearer {}", *PROXYAPI_KEY))
        .header("Content-Type", "application/json")
        .json(&json!({"model": "gemini/gemini-2.0-flash", "temperature": 0.3, "messages": messages}))
        .send()
        .await;

    let ai_response = match api_result {
        Err(e) => { error!("[public_support_chat] ProxyAPI failed: {}", e); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
        Ok(resp) if !resp.status().is_success() => { error!("[public_support_chat] ProxyAPI error: {}", resp.status()); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(v) => v["choices"][0]["message"]["content"].as_str().unwrap_or("Извините, не удалось получить ответ.").to_string(),
            Err(e) => { error!("[public_support_chat] Parse error: {}", e); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
        }
    };

    // Save messages
    let _ = sqlx::query("INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'user', $2)")
        .bind(telegram_id).bind(user_message).execute(pool.get_ref()).await;
    let _ = sqlx::query("INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'assistant', $2)")
        .bind(telegram_id).bind(&ai_response).execute(pool.get_ref()).await;

    HttpResponse::Ok().json(json!({"response": ai_response}))
}

pub async fn public_support_escalate(
    pool: web::Data<PgPool>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let session_id = body.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
    if session_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({"error": "session_id required"}));
    }
    let telegram_id = session_to_telegram_id(session_id);

    // Fetch recent chat history
    let history = sqlx::query(
        "SELECT role, content FROM support_chats WHERE telegram_id = $1 ORDER BY created_at DESC LIMIT 10"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let history_text = if history.is_empty() {
        "История пуста".to_string()
    } else {
        history.iter().rev().map(|row| {
            let role = row.get::<String, _>("role");
            let content = row.get::<String, _>("content");
            let truncated = if content.chars().count() > 200 {
                format!("{}...", content.chars().take(200).collect::<String>())
            } else { content };
            format!("[{}]: {}", role, truncated)
        }).collect::<Vec<_>>().join("\n")
    };

    let ticket_text = format!(
        "<b>Запрос на поддержку (сайт, без авторизации)</b>\n\n\
         <b>Session:</b> <code>{}</code>\n\
         <b>ID:</b> <code>{}</code>\n\n\
         <b>История чата:</b>\n{}",
        session_id, telegram_id, history_text
    );

    // Send to admins via Telegram
    let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", *SUPPORT_BOT_TOKEN);
    for admin_id in ADMIN_IDS.iter() {
        let _ = HTTP_CLIENT.post(&tg_url)
            .json(&json!({"chat_id": admin_id, "text": ticket_text, "parse_mode": "HTML"}))
            .send().await;
    }

    // Create ticket
    let _ = sqlx::query(
        "INSERT INTO support_tickets (telegram_id, username, reason, status, created_at) \
         VALUES ($1, $2, 'Эскалация с сайта (анон)', 'open', NOW()) \
         ON CONFLICT (telegram_id) DO UPDATE SET status = 'open', reason = 'Эскалация с сайта (анон)', created_at = NOW()"
    )
    .bind(telegram_id)
    .bind(session_id)
    .execute(pool.get_ref())
    .await;

    // Save a system message so the chat appears in admin list
    let _ = sqlx::query(
        "INSERT INTO support_chats (telegram_id, role, content, created_at) VALUES ($1, 'user', $2, NOW())"
    )
    .bind(telegram_id)
    .bind(format!("[Анонимный пользователь запросил оператора]\nSession: {}", session_id))
    .execute(pool.get_ref())
    .await;

    info!("[public_escalate] Escalated session {} (tg_id={})", session_id, telegram_id);
    HttpResponse::Ok().json(json!({"status": "escalated"}))
}

#[derive(Deserialize)]
pub struct PushSubscribeRequest {
    pub session_id: String,
    pub subscription: PushSubscriptionPayload,
    pub user_agent: Option<String>,
}

#[derive(Deserialize)]
pub struct PushSubscriptionPayload {
    pub endpoint: String,
    pub keys: PushKeys,
}

#[derive(Deserialize)]
pub struct PushKeys {
    pub p256dh: String,
    pub auth: String,
}

pub async fn public_push_subscribe(
    pool: web::Data<PgPool>,
    body: web::Json<PushSubscribeRequest>,
) -> HttpResponse {
    let session_id = body.session_id.trim();
    if session_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({"error": "session_id required"}));
    }
    let telegram_id = session_to_telegram_id(session_id);

    let res = sqlx::query(
        "INSERT INTO web_push_subscriptions (telegram_id, endpoint, p256dh, auth, user_agent) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (endpoint) DO UPDATE SET \
            telegram_id = EXCLUDED.telegram_id, \
            p256dh = EXCLUDED.p256dh, \
            auth = EXCLUDED.auth, \
            user_agent = EXCLUDED.user_agent",
    )
    .bind(telegram_id)
    .bind(&body.subscription.endpoint)
    .bind(&body.subscription.keys.p256dh)
    .bind(&body.subscription.keys.auth)
    .bind(body.user_agent.as_deref())
    .execute(pool.get_ref())
    .await;

    match res {
        Ok(_) => {
            info!(
                "[public_push_subscribe] saved sub for session_id={} tg={}",
                session_id, telegram_id
            );
            HttpResponse::Ok().json(json!({"status": "subscribed"}))
        }
        Err(e) => {
            error!("[public_push_subscribe] DB error: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "db error"}))
        }
    }
}

#[derive(Deserialize)]
pub struct AuthedPushSubscribeRequest {
    pub subscription: PushSubscriptionPayload,
    pub user_agent: Option<String>,
}

pub async fn push_subscribe(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    body: web::Json<AuthedPushSubscribeRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let res = sqlx::query(
        "INSERT INTO web_push_subscriptions (telegram_id, endpoint, p256dh, auth, user_agent) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (endpoint) DO UPDATE SET \
            telegram_id = EXCLUDED.telegram_id, \
            p256dh = EXCLUDED.p256dh, \
            auth = EXCLUDED.auth, \
            user_agent = EXCLUDED.user_agent",
    )
    .bind(telegram_id)
    .bind(&body.subscription.endpoint)
    .bind(&body.subscription.keys.p256dh)
    .bind(&body.subscription.keys.auth)
    .bind(body.user_agent.as_deref())
    .execute(pool.get_ref())
    .await;

    match res {
        Ok(_) => {
            info!("[push_subscribe] saved sub for tg={}", telegram_id);
            HttpResponse::Ok().json(json!({"status": "subscribed"}))
        }
        Err(e) => {
            error!("[push_subscribe] DB error: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "db error"}))
        }
    }
}

pub async fn web_support_escalate(
    pool: web::Data<PgPool>,
    req: HttpRequest,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // 1. Fetch user info for ticket
    let user_row = sqlx::query(
        "SELECT telegram_id, username, plan, subscription_end, is_active, device_limit, is_pro FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await;

    let user_row = match user_row {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "Пользователь не найден"})),
        Err(e) => {
            error!("[support_escalate] DB error fetching user {}: {}", telegram_id, e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
    };

    let username: String = user_row.try_get::<String, _>("username")
        .unwrap_or_else(|_| "не указан".to_string());
    let plan: String = user_row.try_get::<String, _>("plan")
        .unwrap_or_else(|_| "не указан".to_string());
    let subscription_end: String = user_row.try_get::<chrono::DateTime<chrono::Utc>, _>("subscription_end")
        .map(|dt| dt.format("%d.%m.%Y %H:%M").to_string())
        .unwrap_or_else(|_| "не указана".to_string());
    let is_active: bool = user_row.try_get::<i32, _>("is_active")
        .map(|v| v != 0)
        .unwrap_or(false);
    let device_limit: i64 = user_row.try_get::<i64, _>("device_limit")
        .unwrap_or(0);
    let is_pro: bool = user_row.try_get::<bool, _>("is_pro")
        .unwrap_or(false);

    // 2. Fetch recent chat history (last 10 messages for ticket context)
    let history = sqlx::query(
        "SELECT role, content, created_at FROM support_chats WHERE telegram_id = $1 ORDER BY created_at DESC LIMIT 10"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // 3. Format ticket text in HTML (Telegram parse_mode)
    let history_text = if history.is_empty() {
        "История чата пуста.".to_string()
    } else {
        history.iter().rev().map(|row| {
            let role = row.get::<String, _>("role");
            let content = row.get::<String, _>("content");
            let truncated = if content.chars().count() > 200 {
                let end: String = content.chars().take(200).collect();
                format!("{}...", end)
            } else {
                content
            };
            format!("[{}]: {}", role, truncated)
        })
        .collect::<Vec<_>>()
        .join("\n")
    };

    let mut ticket_text = format!(
        "<b>Запрос на поддержку</b>\n\n\
         <b>Пользователь:</b>\n\
         Telegram ID: <code>{}</code>\n\
         Username: {}\n\
         Тариф: {}\n\
         Подписка до: {}\n\
         Активен: {}\n\
         Устройств: {}\n\
         PRO: {}\n\n\
         <b>История чата (последние сообщения):</b>\n{}",
        telegram_id,
        username,
        plan,
        subscription_end,
        if is_active { "Да" } else { "Нет" },
        device_limit,
        if is_pro { "Да" } else { "Нет" },
        history_text,
    );

    // Truncate to 4000 chars max (Telegram limit is 4096)
    if ticket_text.len() > 4000 {
        // Find a valid UTF-8 boundary at or before 4000 bytes
        let mut end = 4000;
        while !ticket_text.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        ticket_text.truncate(end);
        ticket_text.push_str("...");
    }

    // 4. Send to each admin via Telegram Bot API
    let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", *SUPPORT_BOT_TOKEN);

    for admin_id in ADMIN_IDS.iter() {
        let result = HTTP_CLIENT.post(&tg_url)
            .json(&json!({
                "chat_id": admin_id,
                "text": ticket_text,
                "parse_mode": "HTML"
            }))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                info!("[support_escalate] Sent ticket to admin {}", admin_id);
            }
            Ok(resp) => {
                error!("[support_escalate] Failed to notify admin {}: HTTP {}", admin_id, resp.status());
            }
            Err(e) => {
                error!("[support_escalate] Failed to notify admin {}: {}", admin_id, e);
            }
        }
    }

    // Create ticket in support_tickets so AI stops responding
    let _ = sqlx::query(
        "INSERT INTO support_tickets (telegram_id, username, reason, status, created_at) \
         VALUES ($1, $2, 'Эскалация через сайт', 'open', NOW()) \
         ON CONFLICT (telegram_id) DO UPDATE SET status = 'open', reason = 'Эскалация через сайт', created_at = NOW()"
    )
    .bind(telegram_id)
    .bind(&username)
    .execute(pool.get_ref())
    .await;

    info!("[support_escalate] Created ticket for user {}", telegram_id);

    HttpResponse::Ok().json(json!({"status": "escalated"}))
}

pub async fn app_support_message(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    mut payload: Multipart,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut message = String::new();
    let mut log_bytes: Vec<u8> = Vec::new();
    let mut log_filename: Option<String> = None;
    const MAX_MSG: usize = 4_000;
    const MAX_LOG: usize = 5 * 1024 * 1024; // 5 MB

    while let Some(field_result) = payload.next().await {
        let mut field = match field_result {
            Ok(f) => f,
            Err(e) => {
                error!("[app_support_message] multipart error: {}", e);
                return HttpResponse::BadRequest()
                    .json(json!({"error": "Invalid multipart payload"}));
            }
        };

        // actix-multipart 0.6: field.name() returns &str directly, not Option<&str>.
        let name = field.name().to_string();
        match name.as_str() {
            "message" => {
                while let Some(chunk) = field.next().await {
                    match chunk {
                        Ok(data) => {
                            if message.len() + data.len() > MAX_MSG {
                                return HttpResponse::PayloadTooLarge()
                                    .json(json!({"error": "Message too long"}));
                            }
                            message.push_str(std::str::from_utf8(&data).unwrap_or(""));
                        }
                        Err(e) => {
                            error!("[app_support_message] read message error: {}", e);
                            return HttpResponse::BadRequest()
                                .json(json!({"error": "Bad message field"}));
                        }
                    }
                }
            }
            "logs" => {
                // actix-multipart 0.6: content_disposition() returns &ContentDisposition
                // (not Option<&_>) — clone, then ask for the filename.
                let content_disposition = field.content_disposition().clone();
                log_filename = content_disposition.get_filename().map(|s| s.to_string());
                while let Some(chunk) = field.next().await {
                    match chunk {
                        Ok(data) => {
                            if log_bytes.len() + data.len() > MAX_LOG {
                                return HttpResponse::PayloadTooLarge()
                                    .json(json!({"error": "Log file too large"}));
                            }
                            log_bytes.extend_from_slice(&data);
                        }
                        Err(e) => {
                            error!("[app_support_message] read logs error: {}", e);
                            return HttpResponse::BadRequest()
                                .json(json!({"error": "Bad logs field"}));
                        }
                    }
                }
            }
            _ => { /* ignore unknown fields */ }
        }
    }

    let message = message.trim();
    if message.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({"error": "Message is required"}));
    }

    // 1. Insert into support_chats
    let inserted = sqlx::query(
        "INSERT INTO support_chats (telegram_id, role, content, created_at) \
         VALUES ($1, 'user', $2, NOW()) RETURNING created_at"
    )
    .bind(telegram_id)
    .bind(message)
    .fetch_one(pool.get_ref())
    .await;

    let created_at: chrono::DateTime<chrono::Utc> = match inserted {
        Ok(row) => row.get("created_at"),
        Err(e) => {
            error!("[app_support_message] insert chat failed: {}", e);
            return HttpResponse::InternalServerError()
                .json(json!({"error": "internal server error"}));
        }
    };

    // 2. Upsert support_tickets to status='open'. Matches the schema
    // used by the existing /web/support/escalate handler: columns
    // (telegram_id, username, reason, status, created_at) with a
    // unique constraint on telegram_id.
    let _ = sqlx::query(
        "INSERT INTO support_tickets (telegram_id, username, reason, status, created_at) \
         VALUES ($1, NULL, 'Сообщение из приложения', 'open', NOW()) \
         ON CONFLICT (telegram_id) DO UPDATE SET status = 'open', \
         reason = 'Сообщение из приложения', created_at = NOW()"
    )
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    // 3. Forward to admin TG (fire-and-forget; failure doesn't fail the user request)
    let log_attach: Option<(String, Vec<u8>)> = if !log_bytes.is_empty() {
        Some((log_filename.unwrap_or_else(|| "logs.txt".to_string()), log_bytes))
    } else {
        None
    };
    let user_id_for_log = telegram_id;
    let message_for_log = message.to_string();
    actix_web::rt::spawn(async move {
        forward_app_message_to_admin(user_id_for_log, &message_for_log, log_attach).await;
    });

    HttpResponse::Ok().json(crate::models::AppSupportMessageResponse {
        stored: true,
        created_at,
        forwarded_to_admin: true,
        chat_id: None,
        attachment: None,
    })
}

async fn forward_app_message_to_admin(
    user_telegram_id: i64,
    message: &str,
    log_attach: Option<(String, Vec<u8>)>,
) {
    // Indirection: queries DB for the rich user-info envelope, falls back
    // to a slim "ID-only" ticket if the DB lookup blows up. We never want
    // the user's support message to disappear silently — that's worse
    // than a less-informative TG notification.
    forward_app_message_to_admin_inner(user_telegram_id, message, log_attach).await;
}

/// Pool-free helper: lazily acquires a fresh PgPool from DATABASE_URL on
/// each call. We avoid threading the existing actix-web Data<PgPool>
/// through the spawn boundary because the original handler already
/// detaches the forward into actix::rt::spawn, and reaching back across
/// the spawn would force the whole call chain to hold a 'static pool
/// reference. A short-lived connection here is fine — this only fires
/// once per user-sent support message.
async fn forward_app_message_to_admin_inner(
    user_telegram_id: i64,
    message: &str,
    log_attach: Option<(String, Vec<u8>)>,
) {
    let bot_token = match std::env::var("SUPPORT_BOT_TOKEN") {
        Ok(v) => v,
        Err(_) => { error!("SUPPORT_BOT_TOKEN missing — skipping TG forward"); return; }
    };
    let admin_id = match std::env::var("ADMIN_IDS")
        .ok()
        .and_then(|s| s.split(',').next().map(|x| x.trim().to_string())) {
        Some(id) => id,
        None => { error!("ADMIN_IDS missing — skipping TG forward"); return; }
    };

    let user_info = fetch_user_info_for_ticket(user_telegram_id).await;

    // Header explicitly tagged "📱 ТИКЕТ ИЗ ПРИЛОЖЕНИЯ" so the admin can
    // tell at a glance that this came from the SvoiVPN mobile client and
    // not a Telegram-bot conversation. The body block mirrors the
    // bot's `create_admin_ticket()` layout (Email/Тариф/Статус/...)
    // exactly so the admin's eye doesn't have to switch between two
    // formats for ticket triage.
    //
    // The `ID: <code>{id}</code>` line MUST stay verbatim — the bot's
    // `handle_admin_reply` (tech-support-bot/main.py:~1559) uses that
    // regex to route admin replies back to this user.
    let text = build_app_ticket_text(user_telegram_id, message, &user_info);

    // Inline buttons that the existing bot already wires up: "open ticket"
    // and "close ticket" callbacks are handled in main.py's
    // callback_query_handler. We just send the same callback_data.
    let reply_markup = serde_json::json!({
        "inline_keyboard": [[
            { "text": "📖 Открыть переписку", "callback_data": format!("open_ticket_{}", user_telegram_id) },
            { "text": "✅ Закрыть тикет", "callback_data": format!("close_ticket_{}", user_telegram_id) },
        ]]
    }).to_string();

    let client = reqwest::Client::new();
    let send_msg_url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let resp = client.post(&send_msg_url)
        .form(&[
            ("chat_id", admin_id.as_str()),
            ("text", text.as_str()),
            ("parse_mode", "HTML"),
            ("reply_markup", reply_markup.as_str()),
        ])
        .send().await;
    if let Err(e) = resp {
        error!("[forward_app_message_to_admin] sendMessage failed: {}", e);
    }

    if let Some((filename, bytes)) = log_attach {
        let doc_url = format!("https://api.telegram.org/bot{}/sendDocument", bot_token);
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.clone())
            .mime_str("application/octet-stream")
            .unwrap();
        let form = reqwest::multipart::Form::new()
            .text("chat_id", admin_id)
            .text("caption", format!("📜 Лог приложения от {}", user_telegram_id))
            .part("document", part);
        if let Err(e) = client.post(&doc_url).multipart(form).send().await {
            error!("[forward_app_message_to_admin] sendDocument failed: {}", e);
        }
    }
}

/// Rich user-info envelope for the app-ticket Telegram notification.
/// All fields default to "—" so a missing row never breaks the message.
#[derive(Default)]
struct AppTicketUserInfo {
    username: Option<String>,
    email: Option<String>,
    plan_display: String,
    status: String,
    is_pro: bool,
    sub_end_msk: String,
    auto_renew: bool,
    card_last4: Option<String>,
    device_limit: i64,
    messages_in_conv: i64,
}

async fn fetch_user_info_for_ticket(telegram_id: i64) -> AppTicketUserInfo {
    let mut info = AppTicketUserInfo::default();
    info.plan_display = "—".to_string();
    info.status = "—".to_string();
    info.sub_end_msk = "—".to_string();
    info.device_limit = 0;

    let db_url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => { error!("DATABASE_URL missing — sending slim ticket"); return info; }
    };

    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&db_url)
        .await
    {
        Ok(p) => p,
        Err(e) => { error!("[ticket] pool connect failed: {}", e); return info; }
    };

    // users table: plan, status, expiry, auto-renew, card, device limit, username.
    if let Ok(Some(row)) = sqlx::query(
        "SELECT username, plan, is_active, is_pro, subscription_end, auto_renew, card_last4, device_limit \
         FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(&pool)
    .await
    {
        info.username = row.try_get::<Option<String>, _>("username").ok().flatten();
        let plan_raw: String = row.try_get("plan").unwrap_or_default();
        info.plan_display = plan_display_name(&plan_raw);
        let is_active: i32 = row.try_get("is_active").unwrap_or(0);
        info.status = if is_active == 1 { "Активна".to_string() } else { "Неактивна".to_string() };
        info.is_pro = row.try_get("is_pro").unwrap_or(false);
        if let Ok(sub_end) = row.try_get::<chrono::DateTime<chrono::Utc>, _>("subscription_end") {
            // +3h to render Moscow time, matches bot's format.
            let msk = sub_end + chrono::Duration::hours(3);
            info.sub_end_msk = msk.format("%d.%m.%Y, %H:%M МСК").to_string();
        }
        info.auto_renew = row.try_get("auto_renew").unwrap_or(false);
        info.card_last4 = row.try_get::<Option<String>, _>("card_last4").ok().flatten();
        info.device_limit = row.try_get("device_limit").unwrap_or(0);
    }

    // Email comes from a separate table because telegram-only users have
    // no row in user_credentials.
    if let Ok(Some(email)) = sqlx::query_scalar::<_, String>(
        "SELECT email FROM user_credentials WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(&pool)
    .await
    {
        info.email = Some(email);
    }

    // Count of user-side messages in the support_chats history — gives
    // the admin a sense of how chatty the user has been before
    // committing to "open ticket".
    if let Ok(count) = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM support_chats WHERE telegram_id = $1 AND role = 'user'"
    )
    .bind(telegram_id)
    .fetch_one(&pool)
    .await
    {
        info.messages_in_conv = count;
    }

    info
}

fn plan_display_name(plan: &str) -> String {
    match plan {
        "base" => "Base",
        "bsbase" => "BS Base",
        "family" => "Family",
        "bsfamily" => "BS Family",
        "trial" => "Trial",
        "free" => "Free",
        "" => "—",
        other => return other.to_string(),
    }.to_string()
}

fn build_app_ticket_text(
    telegram_id: i64,
    message: &str,
    info: &AppTicketUserInfo,
) -> String {
    let username_line = match info.username.as_deref() {
        Some(u) if !u.is_empty() => format!("<b>Пользователь:</b> @{}", html_escape_local(u)),
        _ => format!("<b>Пользователь:</b> —"),
    };
    let email_line = format!(
        "<b>Email:</b> {}",
        info.email.as_deref().map(html_escape_local).unwrap_or_else(|| "—".to_string()),
    );
    let card_text = info.card_last4.as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| format!("•••• {}", s))
        .unwrap_or_else(|| "Нет".to_string());

    format!(
        "📱 <b>ТИКЕТ ИЗ ПРИЛОЖЕНИЯ</b>\n\
         ━━━━━━━━━━━━━━━━━━━━\n\
         {username_line}\n\
         <b>ID:</b> <code>{tg_id}</code>\n\
         {email_line}\n\
         <b>Тариф:</b> {plan}\n\
         <b>Статус:</b> {status}\n\
         <b>PRO:</b> {pro}\n\
         <b>Окончание:</b> {sub_end}\n\
         <b>Автопродление:</b> {auto_renew}\n\
         <b>Карта:</b> {card}\n\
         <b>Устройств:</b> {devices}\n\
         <b>Сообщений в диалоге:</b> {msg_count}\n\
         ━━━━━━━━━━━━━━━━━━━━\n\
         <b>Причина:</b> Сообщение из приложения\n\n\
         {body}",
        username_line = username_line,
        tg_id = telegram_id,
        email_line = email_line,
        plan = info.plan_display,
        status = info.status,
        pro = if info.is_pro { "Да" } else { "Нет" },
        sub_end = info.sub_end_msk,
        auto_renew = if info.auto_renew { "Да" } else { "Нет" },
        card = card_text,
        devices = info.device_limit,
        msg_count = info.messages_in_conv,
        body = html_escape_local(message),
    )
}

fn html_escape_local(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

// === App support: attachment upload + proxy-fetch ===

/// Telegram Bot API limits we mirror on the client side. 50 MiB matches
/// sendDocument's cap; sendPhoto's 10 MiB is enforced by retrying as a
/// document if the incoming MIME is an image but the file exceeds the
/// photo limit.
const ATTACHMENT_MAX_BYTES: usize = 50 * 1024 * 1024;
const PHOTO_MAX_BYTES: usize = 10 * 1024 * 1024;
const ATTACHMENT_FILENAME_MAX: usize = 256;

/// POST /api/app/support/attachment — multipart form with:
///   - `message` (optional text, ≤4000 chars): user-typed caption to
///     accompany the file in both DB and admin TG. Stored as the
///     support_chats.content alongside the attachment metadata.
///   - `attachment` (required file, ≤50 MiB): photo / video / arbitrary
///     binary. Forwarded to the admin TG via sendPhoto / sendVideo /
///     sendDocument depending on MIME, then the file_id returned by
///     Telegram is persisted in support_chats so the user can re-fetch
///     it later through GET /api/app/support/attachment/{id}.
///
/// Auth: same JWT extraction as app_support_message — owner-only.
pub async fn app_support_attachment_upload(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    mut payload: Multipart,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut caption = String::new();
    let mut file_bytes: Vec<u8> = Vec::new();
    let mut filename: Option<String> = None;
    let mut declared_mime: Option<String> = None;
    const MAX_CAPTION: usize = 4_000;

    while let Some(field_result) = payload.next().await {
        let mut field = match field_result {
            Ok(f) => f,
            Err(e) => {
                error!("[app_support_attachment_upload] multipart error: {}", e);
                return HttpResponse::BadRequest()
                    .json(json!({"error": "Invalid multipart payload"}));
            }
        };
        let name = field.name().to_string();
        match name.as_str() {
            "message" => {
                while let Some(chunk) = field.next().await {
                    match chunk {
                        Ok(data) => {
                            if caption.len() + data.len() > MAX_CAPTION {
                                return HttpResponse::PayloadTooLarge()
                                    .json(json!({"error": "Message too long"}));
                            }
                            caption.push_str(std::str::from_utf8(&data).unwrap_or(""));
                        }
                        Err(e) => {
                            error!("[app_support_attachment_upload] read message: {}", e);
                            return HttpResponse::BadRequest()
                                .json(json!({"error": "Bad message field"}));
                        }
                    }
                }
            }
            "attachment" => {
                let cd = field.content_disposition().clone();
                filename = cd.get_filename().map(|s| s.to_string());
                declared_mime = field.content_type().map(|m| m.to_string());
                while let Some(chunk) = field.next().await {
                    match chunk {
                        Ok(data) => {
                            if file_bytes.len() + data.len() > ATTACHMENT_MAX_BYTES {
                                return HttpResponse::PayloadTooLarge()
                                    .json(json!({"error": "Attachment exceeds 50 MiB limit"}));
                            }
                            file_bytes.extend_from_slice(&data);
                        }
                        Err(e) => {
                            error!("[app_support_attachment_upload] read attachment: {}", e);
                            return HttpResponse::BadRequest()
                                .json(json!({"error": "Bad attachment field"}));
                        }
                    }
                }
            }
            _ => { /* ignore unknown fields */ }
        }
    }

    if file_bytes.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({"error": "Attachment file is required"}));
    }

    // Pick a sane filename. Some clients omit Content-Disposition's
    // filename (Android Photo Picker URIs in particular), so synthesize
    // one from the MIME so the admin downloads a file with a sensible
    // extension instead of "blob".
    let mut fname = filename.unwrap_or_default();
    if fname.is_empty() {
        fname = synthesize_filename(declared_mime.as_deref());
    }
    if fname.len() > ATTACHMENT_FILENAME_MAX {
        // Pathologically long filenames break TG's caption length budget
        // when echoed back in error messages — clamp to a reasonable
        // length while keeping the extension intact.
        let ext_dot = fname.rfind('.').filter(|i| fname.len() - i <= 8);
        if let Some(i) = ext_dot {
            let ext = fname[i..].to_string();
            fname.truncate(ATTACHMENT_FILENAME_MAX - ext.len());
            fname.push_str(&ext);
        } else {
            fname.truncate(ATTACHMENT_FILENAME_MAX);
        }
    }
    let mime = declared_mime.unwrap_or_else(|| guess_mime_from_filename(&fname));
    let size = file_bytes.len() as i64;
    let caption = caption.trim().to_string();

    // Decide TG send method by MIME family. Force sendDocument for
    // oversized photos so we don't get a TG 400 back. Animated GIFs go
    // as documents (sendAnimation requires a separate code path and we
    // don't want to add it for v1).
    let kind = classify_attachment(&mime, file_bytes.len());

    // Forward to admin TG and capture the file_id. We refuse to insert
    // the chat row when TG forward fails — otherwise the user would see
    // their own bubble with a working "download" button, but the admin
    // wouldn't have received anything, which is the worst possible
    // mismatch.
    let user_info = fetch_user_info_for_ticket(telegram_id).await;
    let admin_caption = build_attachment_caption(telegram_id, &caption, &user_info);
    let tg_result = forward_attachment_to_admin(
        kind,
        &fname,
        &mime,
        file_bytes.clone(),
        &admin_caption,
        telegram_id,
    ).await;

    let (tg_file_id, kind_str) = match tg_result {
        Ok(v) => v,
        Err(e) => {
            error!("[app_support_attachment_upload] TG forward failed: {}", e);
            return HttpResponse::BadGateway()
                .json(json!({"error": format!("Telegram forward failed: {}", e)}));
        }
    };

    // Store row with attachment metadata. content carries the optional
    // user caption (empty string when none provided — keeps the NOT NULL
    // constraint on `content` happy).
    let inserted = sqlx::query(
        "INSERT INTO support_chats \
         (telegram_id, role, content, attachment_file_id, attachment_filename, \
          attachment_mime, attachment_size, attachment_kind, created_at) \
         VALUES ($1, 'user', $2, $3, $4, $5, $6, $7, NOW()) \
         RETURNING id, created_at"
    )
    .bind(telegram_id)
    .bind(&caption)
    .bind(&tg_file_id)
    .bind(&fname)
    .bind(&mime)
    .bind(size)
    .bind(kind_str)
    .fetch_one(pool.get_ref())
    .await;

    let (chat_id, created_at): (i64, chrono::DateTime<chrono::Utc>) = match inserted {
        Ok(row) => (row.get("id"), row.get("created_at")),
        Err(e) => {
            error!("[app_support_attachment_upload] insert failed: {}", e);
            return HttpResponse::InternalServerError()
                .json(json!({"error": "internal server error"}));
        }
    };

    // Open the ticket so admin replies route back. Same upsert as
    // app_support_message.
    let _ = sqlx::query(
        "INSERT INTO support_tickets (telegram_id, username, reason, status, created_at) \
         VALUES ($1, NULL, 'Файл из приложения', 'open', NOW()) \
         ON CONFLICT (telegram_id) DO UPDATE SET status = 'open', \
         reason = 'Файл из приложения', created_at = NOW()"
    )
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    HttpResponse::Ok().json(crate::models::AppSupportMessageResponse {
        stored: true,
        created_at,
        forwarded_to_admin: true,
        chat_id: Some(chat_id),
        attachment: Some(crate::models::SupportAttachmentMeta {
            id: chat_id,
            kind: kind_str.to_string(),
            filename: fname,
            mime,
            size,
        }),
    })
}

/// GET /api/app/support/attachment/{id} — streams the file bytes the
/// owner originally uploaded, by asking Telegram for them and pushing
/// the response through.
///
/// We don't expose the underlying `https://api.telegram.org/file/bot…`
/// URL to the client because it contains the bot token. Proxying also
/// gives us a chokepoint for auth: only the row's owner can fetch.
pub async fn app_support_attachment_get(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> HttpResponse {
    let owner = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let chat_id = path.into_inner();

    // Fetch row + verify ownership in one shot. Returning 404 (not 403)
    // for cross-user access keeps file_id existence indistinguishable.
    let row = sqlx::query(
        "SELECT telegram_id, attachment_file_id, attachment_filename, \
                attachment_mime, attachment_kind \
         FROM support_chats WHERE id = $1"
    )
    .bind(chat_id)
    .fetch_optional(pool.get_ref())
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().finish(),
        Err(e) => {
            error!("[app_support_attachment_get] query failed: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let row_owner: i64 = row.get("telegram_id");
    if row_owner != owner {
        return HttpResponse::NotFound().finish();
    }
    let file_id: Option<String> = row.get("attachment_file_id");
    let file_id = match file_id {
        Some(s) if !s.is_empty() => s,
        _ => return HttpResponse::NotFound().finish(),
    };
    let mime: Option<String> = row.get("attachment_mime");
    let filename: Option<String> = row.get("attachment_filename");

    let bot_token = match std::env::var("SUPPORT_BOT_TOKEN") {
        Ok(v) => v,
        Err(_) => {
            error!("[app_support_attachment_get] SUPPORT_BOT_TOKEN missing");
            return HttpResponse::InternalServerError().finish();
        }
    };

    // 1) getFile — small JSON call to convert file_id → file_path.
    let client = reqwest::Client::new();
    let get_file_url = format!("https://api.telegram.org/bot{}/getFile", bot_token);
    let gf = client.post(&get_file_url)
        .form(&[("file_id", file_id.as_str())])
        .send().await;
    let gf_text = match gf {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(e) => {
                error!("[app_support_attachment_get] getFile read body: {}", e);
                return HttpResponse::BadGateway().finish();
            }
        },
        Err(e) => {
            error!("[app_support_attachment_get] getFile: {}", e);
            return HttpResponse::BadGateway().finish();
        }
    };
    let file_path = match serde_json::from_str::<serde_json::Value>(&gf_text)
        .ok()
        .and_then(|v| v.get("result").and_then(|r| r.get("file_path"))
                       .and_then(|p| p.as_str()).map(|s| s.to_string()))
    {
        Some(p) => p,
        None => {
            error!("[app_support_attachment_get] getFile bad response: {}", gf_text);
            return HttpResponse::BadGateway().finish();
        }
    };

    // 2) Fetch the bytes from TG's file CDN.
    let file_url = format!("https://api.telegram.org/file/bot{}/{}", bot_token, file_path);
    let resp = client.get(&file_url).send().await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            error!("[app_support_attachment_get] file fetch: {}", e);
            return HttpResponse::BadGateway().finish();
        }
    };
    let status = resp.status();
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!("[app_support_attachment_get] read file: {}", e);
            return HttpResponse::BadGateway().finish();
        }
    };
    if !status.is_success() {
        return HttpResponse::BadGateway().finish();
    }

    let ct = mime.unwrap_or_else(|| "application/octet-stream".to_string());
    let cd = filename
        .filter(|s| !s.is_empty())
        .map(|f| format!("inline; filename=\"{}\"", f.replace('"', "")));

    let mut builder = HttpResponse::Ok();
    builder.content_type(ct);
    if let Some(cd) = cd {
        builder.append_header(("Content-Disposition", cd));
    }
    // Cache-Control: private + short max-age. Files live forever on
    // TG but the proxy URL is per-user (auth-gated), so caching in
    // the OS http cache is fine. App-side Coil also caches.
    builder.append_header(("Cache-Control", "private, max-age=3600"));
    builder.body(bytes)
}

// ── helpers ────────────────────────────────────────────────────────

/// "photo" / "video" / "document" — drives which Telegram send method
/// we call. Photos > PHOTO_MAX_BYTES go as document so we don't trip
/// TG's 10 MiB photo limit and lose the upload.
fn classify_attachment(mime: &str, size: usize) -> &'static str {
    if mime.starts_with("image/") && mime != "image/gif" && size <= PHOTO_MAX_BYTES {
        "photo"
    } else if mime.starts_with("video/") {
        "video"
    } else {
        "document"
    }
}

fn synthesize_filename(mime: Option<&str>) -> String {
    let ext = match mime {
        Some("image/jpeg") | Some("image/jpg") => "jpg",
        Some("image/png") => "png",
        Some("image/webp") => "webp",
        Some("image/gif") => "gif",
        Some("image/heic") => "heic",
        Some("video/mp4") => "mp4",
        Some("video/quicktime") => "mov",
        Some("video/x-matroska") => "mkv",
        Some("application/pdf") => "pdf",
        Some("application/zip") => "zip",
        Some("text/plain") => "txt",
        _ => "bin",
    };
    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    format!("attachment-{}.{}", ts, ext)
}

fn guess_mime_from_filename(name: &str) -> String {
    let lower = name.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "heic" => "image/heic",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }.to_string()
}

/// Variant of build_app_ticket_text optimised for attachment captions
/// (Telegram caption limit is 1024 chars, vs 4096 for plain text).
/// Drops the bottom message body so the limit applies only to the rich
/// user-info envelope; the attached photo / file is the payload.
fn build_attachment_caption(
    telegram_id: i64,
    user_caption: &str,
    info: &AppTicketUserInfo,
) -> String {
    let username_line = match info.username.as_deref() {
        Some(u) if !u.is_empty() => format!("<b>Пользователь:</b> @{}", html_escape_local(u)),
        _ => "<b>Пользователь:</b> —".to_string(),
    };
    let email_line = format!(
        "<b>Email:</b> {}",
        info.email.as_deref().map(html_escape_local).unwrap_or_else(|| "—".to_string()),
    );
    let caption_block = if user_caption.is_empty() {
        String::new()
    } else {
        format!("\n📝 {}", html_escape_local(user_caption))
    };
    let body = format!(
        "📎 <b>ФАЙЛ ИЗ ПРИЛОЖЕНИЯ</b>\n\
         ━━━━━━━━━━━━━━━━━━━━\n\
         {username_line}\n\
         <b>ID:</b> <code>{tg_id}</code>\n\
         {email_line}\n\
         <b>Тариф:</b> {plan}\n\
         <b>Статус:</b> {status}\n\
         <b>Окончание:</b> {sub_end}{caption}",
        username_line = username_line,
        tg_id = telegram_id,
        email_line = email_line,
        plan = info.plan_display,
        status = info.status,
        sub_end = info.sub_end_msk,
        caption = caption_block,
    );
    // Cap to TG's 1024-char caption limit. Chops at a char boundary.
    let mut out = body;
    if out.chars().count() > 1024 {
        out = out.chars().take(1020).collect::<String>() + "…";
    }
    out
}

/// Fires the file at the admin TG via the appropriate send method, then
/// extracts the bot file_id we need to persist. Returns (file_id, kind_str).
async fn forward_attachment_to_admin(
    kind: &'static str,
    filename: &str,
    mime: &str,
    bytes: Vec<u8>,
    caption: &str,
    telegram_id: i64,
) -> Result<(String, &'static str), String> {
    let bot_token = std::env::var("SUPPORT_BOT_TOKEN")
        .map_err(|_| "SUPPORT_BOT_TOKEN missing".to_string())?;
    let admin_id = std::env::var("ADMIN_IDS")
        .ok()
        .and_then(|s| s.split(',').next().map(|x| x.trim().to_string()))
        .ok_or_else(|| "ADMIN_IDS missing".to_string())?;

    let (endpoint, field_name) = match kind {
        "photo" => ("sendPhoto", "photo"),
        "video" => ("sendVideo", "video"),
        _       => ("sendDocument", "document"),
    };
    let url = format!("https://api.telegram.org/bot{}/{}", bot_token, endpoint);

    let reply_markup = serde_json::json!({
        "inline_keyboard": [[
            { "text": "📖 Открыть переписку", "callback_data": format!("open_ticket_{}", telegram_id) },
            { "text": "✅ Закрыть тикет",     "callback_data": format!("close_ticket_{}", telegram_id) },
        ]]
    }).to_string();

    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(filename.to_string())
        .mime_str(mime)
        .map_err(|e| format!("bad mime: {}", e))?;

    let form = reqwest::multipart::Form::new()
        .text("chat_id", admin_id)
        .text("caption", caption.to_string())
        .text("parse_mode", "HTML")
        .text("reply_markup", reply_markup)
        .part(field_name, part);

    let client = reqwest::Client::new();
    let resp = client.post(&url).multipart(form).send().await
        .map_err(|e| format!("network: {}", e))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| format!("read body: {}", e))?;
    if !status.is_success() {
        return Err(format!("TG {} returned {}: {}", endpoint, status, body));
    }
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("bad json: {}", e))?;
    if !v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
        return Err(format!("TG !ok: {}", body));
    }
    // sendPhoto returns result.photo: [PhotoSize, …]; take the largest.
    // sendDocument returns result.document.file_id.
    // sendVideo returns result.video.file_id.
    let result = v.get("result").ok_or_else(|| "no .result".to_string())?;
    let file_id = match kind {
        "photo" => {
            let arr = result.get("photo").and_then(|x| x.as_array())
                .ok_or_else(|| "no .photo array".to_string())?;
            arr.last()
                .and_then(|x| x.get("file_id"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| "no file_id in photo[]".to_string())?
        }
        "video" => result.get("video")
            .and_then(|x| x.get("file_id"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "no .video.file_id".to_string())?,
        _ => result.get("document")
            .and_then(|x| x.get("file_id"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "no .document.file_id".to_string())?,
    };
    Ok((file_id, kind))
}

// === Push: device-token registration ===

#[derive(Deserialize)]
pub struct RegisterDeviceRequest {
    /// FCM registration token from the Android client.
    pub token: String,
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default)]
    pub app_version: Option<String>,
    /// Per-category opt-ins. Absent → keep existing / default true.
    #[serde(default)]
    pub notify_news: Option<bool>,
    #[serde(default)]
    pub notify_support: Option<bool>,
}

fn default_platform() -> String {
    "android".to_string()
}

/// POST /api/app/register-device — JWT-gated. Upserts the caller's FCM
/// token. ON CONFLICT(token) re-points the row at the current user
/// (handles "logged out, logged in as someone else on same device") and
/// refreshes opt-ins / app_version / updated_at.
///
/// Guests never reach this: the Android side only calls it once a JWT
/// exists, and the endpoint hard-requires a valid token anyway, so the
/// "no push for anonymous users" rule is enforced server-side too.
pub async fn app_register_device(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    body: web::Json<RegisterDeviceRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let token = body.token.trim();
    if token.is_empty() {
        return HttpResponse::BadRequest().json(json!({"error": "token required"}));
    }
    let platform = if body.platform == "ios" { "ios" } else { "android" };
    let notify_news = body.notify_news.unwrap_or(true);
    let notify_support = body.notify_support.unwrap_or(true);

    let res = sqlx::query(
        "INSERT INTO device_tokens \
           (telegram_id, token, platform, notify_news, notify_support, app_version, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) \
         ON CONFLICT (token) DO UPDATE SET \
           telegram_id = EXCLUDED.telegram_id, \
           platform = EXCLUDED.platform, \
           notify_news = EXCLUDED.notify_news, \
           notify_support = EXCLUDED.notify_support, \
           app_version = EXCLUDED.app_version, \
           updated_at = NOW()"
    )
    .bind(telegram_id)
    .bind(token)
    .bind(platform)
    .bind(notify_news)
    .bind(notify_support)
    .bind(&body.app_version)
    .execute(pool.get_ref())
    .await;

    match res {
        Ok(_) => HttpResponse::Ok().json(json!({"status": "ok"})),
        Err(e) => {
            error!("[register_device] upsert failed for {}: {}", telegram_id, e);
            HttpResponse::InternalServerError().json(json!({"error": "internal server error"}))
        }
    }
}

// === Internal support endpoints (no JWT - called by bot from Docker network) ===

pub async fn internal_support_chat(
    pool: web::Data<PgPool>,
    body: web::Json<InternalSupportChatRequest>,
    system_prompt: web::Data<Arc<String>>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let telegram_id = body.telegram_id;

    // Input validation
    let user_message = body.message.trim();
    if user_message.is_empty() {
        return HttpResponse::BadRequest().body("Message cannot be empty");
    }

    // Skip AI for system messages — just save to DB and return
    if user_message.starts_with("[SYSTEM]") {
        let _ = sqlx::query(
            "INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'user', $2)"
        )
        .bind(telegram_id)
        .bind(user_message)
        .execute(pool.get_ref())
        .await;
        return HttpResponse::Ok().json(json!({"response": ""}));
    }

    // Check if user has active ticket — don't call AI
    let has_ticket = sqlx::query(
        "SELECT id FROM support_tickets WHERE telegram_id = $1 AND status = 'open' LIMIT 1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten()
    .is_some();

    if has_ticket {
        // Save user message but don't call AI
        let _ = sqlx::query(
            "INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'user', $2)"
        )
        .bind(telegram_id)
        .bind(user_message)
        .execute(pool.get_ref())
        .await;
        return HttpResponse::Ok().json(json!({"response": ""}));
    }

    // 0. Check maintenance mode
    let maintenance = sqlx::query(
        "SELECT value FROM support_settings WHERE key = 'maintenance_mode'"
    )
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten()
    .map(|row| row.get::<String, _>("value") == "true")
    .unwrap_or(false);

    // 1. Fetch user context from DB
    let user_row = sqlx::query(
        "SELECT plan, subscription_end, is_active, device_limit, is_pro FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await;

    let maintenance_tag = if maintenance { "\n[MAINTENANCE_MODE: ON]" } else { "" };

    let user_context = match user_row {
        Ok(Some(row)) => format!(
            "Контекст пользователя: тариф={}, подписка_до={}, активен={}, лимит_устройств={}, PRO={}{}",
            row.get::<String, _>("plan"),
            row.get::<chrono::DateTime<chrono::Utc>, _>("subscription_end").to_rfc3339(),
            row.get::<i32, _>("is_active"),
            row.get::<i64, _>("device_limit"),
            row.get::<bool, _>("is_pro"),
            maintenance_tag,
        ),
        Ok(None) => format!(
            "Контекст: пользователь не зарегистрирован (telegram_id={}). Помоги с общими вопросами и предложи зарегистрироваться через бота @svoivless_bot или на сайте svoiweb.ru{}",
            telegram_id, maintenance_tag
        ),
        Err(e) => {
            error!("[internal_support_chat] DB error fetching user {}: {}", telegram_id, e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
    };

    // 2. Fetch last 40 messages from support_chats
    let history = sqlx::query(
        "SELECT role, content FROM support_chats WHERE telegram_id = $1 ORDER BY created_at DESC LIMIT 40"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // 3. Build messages array for ProxyAPI
    let mut messages: Vec<serde_json::Value> = Vec::new();
    messages.push(json!({"role": "system", "content": system_prompt.as_str()}));
    messages.push(json!({"role": "system", "content": user_context}));

    // First message: disclose AI identity
    if history.is_empty() {
        messages.push(json!({
            "role": "assistant",
            "content": "Здравствуйте! Я — ИИ-ассистент службы поддержки SvoiVPN. Чем могу Вам помочь?"
        }));
    } else {
        // Add history in chronological order (reverse the DESC result)
        let hist_messages: Vec<serde_json::Value> = history.iter().rev().map(|row| {
            json!({
                "role": row.get::<String, _>("role"),
                "content": row.get::<String, _>("content")
            })
        }).collect();
        messages.extend(hist_messages);
    }

    messages.push(json!({"role": "user", "content": user_message}));

    // 4. Define function calling tools
    let tools = json!([
        {
            "type": "function",
            "function": {
                "name": "get_user_info",
                "description": "Получить информацию о пользователе: тариф, статус подписки, ссылку на подписку, PRO режим, лимит устройств. Вызывайте когда пользователь спрашивает о своей подписке, ссылке, устройствах или статусе.",
                "parameters": {"type": "object", "properties": {}, "required": []}
            }
        },
        {
            "type": "function",
            "function": {
                "name": "toggle_pro",
                "description": "Включить или выключить PRO режим для пользователя. PRO добавляет протоколы gRPC и Trojan для обхода блокировок. Вызывайте ТОЛЬКО после подтверждения пользователя.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "enable": {"type": "boolean", "description": "true для включения PRO, false для выключения"}
                    },
                    "required": ["enable"]
                }
            }
        }
    ]);

    // 5. Call ProxyAPI with tools (tool call dispatch loop, max 3 iterations)
    let mut ai_response = String::new();
    let max_iterations = 3;

    for iteration in 0..max_iterations {
        let request_body = json!({
            "model": "gemini/gemini-2.0-flash",
            "temperature": 0.3,
            "messages": messages,
            "tools": tools
        });

        let api_result = HTTP_CLIENT
            .post(format!("{}/chat/completions", *PROXYAPI_BASE_URL))
            .header("Authorization", format!("Bearer {}", *PROXYAPI_KEY))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await;

        let resp_json = match api_result {
            Err(e) => {
                warn!("[internal_support_chat] ProxyAPI call failed (iteration {}): {}, retrying...", iteration, e);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let retry = HTTP_CLIENT
                    .post(format!("{}/chat/completions", *PROXYAPI_BASE_URL))
                    .header("Authorization", format!("Bearer {}", *PROXYAPI_KEY))
                    .header("Content-Type", "application/json")
                    .json(&request_body)
                    .send()
                    .await;
                match retry {
                    Err(e2) => { error!("[internal_support_chat] ProxyAPI retry failed (iteration {}): {}", iteration, e2); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
                    Ok(resp) if !resp.status().is_success() => { error!("[internal_support_chat] ProxyAPI retry error (iteration {}): {}", iteration, resp.status()); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
                    Ok(resp) => match resp.json::<serde_json::Value>().await {
                        Ok(v) => v,
                        Err(e2) => { error!("[internal_support_chat] ProxyAPI retry parse error: {}", e2); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
                    }
                }
            }
            Ok(resp) if !resp.status().is_success() => {
                let status = resp.status();
                warn!("[internal_support_chat] ProxyAPI error (iteration {}): {}, retrying...", iteration, status);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let retry = HTTP_CLIENT
                    .post(format!("{}/chat/completions", *PROXYAPI_BASE_URL))
                    .header("Authorization", format!("Bearer {}", *PROXYAPI_KEY))
                    .header("Content-Type", "application/json")
                    .json(&request_body)
                    .send()
                    .await;
                match retry {
                    Err(e) => { error!("[internal_support_chat] ProxyAPI retry failed (iteration {}): {}", iteration, e); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
                    Ok(resp) if !resp.status().is_success() => { error!("[internal_support_chat] ProxyAPI retry error (iteration {}): {}", iteration, resp.status()); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
                    Ok(resp) => match resp.json::<serde_json::Value>().await {
                        Ok(v) => v,
                        Err(e) => { error!("[internal_support_chat] ProxyAPI retry parse error: {}", e); return HttpResponse::ServiceUnavailable().body("service temporarily unavailable"); }
                    }
                }
            }
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(v) => v,
                Err(e) => {
                    error!("[internal_support_chat] Failed to parse ProxyAPI response (iteration {}): {}", iteration, e);
                    return HttpResponse::ServiceUnavailable().body("service temporarily unavailable");
                }
            }
        };

        let choice = &resp_json["choices"][0]["message"];

        // Check for tool_calls
        let tool_calls = choice.get("tool_calls").and_then(|tc| tc.as_array());

        if let Some(calls) = tool_calls {
            if !calls.is_empty() {
                // Append assistant message with tool_calls to messages
                messages.push(choice.clone());

                // Process each tool call
                for tool_call in calls {
                    let call_id = tool_call["id"].as_str().unwrap_or("unknown");
                    let function_name = tool_call["function"]["name"].as_str().unwrap_or("");
                    let arguments_str = tool_call["function"]["arguments"].as_str().unwrap_or("{}");

                    let tool_result = match function_name {
                        "get_user_info" => {
                            // Direct DB query for user info
                            match sqlx::query(
                                "SELECT telegram_id, plan, subscription_end, is_active, device_limit, is_pro, sub_link, username FROM users WHERE telegram_id = $1"
                            )
                            .bind(telegram_id)
                            .fetch_optional(pool.get_ref())
                            .await {
                                Ok(Some(row)) => {
                                    let sub_end: chrono::DateTime<chrono::Utc> = row.get("subscription_end");
                                    let sub_end_formatted = sub_end.format("%d.%m.%Y %H:%M MSK").to_string();
                                    json!({
                                        "plan": row.get::<String, _>("plan"),
                                        "subscription_end": sub_end_formatted,
                                        "is_active": row.get::<i32, _>("is_active") != 0,
                                        "device_limit": row.get::<i64, _>("device_limit"),
                                        "is_pro": row.get::<bool, _>("is_pro"),
                                        "sub_link": row.get::<String, _>("sub_link"),
                                        "username": row.get::<Option<String>, _>("username")
                                    }).to_string()
                                }
                                Ok(None) => json!({"error": "User not found"}).to_string(),
                                Err(e) => {
                                    error!("[internal_support_chat] get_user_info DB error: {}", e);
                                    json!({"error": "Failed to fetch user info"}).to_string()
                                }
                            }
                        }
                        "toggle_pro" => {
                            // Parse enable argument
                            let enable = match serde_json::from_str::<serde_json::Value>(arguments_str) {
                                Ok(args) => args["enable"].as_bool().unwrap_or(false),
                                Err(_) => false,
                            };

                            // Internal HTTP call to toggle_pro endpoint
                            let toggle_result = HTTP_CLIENT
                                .patch(format!("http://127.0.0.1:8080/users/{}/pro", telegram_id))
                                .json(&json!({"is_pro": enable}))
                                .send()
                                .await;

                            match toggle_result {
                                Ok(resp) if resp.status().is_success() => {
                                    json!({"success": true, "is_pro": enable}).to_string()
                                }
                                Ok(resp) => {
                                    let status = resp.status();
                                    let body = resp.text().await.unwrap_or_default();
                                    error!("[internal_support_chat] toggle_pro failed: {} - {}", status, body);
                                    json!({"success": false, "error": format!("Failed to toggle PRO: {}", status)}).to_string()
                                }
                                Err(e) => {
                                    error!("[internal_support_chat] toggle_pro HTTP error: {}", e);
                                    json!({"success": false, "error": "Failed to reach toggle_pro endpoint"}).to_string()
                                }
                            }
                        }
                        _ => {
                            error!("[internal_support_chat] Unknown tool call: {}", function_name);
                            json!({"error": format!("Unknown function: {}", function_name)}).to_string()
                        }
                    };

                    // Append tool result to messages
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": tool_result
                    }));
                }

                // Continue loop to re-call ProxyAPI with tool results
                continue;
            }
        }

        // No tool_calls -- extract final text response
        ai_response = choice["content"]
            .as_str()
            .unwrap_or("Извините, не удалось получить ответ.")
            .to_string();
        break;
    }

    // If we exhausted iterations without getting a text response
    if ai_response.is_empty() {
        ai_response = "Извините, произошла ошибка при обработке запроса. Попробуйте ещё раз или свяжитесь с оператором.".to_string();
    }

    // 6. Persist user message and AI response
    let _ = sqlx::query(
        "INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'user', $2)"
    )
    .bind(telegram_id)
    .bind(user_message)
    .execute(pool.get_ref())
    .await;

    let _ = sqlx::query(
        "INSERT INTO support_chats (telegram_id, role, content) VALUES ($1, 'assistant', $2)"
    )
    .bind(telegram_id)
    .bind(&ai_response)
    .execute(pool.get_ref())
    .await;

    HttpResponse::Ok().json(json!({"response": ai_response}))
}

pub async fn internal_support_escalate(
    pool: web::Data<PgPool>,
    body: web::Json<InternalSupportEscalateRequest>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let telegram_id = body.telegram_id;

    // 1. Fetch user info for ticket
    let user_row = sqlx::query(
        "SELECT telegram_id, username, plan, subscription_end, is_active, device_limit, is_pro FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await;

    let user_row = match user_row {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "Пользователь не найден"})),
        Err(e) => {
            error!("[internal_support_escalate] DB error fetching user {}: {}", telegram_id, e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
    };

    let username: String = user_row.try_get::<String, _>("username")
        .unwrap_or_else(|_| "не указан".to_string());
    let plan: String = user_row.try_get::<String, _>("plan")
        .unwrap_or_else(|_| "не указан".to_string());
    let subscription_end: String = user_row.try_get::<chrono::DateTime<chrono::Utc>, _>("subscription_end")
        .map(|dt| dt.format("%d.%m.%Y %H:%M").to_string())
        .unwrap_or_else(|_| "не указана".to_string());
    let is_active: bool = user_row.try_get::<i32, _>("is_active")
        .map(|v| v != 0)
        .unwrap_or(false);
    let device_limit: i64 = user_row.try_get::<i64, _>("device_limit")
        .unwrap_or(0);
    let is_pro: bool = user_row.try_get::<bool, _>("is_pro")
        .unwrap_or(false);

    // 2. Fetch recent chat history (last 10 messages for ticket context)
    let history = sqlx::query(
        "SELECT role, content, created_at FROM support_chats WHERE telegram_id = $1 ORDER BY created_at DESC LIMIT 10"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // 3. Format ticket text in HTML (Telegram parse_mode)
    let history_text = if history.is_empty() {
        "История чата пуста.".to_string()
    } else {
        history.iter().rev().map(|row| {
            let role = row.get::<String, _>("role");
            let content = row.get::<String, _>("content");
            let truncated = if content.chars().count() > 200 {
                let end: String = content.chars().take(200).collect();
                format!("{}...", end)
            } else {
                content
            };
            format!("[{}]: {}", role, truncated)
        })
        .collect::<Vec<_>>()
        .join("\n")
    };

    let mut ticket_text = format!(
        "<b>Запрос на поддержку</b>\n\n\
         <b>Пользователь:</b>\n\
         Telegram ID: <code>{}</code>\n\
         Username: {}\n\
         Тариф: {}\n\
         Подписка до: {}\n\
         Активен: {}\n\
         Устройств: {}\n\
         PRO: {}\n\n\
         <b>История чата (последние сообщения):</b>\n{}",
        telegram_id,
        username,
        plan,
        subscription_end,
        if is_active { "Да" } else { "Нет" },
        device_limit,
        if is_pro { "Да" } else { "Нет" },
        history_text,
    );

    // Truncate to 4000 chars max (Telegram limit is 4096)
    if ticket_text.len() > 4000 {
        let mut end = 4000;
        while !ticket_text.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        ticket_text.truncate(end);
        ticket_text.push_str("...");
    }

    // 4. Send to each admin via Telegram Bot API
    let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", *SUPPORT_BOT_TOKEN);

    for admin_id in ADMIN_IDS.iter() {
        let result = HTTP_CLIENT.post(&tg_url)
            .json(&json!({
                "chat_id": admin_id,
                "text": ticket_text,
                "parse_mode": "HTML"
            }))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                info!("[internal_support_escalate] Sent ticket to admin {}", admin_id);
            }
            Ok(resp) => {
                error!("[internal_support_escalate] Failed to notify admin {}: HTTP {}", admin_id, resp.status());
            }
            Err(e) => {
                error!("[internal_support_escalate] Failed to notify admin {}: {}", admin_id, e);
            }
        }
    }

    HttpResponse::Ok().json(json!({"status": "escalated"}))
}

pub async fn app_get_maintenance(pool: web::Data<PgPool>) -> HttpResponse {
    let maintenance = sqlx::query(
        "SELECT value FROM support_settings WHERE key = 'maintenance_mode'"
    )
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten()
    .map(|row| row.get::<String, _>("value") == "true")
    .unwrap_or(false);

    HttpResponse::Ok().json(json!({
        "maintenance": maintenance,
        "message": if maintenance { "Ведутся технические работы. Обновите подписку после завершения." } else { "" }
    }))
}

pub async fn app_bug_report(body: web::Json<serde_json::Value>) -> HttpResponse {
    let tg_id = body.get("telegram_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let message = body.get("message").and_then(|v| v.as_str()).unwrap_or("");
    let logs = body.get("logs").and_then(|v| v.as_str()).unwrap_or("");
    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
    let device = body.get("device").and_then(|v| v.as_str()).unwrap_or("?");
    let android = body.get("android").and_then(|v| v.as_str()).unwrap_or("?");
    let plan = body.get("plan").and_then(|v| v.as_str()).unwrap_or("?");

    let report = format!(
        "\u{1f4e9} <b>Bug Report</b>\n<b>User:</b> {}\n<b>Version:</b> {}\n<b>Device:</b> {}\n<b>Android:</b> {}\n<b>Plan:</b> {}\n\n<b>Сообщение:</b>\n{}\n\n<b>Логи:</b>\n<pre>{}</pre>",
        tg_id, version, device, android, plan, message, &logs[..logs.len().min(2000)]
    );

    let bot_token = std::env::var("BUG_REPORT_BOT_TOKEN").unwrap_or_default();
    let chat_id = std::env::var("BUG_REPORT_CHAT_ID").unwrap_or_else(|_| "729371813".to_string());

    if bot_token.is_empty() {
        error!("[app_bug_report] BUG_REPORT_BOT_TOKEN not set");
        return HttpResponse::InternalServerError().json(json!({"error": "not configured"}));
    }

    let resp = HTTP_CLIENT
        .post(&format!("https://api.telegram.org/bot{}/sendMessage", bot_token))
        .json(&json!({
            "chat_id": chat_id,
            "text": &report[..report.len().min(4000)],
            "parse_mode": "HTML"
        }))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            info!("[app_bug_report] Report sent from user {}", tg_id);
            HttpResponse::Ok().json(json!({"status": "sent"}))
        }
        Ok(r) => {
            error!("[app_bug_report] Telegram API error: {}", r.status());
            HttpResponse::InternalServerError().json(json!({"error": "failed to send"}))
        }
        Err(e) => {
            error!("[app_bug_report] Request failed: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "failed to send"}))
        }
    }
}

pub async fn internal_set_maintenance(pool: web::Data<PgPool>, body: web::Json<serde_json::Value>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let value = if enabled { "true" } else { "false" };

    let _ = sqlx::query(
        "INSERT INTO support_settings (key, value, updated_at) VALUES ('maintenance_mode', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()"
    )
    .bind(value)
    .execute(pool.get_ref())
    .await;

    info!("[maintenance] mode set to {}", value);
    HttpResponse::Ok().json(json!({"maintenance": enabled}))
}

pub async fn internal_send_verify_code(pool: web::Data<PgPool>, body: web::Json<serde_json::Value>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let email = match body.get("email").and_then(|v| v.as_str()) {
        Some(e) => e.trim().to_lowercase(),
        None => return HttpResponse::BadRequest().json(json!({"error": "email required"})),
    };

    // Check email exists and is not verified
    let row = sqlx::query("SELECT email_verified FROM user_credentials WHERE email = $1")
        .bind(&email).fetch_optional(pool.get_ref()).await;
    match row {
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "Email не зарегистрирован"})),
        Ok(Some(r)) => {
            let verified: bool = r.get("email_verified");
            if verified { return HttpResponse::Ok().json(json!({"status": "already_verified"})); }
        }
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }

    if check_rate_limit(pool.get_ref(), &email).await {
        return HttpResponse::TooManyRequests().json(json!({"error": "Код уже отправлен. Подождите 60 секунд."}));
    }

    let code = generate_6digit_code();
    let _ = sqlx::query(
        "INSERT INTO email_verification_codes (email, code, purpose, expires_at) VALUES ($1, $2, 'register', NOW() + INTERVAL '30 minutes')"
    ).bind(&email).bind(&code).execute(pool.get_ref()).await;

    if let Err(e) = crate::email::send_verification_code(&email, &code).await {
        error!("[internal_send_verify_code] Failed to send: {}", e);
        return HttpResponse::InternalServerError().json(json!({"error": "Не удалось отправить код"}));
    }

    info!("[internal_send_verify_code] Code sent to {}", email);
    HttpResponse::Ok().json(json!({"status": "sent"}))
}

pub async fn internal_confirm_verify_code(pool: web::Data<PgPool>, body: web::Json<serde_json::Value>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let email = match body.get("email").and_then(|v| v.as_str()) {
        Some(e) => e.trim().to_lowercase(),
        None => return HttpResponse::BadRequest().json(json!({"error": "email required"})),
    };
    let code = match body.get("code").and_then(|v| v.as_str()) {
        Some(c) => c.trim(),
        None => return HttpResponse::BadRequest().json(json!({"error": "code required"})),
    };

    let row = match sqlx::query(
        "SELECT id FROM email_verification_codes WHERE email = $1 AND code = $2 AND purpose = 'register' AND used = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1"
    ).bind(&email).bind(code).fetch_optional(pool.get_ref()).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::BadRequest().json(json!({"error": "Неверный или просроченный код"})),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let code_id: i64 = row.get("id");
    let _ = sqlx::query("UPDATE email_verification_codes SET used = TRUE WHERE id = $1").bind(code_id).execute(pool.get_ref()).await;
    let _ = sqlx::query("UPDATE user_credentials SET email_verified = TRUE WHERE email = $1").bind(&email).execute(pool.get_ref()).await;

    info!("[internal_confirm_verify_code] Email {} verified via bot", email);
    HttpResponse::Ok().json(json!({"status": "verified"}))
}

pub async fn internal_get_user_email(pool: web::Data<PgPool>, path: web::Path<i64>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let tg_id = path.into_inner();
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM user_credentials WHERE telegram_id = $1")
        .bind(tg_id)
        .fetch_optional(pool.get_ref())
        .await
        .ok()
        .flatten();

    match email {
        Some(e) => HttpResponse::Ok().json(json!({"email": e})),
        None => HttpResponse::Ok().json(json!({"email": serde_json::Value::Null})),
    }
}

// === Admin endpoints ===

/// GET /admin/chats - List recent chats grouped by telegram_id
pub async fn admin_list_chats(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    // Get last non-system message per user with user info
    // For anonymous users (negative telegram_id), fall back to ticket username
    let rows = sqlx::query(
        "SELECT DISTINCT ON (sc.telegram_id) \
            sc.telegram_id, sc.role, sc.content, sc.created_at, \
            COALESCE(u.username, st.username) as username \
         FROM support_chats sc \
         LEFT JOIN users u ON u.telegram_id = sc.telegram_id \
         LEFT JOIN support_tickets st ON st.telegram_id = sc.telegram_id \
         WHERE sc.content NOT LIKE '[SYSTEM]%' \
         ORDER BY sc.telegram_id, sc.created_at DESC"
    )
    .fetch_all(pool.get_ref())
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            error!("[admin_list_chats] DB error: {}", e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
    };

    // Get message counts per user
    let counts = sqlx::query(
        "SELECT telegram_id, COUNT(*) as cnt FROM support_chats GROUP BY telegram_id"
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let count_map: HashMap<i64, i64> = counts.iter()
        .map(|row| (row.get::<i64, _>("telegram_id"), row.get::<i64, _>("cnt")))
        .collect();

    let mut chats: Vec<serde_json::Value> = rows.iter().map(|row| {
        let tg_id: i64 = row.get("telegram_id");
        let message_count = count_map.get(&tg_id).copied().unwrap_or(0);
        json!({
            "telegram_id": tg_id,
            "username": row.try_get::<String, _>("username").unwrap_or_default(),
            "last_message": row.get::<String, _>("content"),
            "last_role": row.get::<String, _>("role"),
            "last_time": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            "message_count": message_count,
        })
    }).collect();

    // Sort by last_time DESC (most recent first)
    chats.sort_by(|a, b| {
        let time_a = a["last_time"].as_str().unwrap_or("");
        let time_b = b["last_time"].as_str().unwrap_or("");
        time_b.cmp(time_a)
    });

    info!("[admin_list_chats] Returned {} chats", chats.len());
    HttpResponse::Ok().json(chats)
}

/// GET /admin/chats/{telegram_id} - Full chat history for a user
pub async fn admin_get_chat(pool: web::Data<PgPool>, path: web::Path<i64>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let telegram_id = path.into_inner();

    // Fetch user info
    let user_row = sqlx::query(
        "SELECT telegram_id, username, plan, subscription_end, is_active, is_pro, sub_link, device_limit \
         FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await;

    let user_info = match user_row {
        Ok(Some(row)) => json!({
            "telegram_id": row.get::<i64, _>("telegram_id"),
            "username": row.try_get::<String, _>("username").unwrap_or_default(),
            "plan": row.try_get::<String, _>("plan").unwrap_or_default(),
            "subscription_end": row.get::<chrono::DateTime<chrono::Utc>, _>("subscription_end").to_rfc3339(),
            "is_active": row.get::<i32, _>("is_active"),
            "is_pro": row.get::<bool, _>("is_pro"),
            "sub_link": row.try_get::<String, _>("sub_link").unwrap_or_default(),
            "device_limit": row.get::<i64, _>("device_limit"),
        }),
        Ok(None) => json!({"telegram_id": telegram_id, "username": null, "plan": null}),
        Err(e) => {
            error!("[admin_get_chat] DB error fetching user {}: {}", telegram_id, e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
    };

    // Fetch chat messages
    let messages = sqlx::query(
        "SELECT role, content, created_at FROM support_chats \
         WHERE telegram_id = $1 ORDER BY created_at ASC"
    )
    .bind(telegram_id)
    .fetch_all(pool.get_ref())
    .await;

    let messages = match messages {
        Ok(rows) => rows.iter().map(|row| {
            json!({
                "role": row.get::<String, _>("role"),
                "content": row.get::<String, _>("content"),
                "time": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            })
        }).collect::<Vec<_>>(),
        Err(e) => {
            error!("[admin_get_chat] DB error fetching messages for {}: {}", telegram_id, e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
    };

    info!("[admin_get_chat] Returned {} messages for user {}", messages.len(), telegram_id);
    HttpResponse::Ok().json(json!({
        "user": user_info,
        "messages": messages,
    }))
}

/// POST /admin/chats/{telegram_id}/reply - Admin sends reply to user
pub async fn admin_reply_chat(
    pool: web::Data<PgPool>,
    path: web::Path<i64>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let telegram_id = path.into_inner();

    let message = match body.get("message").and_then(|v| v.as_str()) {
        Some(m) if !m.trim().is_empty() => m.trim().to_string(),
        _ => return HttpResponse::BadRequest().json(json!({"error": "message is required and cannot be empty"})),
    };

    // Verify user exists (skip for anonymous web users with negative IDs)
    if telegram_id >= 0 {
        let user_exists = sqlx::query("SELECT telegram_id FROM users WHERE telegram_id = $1")
            .bind(telegram_id)
            .fetch_optional(pool.get_ref())
            .await;

        match user_exists {
            Ok(None) => return HttpResponse::NotFound().json(json!({"error": "User not found"})),
            Err(e) => {
                error!("[admin_reply_chat] DB error checking user {}: {}", telegram_id, e);
                return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
            }
            _ => {}
        }
    }

    // Insert admin message into support_chats
    let result = sqlx::query(
        "INSERT INTO support_chats (telegram_id, role, content, created_at) VALUES ($1, 'admin', $2, NOW())"
    )
    .bind(telegram_id)
    .bind(&message)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            info!("[admin_reply_chat] Admin replied to user {} ({} chars)", telegram_id, message.len());

            // Email notification with 10-minute debounce
            let pool_clone = pool.clone();
            let msg_clone = message.clone();
            tokio::spawn(async move {
                if let Err(e) = maybe_send_support_reply_email(&pool_clone, telegram_id, &msg_clone).await {
                    warn!("[admin_reply_chat] Email notify failed for {}: {}", telegram_id, e);
                }
            });
            // Mobile push to that user's devices (support opt-in only).
            // No debounce: a support reply is always worth a push, and the
            // app dedups by chat history on open.
            let pool_push = pool.clone();
            let msg_push = message.clone();
            tokio::spawn(async move {
                let preview: String = msg_push.chars().take(120).collect();
                crate::push::send_to_user(
                    &pool_push,
                    telegram_id,
                    "Ответ поддержки",
                    &preview,
                    "support",
                )
                .await;
            });

            HttpResponse::Ok().json(json!({"status": "sent", "telegram_id": telegram_id}))
        }
        Err(e) => {
            error!("[admin_reply_chat] DB error inserting reply for {}: {}", telegram_id, e);
            { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) }
        }
    }
}

/// GET /admin/photo/{file_id} - Get Telegram photo URL
pub async fn admin_get_photo(path: web::Path<String>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let file_id = path.into_inner();
    let bot_token = std::env::var("BOT_TOKEN_SUPPORT").unwrap_or_default();
    if bot_token.is_empty() {
        return HttpResponse::InternalServerError().json(json!({"error": "Bot token not configured"}));
    }

    // Call Telegram getFile API
    let url = format!("https://api.telegram.org/bot{}/getFile?file_id={}", bot_token, file_id);
    match HTTP_CLIENT.get(&url).send().await {
        Ok(resp) => {
            match resp.json::<serde_json::Value>().await {
                Ok(data) => {
                    if let Some(file_path) = data["result"]["file_path"].as_str() {
                        let photo_url = format!("https://api.telegram.org/file/bot{}/{}", bot_token, file_path);
                        HttpResponse::Ok().json(json!({"url": photo_url}))
                    } else {
                        HttpResponse::NotFound().json(json!({"error": "File not found"}))
                    }
                }
                Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) }
            }
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) }
    }
}

/// POST /admin/chats/{telegram_id}/save - Save a message to chat history
pub async fn admin_save_chat_message(pool: web::Data<PgPool>, path: web::Path<i64>, body: web::Json<serde_json::Value>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let telegram_id = path.into_inner();
    let role = body.get("role").and_then(|v| v.as_str()).unwrap_or("user");
    let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("");

    if content.is_empty() {
        return HttpResponse::BadRequest().json(json!({"error": "content is required"}));
    }

    let _ = sqlx::query(
        "INSERT INTO support_chats (telegram_id, role, content, created_at) VALUES ($1, $2, $3, NOW())"
    )
    .bind(telegram_id)
    .bind(role)
    .bind(content)
    .execute(pool.get_ref())
    .await;

    HttpResponse::Ok().json(json!({"status": "saved"}))
}

/// GET /admin/tickets - List tickets from support_tickets table
pub async fn admin_list_tickets(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let rows = sqlx::query(
        "SELECT st.telegram_id, st.username, st.reason, st.status, st.created_at, st.closed_at, \
            (SELECT content FROM support_chats WHERE telegram_id = st.telegram_id ORDER BY created_at DESC LIMIT 1) as last_message, \
            (SELECT created_at FROM support_chats WHERE telegram_id = st.telegram_id ORDER BY created_at DESC LIMIT 1) as last_time \
         FROM support_tickets st \
         ORDER BY CASE WHEN st.status = 'open' THEN 0 ELSE 1 END, st.created_at DESC"
    )
    .fetch_all(pool.get_ref())
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            error!("[admin_list_tickets] DB error: {}", e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
    };

    let tickets: Vec<serde_json::Value> = rows.iter().map(|row| {
        json!({
            "telegram_id": row.get::<i64, _>("telegram_id"),
            "username": row.try_get::<String, _>("username").unwrap_or_default(),
            "last_message": row.try_get::<String, _>("last_message").unwrap_or_default(),
            "last_time": row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_time")
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
            "status": row.try_get::<String, _>("status").unwrap_or_else(|_| "open".to_string()),
        })
    }).collect();

    info!("[admin_list_tickets] Returned {} tickets", tickets.len());
    HttpResponse::Ok().json(tickets)
}

/// POST /admin/users/{telegram_id}/reset-password - Reset user password
pub async fn admin_reset_password(
    pool: web::Data<PgPool>,
    path: web::Path<i64>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let telegram_id = path.into_inner();

    let new_password = match body.get("new_password").and_then(|v| v.as_str()) {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => return HttpResponse::BadRequest().json(json!({"error": "new_password is required and cannot be empty"})),
    };

    // Verify user_credentials record exists
    let cred_exists = sqlx::query("SELECT telegram_id FROM user_credentials WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await;

    match cred_exists {
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "No credentials found for this user"})),
        Err(e) => {
            error!("[admin_reset_password] DB error checking credentials for {}: {}", telegram_id, e);
            return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) };
        }
        _ => {}
    }

    // Hash the new password with argon2
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error": "Failed to hash password"})),
    };

    // Update password_hash in user_credentials
    let result = sqlx::query(
        "UPDATE user_credentials SET password_hash = $1 WHERE telegram_id = $2"
    )
    .bind(&password_hash)
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            info!("[admin_reset_password] Password reset for user {}", telegram_id);
            HttpResponse::Ok().json(json!({"status": "password_reset", "telegram_id": telegram_id}))
        }
        Err(e) => {
            error!("[admin_reset_password] DB error updating password for {}: {}", telegram_id, e);
            { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) }
        }
    }
}

/// POST /admin/tickets/open - Open a ticket
pub async fn admin_open_ticket(pool: web::Data<PgPool>, body: web::Json<serde_json::Value>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let telegram_id = body.get("telegram_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");

    let _ = sqlx::query(
        "INSERT INTO support_tickets (telegram_id, username, reason, status, created_at) \
         VALUES ($1, $2, $3, 'open', NOW()) \
         ON CONFLICT (telegram_id) DO UPDATE SET status = 'open', reason = $3, closed_at = NULL"
    )
    .bind(telegram_id)
    .bind(username)
    .bind(reason)
    .execute(pool.get_ref())
    .await;

    info!("[admin_open_ticket] Opened ticket for {}", telegram_id);
    HttpResponse::Ok().json(json!({"status": "opened"}))
}

/// POST /admin/tickets/close - Close a ticket
pub async fn admin_close_ticket(pool: web::Data<PgPool>, body: web::Json<serde_json::Value>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let telegram_id = body.get("telegram_id").and_then(|v| v.as_i64()).unwrap_or(0);

    let _ = sqlx::query(
        "UPDATE support_tickets SET status = 'closed', closed_at = NOW() WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    info!("[admin_close_ticket] Closed ticket for {}", telegram_id);
    HttpResponse::Ok().json(json!({"status": "closed"}))
}

/// GET /admin/tickets/active - List active (open) tickets
pub async fn admin_active_tickets(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let rows = sqlx::query("SELECT telegram_id, username, reason, created_at FROM support_tickets WHERE status = 'open' ORDER BY created_at DESC")
        .fetch_all(pool.get_ref())
        .await;

    match rows {
        Ok(rows) => {
            let tickets: Vec<serde_json::Value> = rows.iter().map(|r| {
                json!({
                    "telegram_id": r.get::<i64, _>("telegram_id"),
                    "username": r.try_get::<String, _>("username").unwrap_or_default(),
                    "reason": r.try_get::<String, _>("reason").unwrap_or_default(),
                })
            }).collect();
            HttpResponse::Ok().json(tickets)
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === Referral top ===

pub async fn admin_referral_top(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }

    let rows = sqlx::query(
        "SELECT telegram_id, username, \
         COALESCE(array_length(referrals, 1), 0)::bigint AS total_refs, \
         payed_refs \
         FROM users \
         WHERE COALESCE(array_length(referrals, 1), 0) > 0 \
         ORDER BY total_refs DESC \
         LIMIT 50"
    )
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(rows) => {
            let list: Vec<serde_json::Value> = rows.iter().map(|r| {
                json!({
                    "telegram_id": r.get::<i64, _>("telegram_id"),
                    "username": r.get::<Option<String>, _>("username").unwrap_or_default(),
                    "total_refs": r.get::<i64, _>("total_refs"),
                    "payed_refs": r.get::<i64, _>("payed_refs"),
                })
            }).collect();
            HttpResponse::Ok().json(list)
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// === Admin: per-user referral details ===

pub async fn admin_user_referrals(pool: web::Data<PgPool>, path: web::Path<i64>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }

    let telegram_id = path.into_inner();

    let user = sqlx::query(
        "SELECT telegram_id, username, referrals, payed_refs FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await;

    let row = match user {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "user not found"})),
        Err(e) => {
            error!("Internal error: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"}));
        }
    };

    let username = row.get::<Option<String>, _>("username").unwrap_or_default();
    let referrals: Option<Vec<i64>> = row.get("referrals");
    let payed_refs: i64 = row.get("payed_refs");
    let refs_count = referrals.as_ref().map(|r| r.len()).unwrap_or(0);

    let mut referral_list: Vec<serde_json::Value> = vec![];
    if let Some(ref ref_ids) = referrals {
        if !ref_ids.is_empty() {
            let rows = sqlx::query(
                "SELECT telegram_id, username, is_active, plan, subscription_end \
                 FROM users WHERE telegram_id = ANY($1)"
            )
            .bind(ref_ids)
            .fetch_all(pool.get_ref())
            .await
            .unwrap_or_default();

            for r in rows {
                let is_active: i32 = r.get("is_active");
                let plan: String = r.get("plan");
                let has_paid = is_active > 0 && plan != "trial" && plan != "free";
                let sub_end = r.try_get::<chrono::DateTime<chrono::Utc>, _>("subscription_end")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default();
                referral_list.push(json!({
                    "telegram_id": r.get::<i64, _>("telegram_id"),
                    "username": r.get::<Option<String>, _>("username").unwrap_or_default(),
                    "plan": plan,
                    "is_active": is_active > 0,
                    "has_paid": has_paid,
                    "subscription_end": sub_end,
                }));
            }
        }
    }

    HttpResponse::Ok().json(json!({
        "telegram_id": telegram_id,
        "username": username,
        "referrals_count": refs_count,
        "payed_refs_count": payed_refs,
        "referrals": referral_list,
    }))
}

// === Admin user list ===

#[derive(serde::Deserialize)]
pub struct UserListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub q: Option<String>,
    pub plan: Option<String>,
    pub status: Option<String>,
    pub expiring: Option<i64>,
    pub is_pro: Option<bool>,
    pub auto_renew: Option<bool>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

/// Pushes the shared ` WHERE ...` filter clauses onto a QueryBuilder.
/// Used by both the COUNT query and the page query so they stay in sync.
fn push_user_filters(qb: &mut sqlx::QueryBuilder<sqlx::Postgres>, q: &UserListQuery) {
    qb.push(" WHERE 1=1");
    if let Some(term) = q.q.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        qb.push(" AND (u.username ILIKE ").push_bind(format!("%{}%", term));
        qb.push(" OR uc.email ILIKE ").push_bind(format!("%{}%", term));
        if let Ok(id) = term.parse::<i64>() {
            qb.push(" OR u.telegram_id = ").push_bind(id);
        }
        qb.push(")");
    }
    if let Some(plan) = q.plan.as_ref().filter(|s| !s.is_empty()) {
        qb.push(" AND u.plan = ").push_bind(plan.clone());
    }
    match q.status.as_deref() {
        Some("active") => { qb.push(" AND u.is_active > 0"); }
        Some("inactive") => { qb.push(" AND u.is_active = 0"); }
        _ => {}
    }
    if let Some(days) = q.expiring {
        qb.push(" AND u.is_active > 0 AND u.subscription_end BETWEEN NOW() AND NOW() + ")
          .push_bind(days)
          .push(" * INTERVAL '1 day'");
    }
    if let Some(pro) = q.is_pro {
        qb.push(" AND u.is_pro = ").push_bind(pro);
    }
    if let Some(ar) = q.auto_renew {
        qb.push(" AND u.auto_renew = ").push_bind(ar);
    }
}

/// GET /admin/users — paginated, filterable user list.
pub async fn admin_list_users(
    pool: web::Data<PgPool>,
    query: web::Query<UserListQuery>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let q = query.into_inner();
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;

    // Column name is whitelisted (never bound) — safe to interpolate.
    let sort_col = match q.sort.as_deref() {
        Some("subscription_end") => "u.subscription_end",
        _ => "u.created_at",
    };
    let order = match q.order.as_deref() {
        Some("asc") => "ASC",
        _ => "DESC",
    };

    let mut count_qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT COUNT(*) FROM users u LEFT JOIN user_credentials uc ON uc.telegram_id = u.telegram_id",
    );
    push_user_filters(&mut count_qb, &q);
    let total: i64 = match count_qb.build_query_scalar().fetch_one(pool.get_ref()).await {
        Ok(t) => t,
        Err(e) => { error!("[admin_list_users] count error: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"})); }
    };

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT u.* FROM users u LEFT JOIN user_credentials uc ON uc.telegram_id = u.telegram_id",
    );
    push_user_filters(&mut qb, &q);
    qb.push(" ORDER BY ").push(sort_col).push(" ").push(order);
    qb.push(" LIMIT ").push_bind(page_size).push(" OFFSET ").push_bind(offset);

    let users: Vec<User> = match qb.build_query_as::<User>().fetch_all(pool.get_ref()).await {
        Ok(u) => u,
        Err(e) => { error!("[admin_list_users] query error: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"})); }
    };

    let now = Utc::now();
    let items: Vec<serde_json::Value> = users.iter().map(|u| json!({
        "telegram_id": u.telegram_id,
        "username": u.username,
        "plan": u.plan,
        "is_active": u.is_active,
        "is_pro": u.is_pro,
        "subscription_end": u.subscription_end.to_rfc3339(),
        "days_left": (u.subscription_end - now).num_days(),
        "device_limit": u.device_limit,
        "auto_renew": u.auto_renew,
        "created_at": u.created_at.to_rfc3339(),
    })).collect();

    info!("[admin_list_users] page {} returned {}/{}", page, items.len(), total);
    HttpResponse::Ok().json(json!({
        "items": items, "total": total, "page": page, "page_size": page_size,
    }))
}

/// Fetches the user's HWID device list from Remnawave. Non-fatal:
/// on any failure returns an empty list so the detail page still renders.
async fn fetch_remnawave_devices(uuid: &str) -> serde_json::Value {
    let resp = HTTP_CLIENT
        .get(&format!("{}/hwid/devices/{}", *REMNAWAVE_API_BASE, uuid))
        .headers(remnawave_headers())
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
            Ok(j) => json!({
                "devices": j["response"]["devices"].clone(),
                "total": j["response"]["total"].as_u64().unwrap_or(0),
            }),
            Err(_) => json!({ "devices": [], "total": 0 }),
        },
        _ => json!({ "devices": [], "total": 0 }),
    }
}

/// Resolves the user's `referrals` id array into basic info rows.
async fn fetch_referral_list(pool: &PgPool, user: &User) -> Vec<serde_json::Value> {
    let ref_ids = match &user.referrals {
        Some(ids) if !ids.is_empty() => ids.clone(),
        _ => return vec![],
    };
    let rows = sqlx::query(
        "SELECT telegram_id, username, is_active, plan, subscription_end \
         FROM users WHERE telegram_id = ANY($1)",
    )
    .bind(&ref_ids)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    rows.iter().map(|r| {
        let is_active: i32 = r.get("is_active");
        json!({
            "telegram_id": r.get::<i64, _>("telegram_id"),
            "username": r.get::<Option<String>, _>("username"),
            "plan": r.get::<String, _>("plan"),
            "is_active": is_active > 0,
            "subscription_end": r.try_get::<chrono::DateTime<chrono::Utc>, _>("subscription_end")
                .map(|d| d.to_rfc3339()).unwrap_or_default(),
        })
    }).collect()
}

/// GET /admin/users/{telegram_id} — full user detail + devices + referrals.
pub async fn admin_get_user(
    pool: web::Data<PgPool>,
    path: web::Path<i64>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let telegram_id = path.into_inner();

    let user: User = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "user not found"})),
        Err(e) => { error!("[admin_get_user] db error: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"})); }
    };

    let email: Option<String> = sqlx::query_scalar::<_, String>(
        "SELECT email FROM user_credentials WHERE telegram_id = $1",
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    let devices = fetch_remnawave_devices(&user.uuid.to_string()).await;
    let referrals = fetch_referral_list(pool.get_ref(), &user).await;

    let days_left = (user.subscription_end - Utc::now()).num_days();
    let mut user_json = serde_json::to_value(&user).unwrap_or_else(|_| json!({}));
    if let Some(obj) = user_json.as_object_mut() {
        obj.insert("days_left".into(), json!(days_left));
        obj.insert("email".into(), json!(email));
    }

    HttpResponse::Ok().json(json!({
        "user": user_json, "devices": devices, "referrals": referrals,
    }))
}

#[derive(serde::Deserialize)]
pub struct AdminUserPatch {
    pub is_active: Option<bool>,
    pub device_limit: Option<i64>,
    pub is_pro: Option<bool>,
    pub plan: Option<String>,
    pub auto_renew: Option<bool>,
}

/// PATCH /admin/users/{telegram_id} — partial update of admin-safe fields.
/// Remnawave-coupled fields sync to Remnawave first; on any Remnawave
/// failure we return 502 before touching the DB (avoids DB/panel desync).
pub async fn admin_update_user(
    pool: web::Data<PgPool>,
    path: web::Path<i64>,
    body: web::Json<AdminUserPatch>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let telegram_id = path.into_inner();
    let p = body.into_inner();

    let user: User = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error": "user not found"})),
        Err(e) => { error!("[admin_update_user] db error: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"})); }
    };

    // 1. Remnawave: block / unblock.
    if let Some(active) = p.is_active {
        let status = if active { "ACTIVE" } else { "DISABLED" };
        let r = HTTP_CLIENT
            .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
            .headers(remnawave_headers())
            .json(&json!({ "uuid": user.uuid, "status": status }))
            .send().await;
        if !matches!(r, Ok(ref resp) if resp.status().is_success()) {
            error!("[admin_update_user] Remnawave status update failed for {}", telegram_id);
            return HttpResponse::BadGateway().json(json!({"error": "remnawave status update failed"}));
        }
    }

    // 2. Remnawave: device limit.
    if let Some(dl) = p.device_limit {
        let r = HTTP_CLIENT
            .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
            .headers(remnawave_headers())
            .json(&json!({ "uuid": user.uuid, "hwidDeviceLimit": dl }))
            .send().await;
        if !matches!(r, Ok(ref resp) if resp.status().is_success()) {
            error!("[admin_update_user] Remnawave device limit update failed for {}", telegram_id);
            return HttpResponse::BadGateway().json(json!({"error": "remnawave device limit update failed"}));
        }
    }

    // 3. PRO — delegate to the existing /users/{tg}/pro handler (squad sync + DB).
    if let Some(pro) = p.is_pro {
        let r = HTTP_CLIENT
            .patch(&format!("http://127.0.0.1:8080/users/{}/pro", telegram_id))
            .json(&json!({ "is_pro": pro }))
            .send().await;
        if !matches!(r, Ok(ref resp) if resp.status().is_success()) {
            error!("[admin_update_user] pro toggle failed for {}", telegram_id);
            return HttpResponse::BadGateway().json(json!({"error": "pro toggle failed"}));
        }
    }

    // 4. DB update for the non-PRO fields.
    let need_db = p.is_active.is_some() || p.device_limit.is_some()
        || p.plan.is_some() || p.auto_renew.is_some();
    if need_db {
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET ");
        let mut sep = qb.separated(", ");
        if let Some(active) = p.is_active {
            sep.push("is_active = ").push_bind_unseparated(if active { 1_i32 } else { 0_i32 });
        }
        if let Some(dl) = p.device_limit {
            sep.push("device_limit = ").push_bind_unseparated(dl);
        }
        if let Some(plan) = &p.plan {
            sep.push("plan = ").push_bind_unseparated(plan.clone());
        }
        if let Some(ar) = p.auto_renew {
            sep.push("auto_renew = ").push_bind_unseparated(ar);
        }
        drop(sep);
        qb.push(" WHERE telegram_id = ").push_bind(telegram_id);
        if let Err(e) = qb.build().execute(pool.get_ref()).await {
            error!("[admin_update_user] db update error: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"}));
        }
    }

    info!("[admin_update_user] updated user {}", telegram_id);
    HttpResponse::Ok().json(json!({ "status": "ok" }))
}

/// GET /admin/stats — aggregate dashboard metrics.
pub async fn admin_stats(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }

    let counts = sqlx::query(
        "SELECT \
            COUNT(*) AS total, \
            COUNT(*) FILTER (WHERE is_active > 0) AS active, \
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day') AS d1, \
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS d7, \
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS d30, \
            COUNT(*) FILTER (WHERE is_active > 0 \
                AND subscription_end BETWEEN NOW() AND NOW() + INTERVAL '7 days') AS expiring, \
            COUNT(*) FILTER (WHERE is_used_trial = true) AS trial_used \
         FROM users",
    )
    .fetch_one(pool.get_ref())
    .await;

    let counts = match counts {
        Ok(r) => r,
        Err(e) => { error!("[admin_stats] counts error: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"})); }
    };

    let plan_rows = sqlx::query("SELECT plan, COUNT(*) AS cnt FROM users GROUP BY plan ORDER BY cnt DESC")
        .fetch_all(pool.get_ref()).await
        .unwrap_or_else(|e| { warn!("[admin_stats] plan distribution query failed: {}", e); Vec::new() });
    let plan_distribution: Vec<serde_json::Value> = plan_rows.iter().map(|r| json!({
        "plan": r.get::<String, _>("plan"),
        "count": r.get::<i64, _>("cnt"),
    })).collect();

    let platform_rows = sqlx::query(
        "SELECT platform, COUNT(*) AS cnt FROM device_tokens GROUP BY platform ORDER BY cnt DESC",
    ).fetch_all(pool.get_ref()).await
        .unwrap_or_else(|e| { warn!("[admin_stats] platform split query failed: {}", e); Vec::new() });
    let platform_split: Vec<serde_json::Value> = platform_rows.iter().map(|r| json!({
        "platform": r.get::<String, _>("platform"),
        "count": r.get::<i64, _>("cnt"),
    })).collect();

    // Sparse series: only days with >=1 signup appear; the chart fills gaps.
    let signup_rows = sqlx::query(
        "SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS day, COUNT(*) AS cnt \
         FROM users WHERE created_at > NOW() - INTERVAL '30 days' \
         GROUP BY day ORDER BY day",
    ).fetch_all(pool.get_ref()).await
        .unwrap_or_else(|e| { warn!("[admin_stats] signups query failed: {}", e); Vec::new() });
    let signups_30d: Vec<serde_json::Value> = signup_rows.iter().map(|r| json!({
        "date": r.get::<String, _>("day"),
        "count": r.get::<i64, _>("cnt"),
    })).collect();

    HttpResponse::Ok().json(json!({
        "total_users":  counts.get::<i64, _>("total"),
        "active_users": counts.get::<i64, _>("active"),
        "new_signups": {
            "d1":  counts.get::<i64, _>("d1"),
            "d7":  counts.get::<i64, _>("d7"),
            "d30": counts.get::<i64, _>("d30"),
        },
        "expiring_7d":  counts.get::<i64, _>("expiring"),
        "trial_used":   counts.get::<i64, _>("trial_used"),
        "plan_distribution": plan_distribution,
        "platform_split": platform_split,
        "signups_30d": signups_30d,
    }))
}

/// Resolves a broadcast `segment` JSON to the matching device-token list.
/// All segments are gated by notify_news = TRUE.
async fn resolve_segment_tokens(pool: &PgPool, segment: &serde_json::Value) -> Vec<String> {
    let seg_type = segment.get("type").and_then(|v| v.as_str()).unwrap_or("all");
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT dt.token FROM device_tokens dt");
    match seg_type {
        "expiring" => {
            let days = segment.get("days").and_then(|v| v.as_i64()).unwrap_or(7);
            qb.push(" JOIN users u ON u.telegram_id = dt.telegram_id \
                      WHERE dt.notify_news = TRUE AND u.is_active > 0 \
                      AND u.subscription_end BETWEEN NOW() AND NOW() + ");
            qb.push_bind(days).push(" * INTERVAL '1 day'");
        }
        "plan" => {
            let plan = segment.get("plan").and_then(|v| v.as_str()).unwrap_or("").to_string();
            qb.push(" JOIN users u ON u.telegram_id = dt.telegram_id \
                      WHERE dt.notify_news = TRUE AND u.plan = ");
            qb.push_bind(plan);
        }
        "inactive" => {
            qb.push(" JOIN users u ON u.telegram_id = dt.telegram_id \
                      WHERE dt.notify_news = TRUE AND u.is_active = 0");
        }
        _ => { qb.push(" WHERE dt.notify_news = TRUE"); }
    }
    match qb.build().fetch_all(pool).await {
        Ok(rows) => rows.iter().map(|r| r.get::<String, _>("token")).collect(),
        Err(e) => { error!("[broadcast] segment query failed: {}", e); Vec::new() }
    }
}

/// POST /admin/broadcast/preview — recipient count for a segment.
pub async fn admin_broadcast_preview(
    pool: web::Data<PgPool>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let segment = body.get("segment").cloned().unwrap_or_else(|| json!({"type": "all"}));
    let tokens = resolve_segment_tokens(pool.get_ref(), &segment).await;
    HttpResponse::Ok().json(json!({"count": tokens.len()}))
}

/// POST /admin/broadcast — send a broadcast (FCM fan-out runs in the background).
pub async fn admin_broadcast(
    pool: web::Data<PgPool>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let text = body.get("body").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let segment = body.get("segment").cloned().unwrap_or_else(|| json!({"type": "all"}));
    if title.is_empty() || text.is_empty() {
        return HttpResponse::BadRequest().json(json!({"error": "title and body are required"}));
    }

    let tokens = resolve_segment_tokens(pool.get_ref(), &segment).await;
    let recipients = tokens.len() as i32;

    let id: i64 = match sqlx::query_scalar::<_, i64>(
        "INSERT INTO broadcasts (admin_label, title, body, segment, recipients, delivered, status) \
         VALUES ('admin', $1, $2, $3::jsonb, $4, 0, 'sending') RETURNING id",
    )
    .bind(&title)
    .bind(&text)
    .bind(segment.to_string())
    .bind(recipients)
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(id) => id,
        Err(e) => { error!("[admin_broadcast] insert failed: {}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "internal server error"})); }
    };

    // Background FCM fan-out: the admin's request returns immediately.
    let pool2 = pool.clone();
    tokio::spawn(async move {
        let delivered = crate::push::blast_tokens(&pool2, tokens, &title, &text).await as i32;
        let _ = sqlx::query("UPDATE broadcasts SET delivered = $1, status = 'sent' WHERE id = $2")
            .bind(delivered)
            .bind(id)
            .execute(pool2.get_ref())
            .await;
        info!("[admin_broadcast] #{} delivered {}/{}", id, delivered, recipients);
    });

    HttpResponse::Ok().json(json!({"id": id, "recipients": recipients, "status": "sending"}))
}

/// GET /admin/broadcasts — broadcast history, newest first.
pub async fn admin_list_broadcasts(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_admin_key(&req) { return resp; }
    let rows = sqlx::query(
        "SELECT id, title, body, segment::text AS segment, recipients, delivered, status, created_at \
         FROM broadcasts ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_else(|e| { error!("[admin_list_broadcasts] query failed: {}", e); Vec::new() });
    let items: Vec<serde_json::Value> = rows.iter().map(|r| json!({
        "id": r.get::<i64, _>("id"),
        "title": r.get::<String, _>("title"),
        "body": r.get::<String, _>("body"),
        "segment": serde_json::from_str::<serde_json::Value>(&r.get::<String, _>("segment"))
            .unwrap_or_else(|_| json!({})),
        "recipients": r.get::<i32, _>("recipients"),
        "delivered": r.get::<i32, _>("delivered"),
        "status": r.get::<String, _>("status"),
        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
    })).collect();
    HttpResponse::Ok().json(json!({"items": items}))
}

// === News ===

pub async fn web_get_news(pool: web::Data<PgPool>) -> HttpResponse {
    let rows = sqlx::query(
        "SELECT id, tg_message_id, text, date, media_url, media_file_ids \
         FROM news_posts ORDER BY date DESC LIMIT 20"
    )
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(rows) => {
            let posts: Vec<serde_json::Value> = rows.iter().map(|r| {
                let id = r.get::<i64, _>("id");
                // images[] — proxied, loadable URLs (bot token stays
                // server-side, same trick as support attachments).
                // Empty array for text-only posts so the app renders
                // NO image area (was an empty grey skeleton before).
                let ids: Vec<String> = r.get::<Option<String>, _>("media_file_ids")
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                let images: Vec<String> = (0..ids.len())
                    .map(|i| format!("https://svoiweb.ru/api/web/news/image/{}/{}", id, i))
                    .collect();
                json!({
                    "id": id,
                    "text": r.get::<String, _>("text"),
                    "date": r.get::<chrono::DateTime<chrono::Utc>, _>("date").to_rfc3339(),
                    "media_url": r.get::<Option<String>, _>("media_url"),
                    "images": images,
                })
            }).collect();
            HttpResponse::Ok().json(posts)
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

/// GET /web/news/image/{id}/{idx} — public proxy for a news photo.
/// News is public, so no auth. Streams bytes from Telegram's file CDN
/// using BOT_TOKEN_TG (the channel bot's token, already in this
/// service's env) so the token never reaches the client.
pub async fn web_get_news_image(
    pool: web::Data<PgPool>,
    path: web::Path<(i64, usize)>,
) -> HttpResponse {
    let (news_id, idx) = path.into_inner();
    let row = sqlx::query("SELECT media_file_ids FROM news_posts WHERE id = $1")
        .bind(news_id)
        .fetch_optional(pool.get_ref())
        .await;
    let file_id = match row {
        Ok(Some(r)) => {
            let ids: Vec<String> = r.get::<Option<String>, _>("media_file_ids")
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            match ids.into_iter().nth(idx) {
                Some(f) => f,
                None => return HttpResponse::NotFound().finish(),
            }
        }
        Ok(None) => return HttpResponse::NotFound().finish(),
        Err(e) => { error!("[news_image] query: {}", e); return HttpResponse::InternalServerError().finish(); }
    };

    let bot_token = match std::env::var("BOT_TOKEN_TG") {
        Ok(v) => v,
        Err(_) => { error!("[news_image] BOT_TOKEN_TG missing"); return HttpResponse::InternalServerError().finish(); }
    };
    let client = reqwest::Client::new();
    let gf = client.post(&format!("https://api.telegram.org/bot{}/getFile", bot_token))
        .form(&[("file_id", file_id.as_str())])
        .send().await;
    let file_path = match gf {
        Ok(r) => match r.text().await {
            Ok(t) => serde_json::from_str::<serde_json::Value>(&t).ok()
                .and_then(|v| v.get("result").and_then(|x| x.get("file_path"))
                    .and_then(|p| p.as_str()).map(|s| s.to_string())),
            Err(_) => None,
        },
        Err(e) => { error!("[news_image] getFile: {}", e); None }
    };
    let file_path = match file_path {
        Some(p) => p,
        None => return HttpResponse::BadGateway().finish(),
    };
    let resp = client.get(&format!("https://api.telegram.org/file/bot{}/{}", bot_token, file_path))
        .send().await;
    match resp {
        Ok(r) if r.status().is_success() => {
            let ct = r.headers().get("content-type")
                .and_then(|h| h.to_str().ok()).unwrap_or("image/jpeg").to_string();
            match r.bytes().await {
                Ok(b) => HttpResponse::Ok()
                    .content_type(ct)
                    .append_header(("Cache-Control", "public, max-age=86400"))
                    .body(b),
                Err(_) => HttpResponse::BadGateway().finish(),
            }
        }
        _ => HttpResponse::BadGateway().finish(),
    }
}

pub async fn internal_save_news(pool: web::Data<PgPool>, body: web::Json<serde_json::Value>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let tg_message_id = body.get("tg_message_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let date = body.get("date").and_then(|v| v.as_str()).unwrap_or("");
    let media_url = body.get("media_url").and_then(|v| v.as_str());
    let photo_file_id = body.get("photo_file_id").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let media_group_id = body.get("media_group_id").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    // A photo-only channel post has no text — still valid news now.
    if tg_message_id == 0 || (text.is_empty() && photo_file_id.is_none()) {
        return HttpResponse::BadRequest().body("tg_message_id and (text or photo) required");
    }

    // Album: Telegram delivers each photo of a multi-photo post as a
    // separate channel_post update sharing media_group_id. Fold them
    // into ONE news row — append this photo's file_id to the existing
    // row, and backfill text if this update is the one carrying the
    // caption. No blast for the extra photos (the first one blasted).
    if let Some(gid) = media_group_id {
        if let (Some(fid), Ok(Some(existing))) = (
            photo_file_id,
            sqlx::query("SELECT id, media_file_ids, text FROM news_posts WHERE media_group_id = $1 LIMIT 1")
                .bind(gid).fetch_optional(pool.get_ref()).await,
        ) {
            let row_id: i64 = existing.get("id");
            let cur_ids: Option<String> = existing.get("media_file_ids");
            let cur_text: String = existing.get("text");
            let mut ids: Vec<String> = cur_ids
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            if !ids.iter().any(|x| x == fid) { ids.push(fid.to_string()); }
            let new_text = if cur_text.trim().is_empty() && !text.is_empty() { text } else { &cur_text };
            let _ = sqlx::query("UPDATE news_posts SET media_file_ids = $1, text = $2 WHERE id = $3")
                .bind(serde_json::to_string(&ids).unwrap_or_default())
                .bind(new_text)
                .bind(row_id)
                .execute(pool.get_ref())
                .await;
            return HttpResponse::Ok().json(json!({"status": "ok", "album_appended": true}));
        }
    }

    let media_file_ids = photo_file_id.map(|f| {
        serde_json::to_string(&vec![f]).unwrap_or_default()
    });

    let result = sqlx::query(
        "INSERT INTO news_posts (tg_message_id, text, date, media_url, media_file_ids, media_group_id) \
         VALUES ($1, $2, $3::timestamptz, $4, $5, $6) ON CONFLICT (tg_message_id) DO NOTHING"
    )
    .bind(tg_message_id)
    .bind(text)
    .bind(date)
    .bind(media_url)
    .bind(&media_file_ids)
    .bind(media_group_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => {
            // Fire-and-forget email blast to verified subscribers
            let pool_clone = pool.clone();
            let text_owned = text.to_string();
            tokio::spawn(async move {
                if let Err(e) = blast_news_email(&pool_clone, &text_owned).await {
                    error!("[news_blast] failed: {}", e);
                }
            });
            // Mobile push to every news-opted device. Same headline/body
            // split as the email blast so the two channels read alike.
            let pool_push = pool.clone();
            let text_push = text.to_string();
            tokio::spawn(async move {
                let mut lines = text_push.splitn(2, '\n');
                let headline = lines.next().unwrap_or("").trim();
                let title = if headline.is_empty() { "Новости SvoiVPN" } else { headline };
                let body = lines.next().unwrap_or("").trim();
                let body = if body.is_empty() { title } else { body };
                crate::push::blast_news(&pool_push, title, body).await;
            });
            HttpResponse::Ok().json(json!({"status": "ok"}))
        }
        Ok(_) => HttpResponse::Ok().json(json!({"status": "ok", "duplicate": true})),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Email notification helpers
// ─────────────────────────────────────────────────────────────────────────────

fn unsubscribe_url(token: &uuid::Uuid, kind: &str) -> String {
    format!("https://svoiweb.ru/api/web/unsubscribe/{}?type={}", token, kind)
}

async fn blast_news_email(pool: &PgPool, news_text: &str) -> Result<(), String> {
    // First line as headline, rest as body
    let mut lines = news_text.splitn(2, '\n');
    let headline = lines.next().unwrap_or("Новости SvoiVPN").trim();
    let headline = if headline.is_empty() { "Новости SvoiVPN" } else { headline };
    let body = lines.next().unwrap_or("").trim();
    let body = if body.is_empty() { news_text } else { body };

    let recipients: Vec<(String, uuid::Uuid)> = sqlx::query_as::<_, (String, uuid::Uuid)>(
        "SELECT email, unsubscribe_token FROM user_credentials \
         WHERE email_verified = true AND notify_news = true"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("DB query failed: {}", e))?;

    info!("[news_blast] sending to {} recipients", recipients.len());

    let mut sent = 0usize;
    let mut failed = 0usize;
    for (i, (email, token)) in recipients.iter().enumerate() {
        let url = unsubscribe_url(token, "news");
        match crate::email::send_news_email(email, headline, body, &url).await {
            Ok(_) => sent += 1,
            Err(e) => {
                failed += 1;
                warn!("[news_blast] failed for {}: {}", email, e);
            }
        }
        // Throttle: 100ms between sends to avoid SMTP quota
        if i < recipients.len() - 1 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    info!("[news_blast] done: sent={} failed={}", sent, failed);
    Ok(())
}

async fn maybe_send_support_reply_email(pool: &PgPool, telegram_id: i64, message: &str) -> Result<(), String> {
    // Look up email + check 10-minute debounce
    let row: Option<(String, uuid::Uuid, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as::<_, (String, uuid::Uuid, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT email, unsubscribe_token, last_support_email_at FROM user_credentials \
             WHERE telegram_id = $1 AND email_verified = true AND notify_support = true"
        )
        .bind(telegram_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("DB query failed: {}", e))?;

    let (email, token, last_at) = match row {
        Some(r) => r,
        None => { return Ok(()); } // No verified email or opted out
    };

    if let Some(t) = last_at {
        let elapsed = chrono::Utc::now().signed_duration_since(t);
        if elapsed.num_minutes() < 10 {
            info!("[support_email] skipping {} (last sent {} min ago)", telegram_id, elapsed.num_minutes());
            return Ok(());
        }
    }

    let url = unsubscribe_url(&token, "support");
    crate::email::send_support_reply_email(&email, message, &url).await?;

    let _ = sqlx::query("UPDATE user_credentials SET last_support_email_at = NOW() WHERE telegram_id = $1")
        .bind(telegram_id)
        .execute(pool)
        .await;
    Ok(())
}

/// GET /web/unsubscribe/{token}?type=news|expiry|support|all
pub async fn web_unsubscribe(
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let token = path.into_inner();
    let kind = query.get("type").map(|s| s.as_str()).unwrap_or("all");

    let column_sql = match kind {
        "news" => "notify_news = false",
        "expiry" => "notify_expiry = false",
        "support" => "notify_support = false",
        "all" => "notify_news = false, notify_expiry = false, notify_support = false",
        _ => return HttpResponse::BadRequest().body("invalid type"),
    };

    let sql = format!("UPDATE user_credentials SET {} WHERE unsubscribe_token = $1 RETURNING email", column_sql);
    let result: Result<Option<(String,)>, _> = sqlx::query_as(&sql)
        .bind(token)
        .fetch_optional(pool.get_ref())
        .await;

    let email = match result {
        Ok(Some((e,))) => e,
        Ok(None) => return HttpResponse::NotFound().body("Ссылка недействительна или устарела."),
        Err(e) => {
            error!("[unsubscribe] DB error: {}", e);
            return HttpResponse::InternalServerError().body("Внутренняя ошибка");
        }
    };

    info!("[unsubscribe] {} unsubscribed from {}", email, kind);

    let kind_label = match kind {
        "news" => "новостей",
        "expiry" => "уведомлений о подписке",
        "support" => "ответов поддержки",
        _ => "всех уведомлений",
    };

    let html = format!(
        r#"<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>Отписка</title></head>
        <body style="background:#0a0a0a;color:#e0e0e0;font-family:-apple-system,sans-serif;padding:60px 20px;text-align:center;">
        <div style="max-width:480px;margin:0 auto;background:#141414;border:1px solid #1e1e1e;border-radius:16px;padding:40px;">
        <h1 style="color:#7C6BFF;margin:0 0 12px;font-size:24px;">Готово ✓</h1>
        <p style="margin:0 0 8px;color:#c4c4c4;">{} больше не будет получать {}.</p>
        <p style="margin:24px 0 0;font-size:13px;color:#666;">Если передумаете — настройки почты в личном кабинете на <a href="https://svoiweb.ru" style="color:#7C6BFF;">svoiweb.ru</a></p>
        </div></body></html>"#,
        html_escape_simple(&email), kind_label
    );

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}

fn html_escape_simple(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// POST /internal/notify/expiry — called by vpn-tg-bot expiry cron
/// Body: { "telegram_id": i64, "kind": "3_days"|"1_day"|"expired" }
pub async fn internal_notify_expiry(
    pool: web::Data<PgPool>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }

    let telegram_id = match body.get("telegram_id").and_then(|v| v.as_i64()) {
        Some(t) => t,
        None => return HttpResponse::BadRequest().json(json!({"error": "telegram_id required"})),
    };
    let kind = match body.get("kind").and_then(|v| v.as_str()) {
        Some(k) if k == "3_days" || k == "1_day" || k == "expired" => k.to_string(),
        _ => return HttpResponse::BadRequest().json(json!({"error": "kind must be 3_days|1_day|expired"})),
    };

    // Get user info: plan, subscription_end
    let user: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as::<_, (String, chrono::DateTime<chrono::Utc>)>(
        "SELECT plan, subscription_end FROM users WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    let (plan, sub_end) = match user {
        Some(u) => u,
        None => return HttpResponse::Ok().json(json!({"status": "skipped", "reason": "user not found"})),
    };

    // Get email + check opt-in
    let creds: Option<(String, uuid::Uuid)> = sqlx::query_as::<_, (String, uuid::Uuid)>(
        "SELECT email, unsubscribe_token FROM user_credentials \
         WHERE telegram_id = $1 AND email_verified = true AND notify_expiry = true"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    let (email, token) = match creds {
        Some(c) => c,
        None => return HttpResponse::Ok().json(json!({"status": "skipped", "reason": "no email or opted out"})),
    };

    // Idempotency check via email_expiry_sent
    let already: Option<(i64,)> = sqlx::query_as::<_, (i64,)>(
        "SELECT id FROM email_expiry_sent WHERE telegram_id = $1 AND kind = $2 AND subscription_end = $3"
    )
    .bind(telegram_id)
    .bind(&kind)
    .bind(sub_end)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    if already.is_some() {
        return HttpResponse::Ok().json(json!({"status": "skipped", "reason": "already sent"}));
    }

    let days_left = (sub_end - chrono::Utc::now()).num_days();
    let url = unsubscribe_url(&token, "expiry");
    match crate::email::send_expiry_email(&email, &kind, &plan, days_left, &url).await {
        Ok(_) => {
            let _ = sqlx::query(
                "INSERT INTO email_expiry_sent (telegram_id, kind, subscription_end) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
            )
            .bind(telegram_id)
            .bind(&kind)
            .bind(sub_end)
            .execute(pool.get_ref())
            .await;
            HttpResponse::Ok().json(json!({"status": "sent"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(json!({"error": e})),
    }
}

pub async fn admin_test_email(path: web::Path<String>, req: HttpRequest) -> HttpResponse {
    let api_key = req.headers().get("x-api-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    let expected = std::env::var("API_KEY").unwrap_or_default();
    if api_key != expected { return HttpResponse::Unauthorized().json(json!({"error": "unauthorized"})); }

    let email = path.into_inner();
    match crate::email::send_test_email(&email).await {
        Ok(_) => HttpResponse::Ok().json(json!({"status": "sent", "to": email})),
        Err(e) => HttpResponse::InternalServerError().json(json!({"error": e})),
    }
}

/// POST /internal/payments — append-only ledger of every subscription extension event.
/// Body: { telegram_id, source, amount_rub?, plan, duration?, days_added, external_id?, metadata? }
/// Fire-and-forget — callers should not depend on this succeeding.
pub async fn internal_log_payment(
    pool: web::Data<PgPool>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }

    let telegram_id = match body.get("telegram_id").and_then(|v| v.as_i64()) {
        Some(t) => t,
        None => return HttpResponse::BadRequest().json(json!({"error": "telegram_id required"})),
    };
    let source = match body.get("source").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return HttpResponse::BadRequest().json(json!({"error": "source required"})),
    };
    let plan = match body.get("plan").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => return HttpResponse::BadRequest().json(json!({"error": "plan required"})),
    };
    let days_added = match body.get("days_added").and_then(|v| v.as_i64()) {
        Some(d) => d as i32,
        None => return HttpResponse::BadRequest().json(json!({"error": "days_added required"})),
    };

    let amount_rub = body.get("amount_rub").and_then(|v| v.as_f64());
    let duration = body.get("duration").and_then(|v| v.as_str()).map(|s| s.to_string());
    let external_id = body.get("external_id").and_then(|v| v.as_str()).map(|s| s.to_string());
    let metadata = body.get("metadata").cloned();

    let result = sqlx::query(
        "INSERT INTO payments (telegram_id, source, amount_rub, plan, duration, days_added, external_id, metadata) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id"
    )
    .bind(telegram_id)
    .bind(&source)
    .bind(amount_rub)
    .bind(&plan)
    .bind(duration.as_deref())
    .bind(days_added)
    .bind(external_id.as_deref())
    .bind(metadata)
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok(row) => {
            let id: i64 = row.get("id");
            info!("[payments] logged id={} tg={} source={} days={}", id, telegram_id, source, days_added);
            HttpResponse::Ok().json(json!({"status": "ok", "id": id}))
        }
        Err(e) => {
            error!("[payments] INSERT error: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "insert failed"}))
        }
    }
}

/// GET /web/me/notifications — current email notification preferences (JWT)
pub async fn web_get_notifications(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let row: Option<(String, bool, bool, bool, bool)> = sqlx::query_as::<_, (String, bool, bool, bool, bool)>(
        "SELECT email, email_verified, notify_news, notify_expiry, notify_support \
         FROM user_credentials WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    match row {
        Some((email, verified, news, expiry, support)) => HttpResponse::Ok().json(json!({
            "has_email": true,
            "email": email,
            "email_verified": verified,
            "notify_news": news,
            "notify_expiry": expiry,
            "notify_support": support,
        })),
        None => HttpResponse::Ok().json(json!({
            "has_email": false,
            "email": null,
            "email_verified": false,
            "notify_news": false,
            "notify_expiry": false,
            "notify_support": false,
        })),
    }
}

/// PATCH /web/me/notifications — update email notification flags (JWT)
/// Body: { "notify_news"?: bool, "notify_expiry"?: bool, "notify_support"?: bool }
pub async fn web_update_notifications(
    pool: web::Data<PgPool>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let news = body.get("notify_news").and_then(|v| v.as_bool());
    let expiry = body.get("notify_expiry").and_then(|v| v.as_bool());
    let support = body.get("notify_support").and_then(|v| v.as_bool());

    if news.is_none() && expiry.is_none() && support.is_none() {
        return HttpResponse::BadRequest().json(json!({"error": "no fields to update"}));
    }

    // Single UPDATE with COALESCE — only touches columns where the new value is not NULL.
    // rows_affected tells us whether the user has a linked email row.
    let result = sqlx::query(
        "UPDATE user_credentials SET \
             notify_news    = COALESCE($2, notify_news), \
             notify_expiry  = COALESCE($3, notify_expiry), \
             notify_support = COALESCE($4, notify_support) \
         WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .bind(news)
    .bind(expiry)
    .bind(support)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() == 0 => {
            HttpResponse::BadRequest().json(json!({"error": "no linked email"}))
        }
        Ok(_) => HttpResponse::Ok().json(json!({"status": "ok"})),
        Err(e) => {
            error!("[web_update_notifications] DB error: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "internal server error"}))
        }
    }
}
