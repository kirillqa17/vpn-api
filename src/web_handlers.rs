use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use serde_json::json;
use sqlx::postgres::PgPool;
use sqlx::Row;
use log::{info, error, warn};
use std::collections::HashMap;
use std::sync::Arc;

use crate::jwt;
use crate::models::{SupportChatRequest, InternalSupportChatRequest, InternalSupportEscalateRequest};
use chrono::Utc;
use uuid::Uuid;

// === Security key validation ===

lazy_static::lazy_static! {
    static ref ADMIN_KEY: String = std::env::var("ADMIN_KEY").unwrap_or_default();
    static ref INTERNAL_KEY: String = std::env::var("INTERNAL_KEY").unwrap_or_default();
    static ref AUTH_ENFORCE: bool = std::env::var("AUTH_ENFORCE").unwrap_or_default() == "true";
}

/// Check admin key. Returns Some(403) if enforcement is on and key is invalid.
pub fn check_admin_key(req: &HttpRequest) -> Option<HttpResponse> {
    if ADMIN_KEY.is_empty() {
        return None;
    }
    let provided = req.headers().get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided == ADMIN_KEY.as_str() {
        return None;
    }
    warn!("[AUTH] Invalid admin key from {:?} path={}", req.peer_addr(), req.path());
    if *AUTH_ENFORCE {
        Some(HttpResponse::Forbidden().json(json!({"error": "forbidden"})))
    } else {
        None
    }
}

/// Check internal key. Returns Some(403) if enforcement is on and key is invalid.
fn check_internal_key(req: &HttpRequest) -> Option<HttpResponse> {
    if INTERNAL_KEY.is_empty() {
        return None;
    }
    let provided = req.headers().get("X-Internal-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided == INTERNAL_KEY.as_str() {
        return None;
    }
    warn!("[AUTH] Invalid internal key from {:?} path={}", req.peer_addr(), req.path());
    if *AUTH_ENFORCE {
        Some(HttpResponse::Forbidden().json(json!({"error": "forbidden"})))
    } else {
        None
    }
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
        return Err(HttpResponse::InternalServerError().json(json!({"error": "internal server error"})));
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
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
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
        return HttpResponse::BadRequest().body("Invalid email");
    }
    if password.len() < 6 {
        return HttpResponse::BadRequest().body("Password must be at least 6 characters");
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
                return HttpResponse::Conflict().body("Email already registered");
            }
            // Not verified — delete old unverified account so they can re-register
            let _ = sqlx::query("DELETE FROM user_credentials WHERE email = $1 AND email_verified = FALSE")
                .bind(&email)
                .execute(pool.get_ref())
                .await;
        }
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
        _ => {}
    }

    // Rate limit
    if check_rate_limit(pool.get_ref(), &email).await {
        return HttpResponse::TooManyRequests().body("Please wait 60 seconds before requesting a new code");
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
        Err(_) => return HttpResponse::InternalServerError().body("Failed to hash password"),
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
        return HttpResponse::InternalServerError().body("Failed to save credentials");
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
        return HttpResponse::InternalServerError().body("Failed to send verification email");
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
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
        Err(e) => return { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    };

    let telegram_id: i64 = cred_row.get("telegram_id");
    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
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
        Ok(None) => return HttpResponse::Unauthorized().body("Invalid email or password"),
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
        Err(_) => return HttpResponse::InternalServerError().body("Invalid stored hash"),
    };

    if Argon2::default().verify_password(data.password.as_bytes(), &parsed_hash).is_err() {
        return HttpResponse::Unauthorized().body("Invalid email or password");
    }

    if !verified {
        return HttpResponse::Forbidden().json(json!({"error": "Email не подтверждён", "needs_verification": true}));
    }

    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
    };

    info!("[auth_email_login] Email login: {} (id={})", email, telegram_id);
    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": telegram_id }))
}

pub async fn auth_forgot_password(
    pool: web::Data<PgPool>,
    data: web::Json<ForgotPasswordRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();

    // Always return success (don't reveal if email exists)
    let response = json!({ "message": "Если аккаунт существует, код отправлен на email" });

    let exists = sqlx::query("SELECT id FROM user_credentials WHERE email = $1 AND email_verified = TRUE")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await;

    if !matches!(exists, Ok(Some(_))) {
        info!("[auth_forgot_password] Email not found or not verified: {}", email);
        return HttpResponse::Ok().json(response);
    }

    if check_rate_limit(pool.get_ref(), &email).await {
        return HttpResponse::Ok().json(response); // Don't reveal rate limit either
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
    HttpResponse::Ok().json(response)
}

pub async fn auth_reset_password(
    pool: web::Data<PgPool>,
    data: web::Json<ResetPasswordRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();
    let code = data.code.trim();
    let new_password = &data.new_password;

    if new_password.len() < 6 {
        return HttpResponse::BadRequest().body("Password must be at least 6 characters");
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
        Err(_) => return HttpResponse::InternalServerError().body("Failed to hash password"),
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

pub async fn auth_telegram_init(pool: web::Data<PgPool>) -> HttpResponse {
    use rand::Rng;
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let result = sqlx::query(
        "INSERT INTO telegram_auth_codes (code, expires_at) VALUES ($1, NOW() + INTERVAL '5 minutes')"
    )
    .bind(&code)
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
        "SELECT telegram_id FROM telegram_auth_codes WHERE code = $1 AND expires_at > NOW()"
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

    match tg_id {
        Some(id) => {
            // Confirmed — generate JWT and cleanup
            let _ = sqlx::query("DELETE FROM telegram_auth_codes WHERE code = $1")
                .bind(&code)
                .execute(pool.get_ref())
                .await;

            let token = match jwt::create_token(id) {
                Ok(t) => t,
                Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
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

// === User info ===
// NOTE: merge endpoints removed (auth_merge_email_account, link_code, merge_by_code)

pub async fn web_get_me(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let user = sqlx::query(
        "SELECT telegram_id, uuid, subscription_end, is_active, created_at, referrals, referral_id, \
         is_used_trial, is_used_ref_bonus, username, plan, sub_link, payed_refs, device_limit, \
         auto_renew, payment_method_id, auto_renew_plan, auto_renew_duration, is_pro, card_last4 \
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
            HttpResponse::Ok().json(json!({
                "telegram_id": row.get::<i64, _>("telegram_id"),
                "uuid": row.get::<uuid::Uuid, _>("uuid").to_string(),
                "subscription_end": row.get::<chrono::DateTime<chrono::Utc>, _>("subscription_end").to_rfc3339(),
                "is_active": row.get::<i32, _>("is_active"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                "referrals": referrals.unwrap_or_default(),
                "referral_id": row.get::<Option<i64>, _>("referral_id"),
                "is_used_trial": row.get::<bool, _>("is_used_trial"),
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
    let prices = json!({
        "base": {
            "1m": std::env::var("BASE_MONTH").unwrap_or_else(|_| "150".to_string()).parse::<i64>().unwrap_or(150),
            "3m": std::env::var("BASE_3_MONTH").unwrap_or_else(|_| "430".to_string()).parse::<i64>().unwrap_or(430),
            "1y": std::env::var("BASE_YEAR").unwrap_or_else(|_| "1500".to_string()).parse::<i64>().unwrap_or(1500),
        },
        "family": {
            "1m": std::env::var("FAMILY_MONTH").unwrap_or_else(|_| "200".to_string()).parse::<i64>().unwrap_or(200),
            "3m": std::env::var("FAMILY_3_MONTH").unwrap_or_else(|_| "570".to_string()).parse::<i64>().unwrap_or(570),
            "1y": std::env::var("FAMILY_YEAR").unwrap_or_else(|_| "1800".to_string()).parse::<i64>().unwrap_or(1800),
        },
        "bsbase": {
            "1m": std::env::var("BSBASE_MONTH").unwrap_or_else(|_| "250".to_string()).parse::<i64>().unwrap_or(250),
            "3m": std::env::var("BSBASE_3_MONTH").unwrap_or_else(|_| "720".to_string()).parse::<i64>().unwrap_or(720),
            "1y": std::env::var("BSBASE_YEAR").unwrap_or_else(|_| "2500".to_string()).parse::<i64>().unwrap_or(2500),
        },
        "bsfamily": {
            "1m": std::env::var("BSFAMILY_MONTH").unwrap_or_else(|_| "300".to_string()).parse::<i64>().unwrap_or(300),
            "3m": std::env::var("BSFAMILY_3_MONTH").unwrap_or_else(|_| "850".to_string()).parse::<i64>().unwrap_or(850),
            "1y": std::env::var("BSFAMILY_YEAR").unwrap_or_else(|_| "2700".to_string()).parse::<i64>().unwrap_or(2700),
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
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
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
        ("family_1m", "FAMILY_MONTH", 200),
        ("family_3m", "FAMILY_3_MONTH", 570),
        ("family_1y", "FAMILY_YEAR", 1800),
        ("bsbase_1m", "BSBASE_MONTH", 250),
        ("bsbase_3m", "BSBASE_3_MONTH", 720),
        ("bsbase_1y", "BSBASE_YEAR", 2500),
        ("bsfamily_1m", "BSFAMILY_MONTH", 300),
        ("bsfamily_3m", "BSFAMILY_3_MONTH", 850),
        ("bsfamily_1y", "BSFAMILY_YEAR", 2700),
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
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
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

    let rows = sqlx::query(
        "SELECT role, content, created_at FROM support_chats WHERE telegram_id = $1 AND role != 'system' AND content NOT LIKE '[SYSTEM]%' ORDER BY created_at ASC LIMIT 100"
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
                let role: String = r.get("role");
                let content: String = r.get("content");
                let created_at: chrono::DateTime<chrono::Utc> = r.get("created_at");
                json!({
                    "role": if role == "assistant" { "ai".to_string() } else { role },
                    "content": content,
                    "created_at": created_at.to_rfc3339()
                })
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
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
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
            error!("[support_chat] ProxyAPI call failed: {}", e);
            return HttpResponse::ServiceUnavailable().body("service temporarily unavailable");
        }
        Ok(resp) if !resp.status().is_success() => {
            error!("[support_chat] ProxyAPI error: {}", resp.status());
            return HttpResponse::ServiceUnavailable().body("service temporarily unavailable");
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
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
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
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
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
                error!("[internal_support_chat] ProxyAPI call failed (iteration {}): {}", iteration, e);
                return HttpResponse::ServiceUnavailable().body("service temporarily unavailable");
            }
            Ok(resp) if !resp.status().is_success() => {
                error!("[internal_support_chat] ProxyAPI error (iteration {}): {}", iteration, resp.status());
                return HttpResponse::ServiceUnavailable().body("service temporarily unavailable");
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
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
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
    let rows = sqlx::query(
        "SELECT DISTINCT ON (sc.telegram_id) \
            sc.telegram_id, sc.role, sc.content, sc.created_at, \
            u.username \
         FROM support_chats sc \
         LEFT JOIN users u ON u.telegram_id = sc.telegram_id \
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

    // Verify user exists
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

// === News ===

pub async fn web_get_news(pool: web::Data<PgPool>) -> HttpResponse {
    let rows = sqlx::query(
        "SELECT id, tg_message_id, text, date, media_url FROM news_posts ORDER BY date DESC LIMIT 20"
    )
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(rows) => {
            let posts: Vec<serde_json::Value> = rows.iter().map(|r| {
                json!({
                    "id": r.get::<i64, _>("id"),
                    "text": r.get::<String, _>("text"),
                    "date": r.get::<chrono::DateTime<chrono::Utc>, _>("date").to_rfc3339(),
                    "media_url": r.get::<Option<String>, _>("media_url"),
                })
            }).collect();
            HttpResponse::Ok().json(posts)
        }
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}

pub async fn internal_save_news(pool: web::Data<PgPool>, body: web::Json<serde_json::Value>, req: HttpRequest) -> HttpResponse {
    if let Some(resp) = check_internal_key(&req) { return resp; }
    let tg_message_id = body.get("tg_message_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let date = body.get("date").and_then(|v| v.as_str()).unwrap_or("");
    let media_url = body.get("media_url").and_then(|v| v.as_str());

    if tg_message_id == 0 || text.is_empty() {
        return HttpResponse::BadRequest().body("tg_message_id and text required");
    }

    let result = sqlx::query(
        "INSERT INTO news_posts (tg_message_id, text, date, media_url) VALUES ($1, $2, $3::timestamptz, $4) ON CONFLICT (tg_message_id) DO NOTHING"
    )
    .bind(tg_message_id)
    .bind(text)
    .bind(date)
    .bind(media_url)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().json(json!({"status": "ok"})),
        Err(e) => { error!("Internal error: {}", e); HttpResponse::InternalServerError().json(json!({"error": "internal server error"})) },
    }
}
