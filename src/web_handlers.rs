use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use serde_json::json;
use sqlx::postgres::PgPool;
use sqlx::Row;
use log::{info, error};
use std::collections::HashMap;
use std::sync::Arc;

use crate::jwt;
use crate::models::SupportChatRequest;
use chrono::Utc;
use uuid::Uuid;

// === Auth endpoints ===

#[derive(Deserialize)]
pub struct TelegramAuthRequest {
    #[serde(rename = "initData")]
    init_data: String,
}

/// Auto-register a new user (same logic as create_user in main.rs)
async fn auto_register_user(pool: &PgPool, telegram_id: i64, username: Option<String>, referral_id: Option<i64>) -> Result<(), HttpResponse> {
    let username = username.unwrap_or_else(|| format!("user_{}", telegram_id));
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
            HttpResponse::InternalServerError().body(e.to_string())
        })?;

    if !api_response.status().is_success() {
        error!("[auto_register] Remnawave error for {}: {}", telegram_id, api_response.status());
        return Err(HttpResponse::InternalServerError().body("Remnawave API error"));
    }

    let json_response: serde_json::Value = api_response.json().await.map_err(|e| {
        error!("[auto_register] Failed to parse Remnawave response: {}", e);
        HttpResponse::InternalServerError().body(e.to_string())
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
        HttpResponse::InternalServerError().body(e.to_string())
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
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    }

    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
    };

    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": telegram_id }))
}

pub async fn auth_telegram_login(
    pool: web::Data<PgPool>,
    data: web::Json<HashMap<String, String>>,
) -> HttpResponse {
    let telegram_id = match jwt::validate_telegram_login(&data) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().body("Invalid login data"),
    };

    let exists = sqlx::query("SELECT telegram_id FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await;

    match exists {
        Ok(Some(_)) => {}
        Ok(None) => {
            let username = data.get("username").cloned();
            if let Err(resp) = auto_register_user(pool.get_ref(), telegram_id, username, None).await {
                return resp;
            }
        }
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    }

    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
    };

    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": telegram_id }))
}

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

pub async fn auth_email_register(
    pool: web::Data<PgPool>,
    data: web::Json<EmailRegisterRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();
    let password = &data.password;

    if !email.contains('@') || email.len() < 5 {
        return HttpResponse::BadRequest().body("Invalid email");
    }
    if password.len() < 8 {
        return HttpResponse::BadRequest().body("Password must be at least 8 characters");
    }

    // Check if email already taken
    let exists = sqlx::query("SELECT id FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await;

    match exists {
        Ok(Some(_)) => return HttpResponse::Conflict().body("Email already registered"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
        _ => {}
    }

    // Generate synthetic negative telegram_id
    let synthetic_id: i64 = match sqlx::query_scalar::<_, i64>("SELECT -nextval('email_user_id_seq')")
        .fetch_one(pool.get_ref())
        .await
    {
        Ok(id) => id,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to generate ID: {}", e)),
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

    // Create user in Remnawave + DB (reuse auto_register_user)
    let username = email.split('@').next().unwrap_or("user").to_string();
    if let Err(resp) = auto_register_user(pool.get_ref(), synthetic_id, Some(username), data.referral_id).await {
        return resp;
    }

    // Save credentials
    let result = sqlx::query(
        "INSERT INTO user_credentials (telegram_id, email, password_hash) VALUES ($1, $2, $3)"
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

    let token = match jwt::create_token(synthetic_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
    };

    info!("[auth_email_register] Registered email user {} (id={})", email, synthetic_id);
    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": synthetic_id }))
}

pub async fn auth_email_login(
    pool: web::Data<PgPool>,
    data: web::Json<EmailLoginRequest>,
) -> HttpResponse {
    let email = data.email.trim().to_lowercase();

    let row = match sqlx::query("SELECT telegram_id, password_hash FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::Unauthorized().body("Invalid email or password"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let telegram_id: i64 = row.get("telegram_id");
    let stored_hash: String = row.get("password_hash");

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

    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
    };

    info!("[auth_email_login] Email login: {} (id={})", email, telegram_id);
    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": telegram_id }))
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
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
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
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/// Merge an email account into the current Telegram account.
/// Transfers subscription, payment method, PRO status, etc. from email account to Telegram account.
pub async fn auth_merge_email_account(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    data: web::Json<EmailLoginRequest>,
) -> HttpResponse {
    let tg_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let email = data.email.trim().to_lowercase();

    // Find email account credentials
    let cred_row = match sqlx::query("SELECT telegram_id, password_hash FROM user_credentials WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().body("Email account not found"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let email_user_id: i64 = cred_row.get("telegram_id");
    let stored_hash: String = cred_row.get("password_hash");

    // Can't merge with yourself
    if email_user_id == tg_id {
        return HttpResponse::BadRequest().body("Cannot merge with the same account");
    }

    // Only email accounts (negative ID) can be merged into other accounts
    if email_user_id > 0 {
        return HttpResponse::BadRequest().body("Can only merge email accounts (not Telegram accounts)");
    }

    // Verify password
    use argon2::{Argon2, PasswordVerifier};
    use argon2::password_hash::PasswordHash;

    let parsed_hash = match PasswordHash::new(&stored_hash) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().body("Invalid stored hash"),
    };

    if Argon2::default().verify_password(data.password.as_bytes(), &parsed_hash).is_err() {
        return HttpResponse::Unauthorized().body("Invalid password");
    }

    // Get email account data
    let email_user = match sqlx::query(
        "SELECT subscription_end, is_active, plan, device_limit, auto_renew, payment_method_id, \
         auto_renew_plan, auto_renew_duration, is_pro, card_last4, payed_refs, is_used_trial \
         FROM users WHERE telegram_id = $1"
    )
    .bind(email_user_id)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().body("Email user account not found in users table"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    // Merge: take the best of both accounts
    let email_sub_end: chrono::DateTime<chrono::Utc> = email_user.get("subscription_end");
    let email_is_active: i32 = email_user.get("is_active");
    let email_plan: String = email_user.get("plan");
    let email_device_limit: i64 = email_user.get("device_limit");
    let email_auto_renew: bool = email_user.get("auto_renew");
    let email_payment_method: Option<String> = email_user.get("payment_method_id");
    let email_ar_plan: Option<String> = email_user.get("auto_renew_plan");
    let email_ar_duration: Option<String> = email_user.get("auto_renew_duration");
    let email_is_pro: bool = email_user.get("is_pro");
    let email_card_last4: Option<String> = email_user.get("card_last4");
    let email_payed_refs: i64 = email_user.get("payed_refs");
    let email_is_used_trial: bool = email_user.get("is_used_trial");

    // Update Telegram account with email account's data (take better values)
    let result = sqlx::query(
        "UPDATE users SET \
         subscription_end = GREATEST(subscription_end, $1), \
         is_active = GREATEST(is_active, $2), \
         plan = CASE WHEN $2 > 0 THEN $3 ELSE plan END, \
         device_limit = GREATEST(device_limit, $4), \
         auto_renew = auto_renew OR $5, \
         payment_method_id = COALESCE(payment_method_id, $6), \
         auto_renew_plan = COALESCE(auto_renew_plan, $7), \
         auto_renew_duration = COALESCE(auto_renew_duration, $8), \
         is_pro = is_pro OR $9, \
         card_last4 = COALESCE(card_last4, $10), \
         payed_refs = payed_refs + $11, \
         is_used_trial = is_used_trial OR $12 \
         WHERE telegram_id = $13"
    )
    .bind(email_sub_end)
    .bind(email_is_active)
    .bind(&email_plan)
    .bind(email_device_limit)
    .bind(email_auto_renew)
    .bind(&email_payment_method)
    .bind(&email_ar_plan)
    .bind(&email_ar_duration)
    .bind(email_is_pro)
    .bind(&email_card_last4)
    .bind(email_payed_refs)
    .bind(email_is_used_trial)
    .bind(tg_id)
    .execute(pool.get_ref())
    .await;

    if let Err(e) = result {
        error!("[merge] Failed to update target user {}: {}", tg_id, e);
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    // Move credentials: delete any existing creds for target, then transfer email creds
    let _ = sqlx::query("DELETE FROM user_credentials WHERE telegram_id = $1")
        .bind(tg_id)
        .execute(pool.get_ref())
        .await;
    let _ = sqlx::query("UPDATE user_credentials SET telegram_id = $1 WHERE telegram_id = $2")
        .bind(tg_id)
        .bind(email_user_id)
        .execute(pool.get_ref())
        .await;

    // Update referrals: anyone referred by email account now belongs to tg account
    let _ = sqlx::query("UPDATE users SET referral_id = $1 WHERE referral_id = $2")
        .bind(tg_id)
        .bind(email_user_id)
        .execute(pool.get_ref())
        .await;

    // Move referrals array entries from other users
    let _ = sqlx::query(
        "UPDATE users SET referrals = array_replace(referrals, $1, $2) WHERE $1 = ANY(referrals)"
    )
    .bind(email_user_id)
    .bind(tg_id)
    .execute(pool.get_ref())
    .await;

    // Delete old email user (credentials already moved above, clean any remaining)
    let _ = sqlx::query("DELETE FROM user_credentials WHERE telegram_id = $1")
        .bind(email_user_id)
        .execute(pool.get_ref())
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE telegram_id = $1")
        .bind(email_user_id)
        .execute(pool.get_ref())
        .await;

    // If the merged email account had a 1-hour trial, extend to full 7 days
    if email_is_used_trial && email_plan == "trial" {
        let new_expire = Utc::now() + chrono::Duration::days(7);
        let _ = sqlx::query(
            "UPDATE users SET subscription_end = $1, is_active = 1, plan = 'trial' WHERE telegram_id = $2"
        )
        .bind(new_expire)
        .bind(tg_id)
        .execute(pool.get_ref())
        .await;

        // Update Remnawave expiry
        let tg_uuid = sqlx::query_scalar::<_, uuid::Uuid>("SELECT uuid FROM users WHERE telegram_id = $1")
            .bind(tg_id)
            .fetch_optional(pool.get_ref())
            .await
            .ok()
            .flatten();

        if let Some(uuid) = tg_uuid {
            let _ = HTTP_CLIENT
                .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
                .headers(remnawave_headers())
                .json(&json!({
                    "uuid": uuid.to_string(),
                    "status": "ACTIVE",
                    "expireAt": new_expire.to_rfc3339(),
                    "hwidDeviceLimit": 2,
                }))
                .send()
                .await;
        }

        info!("[merge] Extended trial to 7 days for user {}", tg_id);
    }

    info!("[merge] Merged email account {} ({}) into Telegram account {}", email, email_user_id, tg_id);
    HttpResponse::Ok().json(json!({"status": "ok", "merged_from": email_user_id}))
}

// === Link code for Telegram binding ===

pub async fn generate_link_code(pool: web::Data<PgPool>, req: HttpRequest) -> HttpResponse {
    let telegram_id = match jwt::extract_telegram_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Only for email users
    if telegram_id >= 0 {
        return HttpResponse::BadRequest().body("Already a Telegram account");
    }

    // Generate random 8-char code
    use rand::Rng;
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    // Clean old codes for this user + expired codes (>1 hour)
    let _ = sqlx::query("DELETE FROM link_codes WHERE telegram_id = $1 OR created_at < NOW() - INTERVAL '1 hour'")
        .bind(telegram_id)
        .execute(pool.get_ref())
        .await;

    // Insert new code
    let result = sqlx::query("INSERT INTO link_codes (code, telegram_id) VALUES ($1, $2)")
        .bind(&code)
        .bind(telegram_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => {
            info!("[link_code] Generated code {} for user {}", code, telegram_id);
            HttpResponse::Ok().json(json!({
                "code": code,
                "deeplink": format!("https://t.me/svoivless_bot?start=link_{}", code),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// Resolve link code (called by bot)
pub async fn resolve_link_code(pool: web::Data<PgPool>, path: web::Path<String>) -> HttpResponse {
    let code = path.into_inner();

    let row = match sqlx::query("SELECT telegram_id, created_at FROM link_codes WHERE code = $1")
        .bind(&code)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().body("Invalid or expired code"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let email_user_id: i64 = row.get("telegram_id");
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");

    // Check expiry (1 hour)
    if Utc::now() - created_at > chrono::Duration::hours(1) {
        let _ = sqlx::query("DELETE FROM link_codes WHERE code = $1").bind(&code).execute(pool.get_ref()).await;
        return HttpResponse::Gone().body("Code expired");
    }

    // Return email user info
    let user = sqlx::query(
        "SELECT u.telegram_id, u.plan, u.subscription_end, u.is_active, u.is_used_trial, \
         c.email FROM users u LEFT JOIN user_credentials c ON c.telegram_id = u.telegram_id \
         WHERE u.telegram_id = $1"
    )
    .bind(email_user_id)
    .fetch_optional(pool.get_ref())
    .await;

    match user {
        Ok(Some(row)) => {
            HttpResponse::Ok().json(json!({
                "email_user_id": email_user_id,
                "email": row.get::<Option<String>, _>("email"),
                "plan": row.get::<String, _>("plan"),
                "is_active": row.get::<i32, _>("is_active"),
                "is_used_trial": row.get::<bool, _>("is_used_trial"),
            }))
        }
        Ok(None) => HttpResponse::NotFound().body("Email user not found"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// Delete link code after successful merge (called by bot)
pub async fn delete_link_code(pool: web::Data<PgPool>, path: web::Path<String>) -> HttpResponse {
    let code = path.into_inner();
    let _ = sqlx::query("DELETE FROM link_codes WHERE code = $1").bind(&code).execute(pool.get_ref()).await;
    HttpResponse::Ok().json(json!({"status": "ok"}))
}

// === Internal merge by code (called by bot, no JWT) ===

#[derive(Deserialize)]
pub struct MergeByCodeRequest {
    tg_id: i64,
    code: String,
}

pub async fn internal_merge_by_code(pool: web::Data<PgPool>, data: web::Json<MergeByCodeRequest>) -> HttpResponse {
    let tg_id = data.tg_id;
    let code = &data.code;

    // Resolve code
    let code_row = match sqlx::query("SELECT telegram_id, created_at FROM link_codes WHERE code = $1")
        .bind(code)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().body("Invalid or expired code"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let email_user_id: i64 = code_row.get("telegram_id");
    let created_at: chrono::DateTime<chrono::Utc> = code_row.get("created_at");

    if Utc::now() - created_at > chrono::Duration::hours(1) {
        let _ = sqlx::query("DELETE FROM link_codes WHERE code = $1").bind(code).execute(pool.get_ref()).await;
        return HttpResponse::Gone().body("Code expired");
    }

    if email_user_id >= 0 {
        return HttpResponse::BadRequest().body("Can only merge email accounts");
    }

    // Get email user data
    let email_user = match sqlx::query(
        "SELECT subscription_end, is_active, plan, device_limit, auto_renew, payment_method_id, \
         auto_renew_plan, auto_renew_duration, is_pro, card_last4, payed_refs, is_used_trial \
         FROM users WHERE telegram_id = $1"
    )
    .bind(email_user_id)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().body("Email user not found"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let email_plan: String = email_user.get("plan");
    let email_is_used_trial: bool = email_user.get("is_used_trial");
    let trial_extended = email_is_used_trial && email_plan == "trial";

    // Merge data into TG account
    let _ = sqlx::query(
        "UPDATE users SET \
         subscription_end = GREATEST(subscription_end, $1), \
         is_active = GREATEST(is_active, $2), \
         plan = CASE WHEN $2 > 0 THEN $3 ELSE plan END, \
         device_limit = GREATEST(device_limit, $4), \
         auto_renew = auto_renew OR $5, \
         payment_method_id = COALESCE(payment_method_id, $6), \
         auto_renew_plan = COALESCE(auto_renew_plan, $7), \
         auto_renew_duration = COALESCE(auto_renew_duration, $8), \
         is_pro = is_pro OR $9, \
         card_last4 = COALESCE(card_last4, $10), \
         payed_refs = payed_refs + $11, \
         is_used_trial = is_used_trial OR $12 \
         WHERE telegram_id = $13"
    )
    .bind(email_user.get::<chrono::DateTime<chrono::Utc>, _>("subscription_end"))
    .bind(email_user.get::<i32, _>("is_active"))
    .bind(&email_plan)
    .bind(email_user.get::<i64, _>("device_limit"))
    .bind(email_user.get::<bool, _>("auto_renew"))
    .bind(email_user.get::<Option<String>, _>("payment_method_id"))
    .bind(email_user.get::<Option<String>, _>("auto_renew_plan"))
    .bind(email_user.get::<Option<String>, _>("auto_renew_duration"))
    .bind(email_user.get::<bool, _>("is_pro"))
    .bind(email_user.get::<Option<String>, _>("card_last4"))
    .bind(email_user.get::<i64, _>("payed_refs"))
    .bind(email_is_used_trial)
    .bind(tg_id)
    .execute(pool.get_ref())
    .await;

    // If trial, extend to 7 days
    if trial_extended {
        let new_expire = Utc::now() + chrono::Duration::days(7);
        let _ = sqlx::query(
            "UPDATE users SET subscription_end = $1, is_active = 1, plan = 'trial', is_used_trial = true WHERE telegram_id = $2"
        )
        .bind(new_expire)
        .bind(tg_id)
        .execute(pool.get_ref())
        .await;

        // Update Remnawave
        let tg_uuid = sqlx::query_scalar::<_, uuid::Uuid>("SELECT uuid FROM users WHERE telegram_id = $1")
            .bind(tg_id)
            .fetch_optional(pool.get_ref())
            .await
            .ok()
            .flatten();

        if let Some(uuid) = tg_uuid {
            let _ = HTTP_CLIENT
                .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
                .headers(remnawave_headers())
                .json(&json!({
                    "uuid": uuid.to_string(),
                    "status": "ACTIVE",
                    "trafficLimitBytes": 26843545600_u64,
                    "expireAt": new_expire.to_rfc3339(),
                    "hwidDeviceLimit": 2,
                }))
                .send()
                .await;
        }
    }

    // Get email for response
    let email: String = sqlx::query_scalar("SELECT email FROM user_credentials WHERE telegram_id = $1")
        .bind(email_user_id)
        .fetch_optional(pool.get_ref())
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    // Transfer credentials
    let _ = sqlx::query("DELETE FROM user_credentials WHERE telegram_id = $1").bind(tg_id).execute(pool.get_ref()).await;
    let _ = sqlx::query("UPDATE user_credentials SET telegram_id = $1 WHERE telegram_id = $2")
        .bind(tg_id).bind(email_user_id).execute(pool.get_ref()).await;

    // Update referrals
    let _ = sqlx::query("UPDATE users SET referral_id = $1 WHERE referral_id = $2")
        .bind(tg_id).bind(email_user_id).execute(pool.get_ref()).await;
    let _ = sqlx::query("UPDATE users SET referrals = array_replace(referrals, $1, $2) WHERE $1 = ANY(referrals)")
        .bind(email_user_id).bind(tg_id).execute(pool.get_ref()).await;

    // Delete old email user
    let _ = sqlx::query("DELETE FROM user_credentials WHERE telegram_id = $1").bind(email_user_id).execute(pool.get_ref()).await;
    let _ = sqlx::query("DELETE FROM link_codes WHERE telegram_id = $1").bind(email_user_id).execute(pool.get_ref()).await;
    let _ = sqlx::query("DELETE FROM users WHERE telegram_id = $1").bind(email_user_id).execute(pool.get_ref()).await;

    info!("[merge_by_code] Merged email {} ({}) into TG {}", email, email_user_id, tg_id);
    HttpResponse::Ok().json(json!({"status": "ok", "email": email, "trial_extended": trial_extended}))
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
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
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
        .map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?
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
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        }
        Ok(r) => HttpResponse::InternalServerError().body(format!("Remnawave error: {}", r.status())),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
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
        Ok(r) => HttpResponse::InternalServerError().body(format!("Remnawave error: {}", r.status())),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
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
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        }
        Ok(_) => HttpResponse::Ok().json(json!({ "connected": false })),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
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
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    if row.get::<bool, _>("is_used_trial") {
        return HttpResponse::BadRequest().body("Trial already used");
    }

    // Email users (negative id) get 1 hour, Telegram users get 7 days
    let is_email_user = telegram_id < 0;
    let (interval_sql, duration) = if is_email_user {
        ("INTERVAL '1 hour'", chrono::Duration::hours(1))
    } else {
        ("INTERVAL '7 days'", chrono::Duration::days(7))
    };

    let result = sqlx::query(&format!(
        "UPDATE users SET is_used_trial = true, is_active = 1, plan = 'trial', \
         subscription_end = GREATEST(subscription_end, NOW()) + {} \
         WHERE telegram_id = $1", interval_sql
    ))
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    if let Err(e) = result {
        return HttpResponse::InternalServerError().body(e.to_string());
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
            "trafficLimitBytes": 26843545600_u64,
            "trafficLimitStrategy": "MONTH",
            "expireAt": new_expire.to_rfc3339(),
            "hwidDeviceLimit": 2,
            "tag": "TRIAL",
        }))
        .send()
        .await;

    HttpResponse::Ok().json(json!({"status": "ok", "is_email_trial": is_email_user}))
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

    // Get username for receipt
    let username = sqlx::query_scalar::<_, Option<String>>("SELECT username FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await
        .ok()
        .flatten()
        .flatten()
        .unwrap_or_else(|| format!("{}", telegram_id));

    let description = format!("SvoiVPN {} {} (@{}, {})", tariff_name, duration_name, username, telegram_id);
    let receipt_email = std::env::var("RECEIPT_EMAIL").unwrap_or_else(|_| "receipt@svoivpn.online".to_string());

    let payment_body = json!({
        "amount": {
            "value": format!("{}.00", price),
            "currency": "RUB"
        },
        "confirmation": {
            "type": "redirect",
            "return_url": format!("https://site.svoivpn.online/?payment_status=success")
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
                Err(e) => HttpResponse::InternalServerError().body(format!("Parse error: {}", e)),
            }
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            error!("[web_create_payment] YooKassa error {}: {}", status, body);
            HttpResponse::InternalServerError().body(format!("YooKassa error: {}", status))
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Request error: {}", e)),
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
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        }
        Ok(r) => HttpResponse::InternalServerError().body(format!("YooKassa error: {}", r.status())),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
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
            "description": format!("SvoiVPN {} {}", data.tariff, data.duration),
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
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        }
        Ok(r) => HttpResponse::InternalServerError().body(format!("CryptoPay error: {}", r.status())),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
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
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
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
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
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
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
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
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
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
                "web_invite_link": format!("https://site.svoivpn.online/?ref={}", telegram_id),
                "referrals_count": refs_count,
                "payed_refs": payed_refs,
                "referrals": referral_list,
            }))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// === AI Support endpoints ===

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
            return HttpResponse::InternalServerError().body(e.to_string());
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

    // 4. Call ProxyAPI
    let api_result = HTTP_CLIENT
        .post(format!("{}/chat/completions", *PROXYAPI_BASE_URL))
        .header("Authorization", format!("Bearer {}", *PROXYAPI_KEY))
        .header("Content-Type", "application/json")
        .json(&json!({
            "model": "gemini/gemini-2.0-flash",
            "temperature": 0.3,
            "max_tokens": 1024,
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
            return HttpResponse::InternalServerError().body(e.to_string());
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

    HttpResponse::Ok().json(json!({"status": "escalated"}))
}
