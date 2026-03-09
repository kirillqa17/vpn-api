use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use serde_json::json;
use sqlx::postgres::PgPool;
use sqlx::Row;
use log::{info, error};
use std::collections::HashMap;

use crate::jwt;

// === Auth endpoints ===

#[derive(Deserialize)]
pub struct TelegramAuthRequest {
    #[serde(rename = "initData")]
    init_data: String,
}

pub async fn auth_telegram(
    pool: web::Data<PgPool>,
    data: web::Json<TelegramAuthRequest>,
) -> HttpResponse {
    let telegram_id = match jwt::validate_init_data(&data.init_data) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().body("Invalid initData"),
    };

    // Verify user exists
    let exists = sqlx::query("SELECT telegram_id FROM users WHERE telegram_id = $1")
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await;

    match exists {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().body("User not registered"),
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
        Ok(None) => return HttpResponse::NotFound().body("User not registered"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    }

    let token = match jwt::create_token(telegram_id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create token"),
    };

    HttpResponse::Ok().json(json!({ "token": token, "telegram_id": telegram_id }))
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

    // Mark trial as used and extend by 7 days
    let result = sqlx::query(
        "UPDATE users SET is_used_trial = true, is_active = 1, plan = 'trial', \
         subscription_end = GREATEST(subscription_end, NOW()) + INTERVAL '7 days' \
         WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    if let Err(e) = result {
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    // Update Remnawave
    let uuid = row.get::<uuid::Uuid, _>("uuid");
    let new_expire = chrono::Utc::now() + chrono::Duration::days(7);

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
        "bsbase" => "Базовый PRO",
        "bsfamily" => "Семейный PRO",
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

    let save_method = data.save_payment_method.unwrap_or(false);

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
        "description": format!("SvoiVPN {} {}", tariff_name, duration_name),
        "save_payment_method": save_method,
        "metadata": {
            "telegram_id": telegram_id,
            "tariff": data.tariff,
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
                "referrals_count": refs_count,
                "payed_refs": payed_refs,
                "referrals": referral_list,
            }))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
