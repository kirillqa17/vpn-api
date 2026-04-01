use actix_web::{HttpRequest, HttpResponse};
use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref JWT_SECRET: String = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    static ref BOT_TOKEN: String = std::env::var("BOT_TOKEN_TG").expect("BOT_TOKEN_TG must be set");
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub telegram_id: i64,
    pub exp: usize,
}

pub fn create_token(telegram_id: i64) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(30))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        telegram_id,
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

pub fn extract_telegram_id(req: &HttpRequest) -> Result<i64, HttpResponse> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| HttpResponse::Unauthorized().body("Missing Authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| HttpResponse::Unauthorized().body("Invalid Authorization format"))?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| HttpResponse::Unauthorized().body("Invalid or expired token"))?;

    Ok(token_data.claims.telegram_id)
}

pub fn validate_init_data(init_data: &str) -> Option<i64> {
    let params: HashMap<String, String> = form_urlencoded::parse(init_data.as_bytes())
        .into_owned()
        .collect();

    let hash = params.get("hash")?;

    let mut sorted_params: Vec<String> = params
        .iter()
        .filter(|(k, _)| k.as_str() != "hash")
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    sorted_params.sort();
    let data_check_string = sorted_params.join("\n");

    let mut secret_hmac = Hmac::<Sha256>::new_from_slice(b"WebAppData").ok()?;
    secret_hmac.update(BOT_TOKEN.as_bytes());
    let secret_key = secret_hmac.finalize().into_bytes();

    let mut hmac = Hmac::<Sha256>::new_from_slice(&secret_key).ok()?;
    hmac.update(data_check_string.as_bytes());
    let computed_hash = hex::encode(hmac.finalize().into_bytes());

    if computed_hash != *hash {
        return None;
    }

    let user_str = params.get("user")?;
    let user: serde_json::Value = serde_json::from_str(user_str).ok()?;
    user["id"].as_i64()
}

pub fn extract_username_from_init_data(init_data: &str) -> Option<String> {
    let params: HashMap<String, String> = form_urlencoded::parse(init_data.as_bytes())
        .into_owned()
        .collect();

    let user_str = params.get("user")?;
    let user: serde_json::Value = serde_json::from_str(user_str).ok()?;
    user["username"].as_str().map(|s| s.to_string())
}

pub fn validate_telegram_login(data: &HashMap<String, String>) -> Option<i64> {
    let hash = data.get("hash")?;

    let mut sorted: Vec<String> = data
        .iter()
        .filter(|(k, _)| k.as_str() != "hash")
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    sorted.sort();
    let check_string = sorted.join("\n");

    let secret = {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(BOT_TOKEN.as_bytes());
        hasher.finalize()
    };

    let mut hmac = Hmac::<Sha256>::new_from_slice(&secret).ok()?;
    hmac.update(check_string.as_bytes());
    let computed = hex::encode(hmac.finalize().into_bytes());

    if computed != *hash {
        return None;
    }

    data.get("id")?.parse().ok()
}
