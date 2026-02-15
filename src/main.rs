use actix_web::{web, App, HttpResponse, HttpServer};
use serde_json::json;
use sqlx::postgres::PgPool;
use uuid::Uuid;
use chrono::Utc;
use log::{info, warn, error};
mod models;
use models::{User, NewUser, AddReferralData, ExtendSubscriptionRequest, ExpiringUser, PromoCode, CreatePromoRequest, ValidatePromoRequest, UsePromoRequest, SavePaymentMethodRequest, ToggleAutoRenewRequest, AutoRenewUser, AutoRenewAttemptRequest, ToggleProRequest};
use std::collections::HashMap;
use chrono::{Duration};

lazy_static::lazy_static! {
    static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::new();
    static ref REMNAWAVE_API_BASE: String = std::env::var("REMNAWAVE_API_BASE").unwrap_or_else(|_| "http://localhost:3000/api".to_string());
    static ref REMNAWAVE_API_KEY: String = std::env::var("REMNAWAVE_API_KEY").expect("REMNAWAVE_API_KEY must be set");
}

async fn create_user(pool: web::Data<PgPool>, data: web::Json<NewUser>) -> HttpResponse {
    info!("[create_user] telegram_id={}, username={:?}, referral={:?}", data.telegram_id, data.username, data.referral_id);
    let existing_user = sqlx::query!(
        "SELECT telegram_id FROM users WHERE telegram_id = $1",
        data.telegram_id
    )
    .fetch_optional(pool.get_ref())
    .await;

    match existing_user {
        Ok(Some(_)) => {
            warn!("[create_user] User {} already exists", data.telegram_id);
            return HttpResponse::Conflict().body("User with this telegram_id already exists");
        }
        Err(e) => {
            error!("[create_user] DB error checking user {}: {}", data.telegram_id, e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        _ => {}
    }

    let referral_id = data.referral_id;
    let username = data.username.clone().unwrap_or_else(|| {
        format!("user_{}", data.telegram_id)
    });

    let api_response = match HTTP_CLIENT
        .post(&format!("{}/users", *REMNAWAVE_API_BASE))
        .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", "127.0.0.1")
        .header("X-Forwarded-Proto", "https")
        .json(&json!({
            "username": username,
            "status": "DISABLED",
            "trafficLimitBytes": 0,
            "trafficLimitStrategy": "MONTH",
            "expireAt": Utc::now(),
            "createdAt": Utc::now(),
            "telegramId": data.telegram_id,
            "hwidDeviceLimit": 2,
            "activeInternalSquads": [
                "514a5e22-c599-4f72-81a5-e646f0391db7"
            ],
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("[create_user] Remnawave API call failed for {}: {}", data.telegram_id, e);
            return HttpResponse::InternalServerError().body(format!("Failed to call remnawave API: {}", e));
        }
    };

    if !api_response.status().is_success() {
        error!("[create_user] Remnawave API error for {}: {}", data.telegram_id, api_response.status());
        return HttpResponse::InternalServerError().body(format!("Remnawave API error: {}", api_response.status()));
    }

    let json_response = match api_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => {
            error!("[create_user] Failed to parse Remnawave response for {}: {}", data.telegram_id, e);
            return HttpResponse::InternalServerError().body(format!("Failed to parse API response: {}", e));
        }
    };

    let uuid = Uuid::parse_str(
        json_response["response"]["uuid"]
        .as_str()
        .unwrap()
    ).unwrap();

    let sub_url = json_response["response"]["subscriptionUrl"]
        .as_str()
        .unwrap()
        .to_string();

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let user = match sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (telegram_id, uuid, subscription_end, is_active, created_at, referral_id, is_used_trial, game_points, is_used_ref_bonus, game_attempts, username, sub_link, payed_refs, is_pro)
        VALUES ($1, $2, NOW() + $3 * INTERVAL '1 day', 0, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING *
        "#,
        data.telegram_id,
        uuid,
        0.0,
        Utc::now(),
        referral_id,
        false,
        0i64,
        false,
        0i64,
        username,
        sub_url,
        0,
        false
    )
    .fetch_one(&mut *tx)
    .await {
        Ok(user) => user,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    if let Some(referral_id) = referral_id {
        let _ = sqlx::query!(
            r#"
            UPDATE users 
            SET referrals = array_append(referrals, $1)
            WHERE telegram_id = $2
            "#,
            user.telegram_id,
            referral_id
        )
        .execute(&mut *tx)
        .await;
    }

    if let Err(e) = tx.commit().await {
        error!("[create_user] TX commit failed for {}: {}", data.telegram_id, e);
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    info!("[create_user] Successfully created user {} (uuid={})", user.telegram_id, user.uuid);
    HttpResponse::Ok().json(user)
}


async fn list_users(pool: web::Data<PgPool>) -> HttpResponse {
    let telegram_ids: Vec<i64> = match sqlx::query_scalar!("SELECT telegram_id FROM users")
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(ids) => ids,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    HttpResponse::Ok().json(telegram_ids)
}

async fn extend_subscription(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
    request: web::Json<ExtendSubscriptionRequest>,
) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    let days = request.days;
    let plan = request.plan.clone();
    info!("[extend_subscription] telegram_id={}, days={}, plan={}", telegram_id, days, plan);

    let user = match sqlx::query!(
        "SELECT * FROM users WHERE telegram_id = $1",
        telegram_id
    )
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(record) => record,
        Err(_) => {
            warn!("[extend_subscription] User {} not found", telegram_id);
            return HttpResponse::NotFound().body("User not found");
        }
    };

    let uuid = user.uuid;

    let device_limit = match plan.as_str() {
        "base" | "bsbase" => 2,
        "family" | "bsfamily" => 10,
        _ => 2,
    };

    let traffic_limit: u64 = match plan.as_str() {
        "base" | "bsbase" => 0,
        "family" | "bsfamily" => 0,
        "trial" => 26843545600,
        _ => 0,
    };

    let tag = match plan.as_str(){
        "base" | "bsbase" => "PAID",
        "family" | "bsfamily" => "PAID",
        "trial" => "TRIAL",
        "free" => "FREE",
        _ => "UNKNOWN",
    };

    let is_pro = user.is_pro;
    let mut squad_list = vec!["514a5e22-c599-4f72-81a5-e646f0391db7".to_string()];
    if plan.starts_with("bs") {
        squad_list.push("9e60626e-32a8-4d91-a2f8-2aa3fecf7b23".to_string());
    }
    if is_pro {
        squad_list.push("b6a4e86b-b769-4c86-a2d9-f31bbe645029".to_string());
    }
    let squads = json!(squad_list);
    info!("[extend_subscription] User {} squads={:?}, is_pro={}, tag={}", telegram_id, squad_list, is_pro, tag);

    let now_utc = Utc::now();
    let plan_changed = user.plan != plan && plan != "trial" && plan != "free";
    let effective_start_time = if plan_changed {
        now_utc
    } else {
        std::cmp::max(user.subscription_end, now_utc)
    };
    let expire_at = effective_start_time + Duration::days(days.into());
    let expire_at_str = expire_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let api_response = match HTTP_CLIENT
        .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
        .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", "127.0.0.1")
        .header("X-Forwarded-Proto", "https")
        .json(&json!({
            "uuid": uuid,
            "status": "ACTIVE",
            "trafficLimitBytes": traffic_limit,
            "trafficLimitStrategy": "MONTH",
            "activeUserInbounds": [
                "d92c68b5-41e9-47d0-b7ee-89e7c8640a59"
            ],
            "activeInternalSquads": squads,
            "tag": tag,
            "expireAt": expire_at_str,
            "telegramId": user.telegram_id,
            "hwidDeviceLimit": device_limit
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("[extend_subscription] Remnawave API call failed for {}: {}", telegram_id, e);
            return HttpResponse::InternalServerError().body(format!("Failed to call remnawave API: {}", e));
        }
    };

    if !api_response.status().is_success() {
        error!("[extend_subscription] Remnawave API error for {}: {}", telegram_id, api_response.status());
        return HttpResponse::InternalServerError().body(format!("Remnawave API error: {}", api_response.status()));
    }

    let result = if plan_changed {
        sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET
                subscription_end = NOW() + $1 * INTERVAL '1 day',
                is_active = 1,
                plan = $2
            WHERE telegram_id = $3
            RETURNING *
            "#,
            days as i32,
            plan,
            telegram_id
        )
        .fetch_one(pool.get_ref())
        .await
    } else {
        sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET
                subscription_end = GREATEST(subscription_end, NOW()) + $1 * INTERVAL '1 day',
                is_active = 1,
                plan = $2
            WHERE telegram_id = $3
            RETURNING *
            "#,
            days as i32,
            plan,
            telegram_id
        )
        .fetch_one(pool.get_ref())
        .await
    };
    match result {
        Ok(user) => {
            info!("[extend_subscription] Success for user {}: plan={}, sub_end={}", user.telegram_id, user.plan, user.subscription_end);
            HttpResponse::Ok().json(json!({
                "telegram_id": user.telegram_id,
                "uuid": uuid,
                "subscription_end": user.subscription_end,
                "is_active": user.is_active,
                "plan":user.plan
            }))
        },
        Err(e) => {
            error!("[extend_subscription] DB update failed for {}: {}", telegram_id, e);
            return HttpResponse::InternalServerError().body("Failed to update database");
        }
    }

}


async fn add_referral(pool: web::Data<PgPool>, data: web::Json<AddReferralData>) -> HttpResponse {
    let referral_id = data.referral_id;
    let referred_telegram_id = data.referred_telegram_id;
    info!("[add_referral] referrer={}, referred={}", referral_id, referred_telegram_id);

    // Проверяем, что пользователь еще не был приглашен кем-либо
    let existing_referral = match sqlx::query!(
        r#"
        SELECT referral_id FROM users WHERE telegram_id = $1
        "#,
        referred_telegram_id
    )
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(record) => record,
        Err(_) => return HttpResponse::BadRequest().body("This user has already been invited"),
    };

    // Если у пользователя уже есть referral_id, значит он уже был приглашен
    if existing_referral.referral_id.is_some() {
        return HttpResponse::BadRequest().body("This user has already been invited by someone else");
    }

    let referrals_record = match sqlx::query!(
        r#"
        SELECT referrals FROM users WHERE telegram_id = $1
        "#,
        referral_id
    )
    .fetch_one(pool.get_ref())
    .await{
        Ok(record) => record,
        Err(_) => return HttpResponse::BadRequest().body("Error collecting referrals")
    };

    // Проверяем, есть ли уже этот реферал в массиве referrals
    if let Some(referrals) = referrals_record.referrals {
        if referrals.contains(&referred_telegram_id) {
            return HttpResponse::BadRequest().body("This referral is already added");
        }
    }

    // Обновляем пользователя, добавляем в массив рефералов
    let result = match sqlx::query!(
        r#"
        UPDATE users 
        SET referrals = array_append(referrals, $1)
        WHERE telegram_id = $2
        "#,
        referred_telegram_id,
        referral_id
    )
    .execute(pool.get_ref())
    .await
    {
        Ok(_) => {
            // Теперь обновляем referral_id для пользователя, которого пригласили
            match sqlx::query!(
                r#"
                UPDATE users
                SET referral_id = $1
                WHERE telegram_id = $2
                "#,
                referral_id,
                referred_telegram_id
            )
            .execute(pool.get_ref())
            .await {
                Ok(_) => HttpResponse::Ok().body("Referral added successfully and referral_id updated"),
                Err(e) => HttpResponse::InternalServerError().body(format!("Error updating referral_id: {}", e)),
            }
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Error adding referral: {}", e)),
    };

    result
}

async fn get_user_info(pool: web::Data<PgPool>, telegram_id: web::Path<i64>) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();

    let result = sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users WHERE telegram_id = $1
        "#,
        telegram_id
    )
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(_) => HttpResponse::NotFound().body("User not found"),
    }
}

async fn trial(pool: web::Data<PgPool>,telegram_id: web::Path<i64>, data: web::Json<bool>) -> HttpResponse {
    let is_used_trial = data.into_inner();
    let telegram_id = telegram_id.into_inner();
    info!("[trial] telegram_id={}, is_used_trial={}", telegram_id, is_used_trial);
    let result = match sqlx::query!(
        r#"
        UPDATE users 
        SET is_used_trial = $1
        WHERE telegram_id = $2
        "#,
        is_used_trial,
        telegram_id
    )
    .execute(pool.get_ref())
    .await {
        Ok(result) => {
            if result.rows_affected() == 0 {
                HttpResponse::NotFound().body("User not found")
            }   
            else {
                HttpResponse::Ok().body("Trial status updated successfully")
            }
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to update trial status")
    };
    result
}

async fn ref_bonus(pool: web::Data<PgPool>,telegram_id: web::Path<i64>, data: web::Json<bool>) -> HttpResponse {
    let is_used_trial = data.into_inner();
    let telegram_id = telegram_id.into_inner();
    info!("[ref_bonus] telegram_id={}, status={}", telegram_id, is_used_trial);
    let result = match sqlx::query!(
        r#"
        UPDATE users 
        SET is_used_ref_bonus = $1
        WHERE telegram_id = $2
        "#,
        is_used_trial,
        telegram_id
    )
    .execute(pool.get_ref())
    .await {
        Ok(result) => {
            if result.rows_affected() == 0 {
                HttpResponse::NotFound().body("User not found")
            }   
            else {
                HttpResponse::Ok().body("Referral bonus status updated successfully")
            }
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to update referral bonus status")
    };
    result
}


async fn check_connection(telegram_id: web::Path<i64>) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    info!("[check_connection] telegram_id={}", telegram_id);

    let api_response = match HTTP_CLIENT
    .get(&format!("{}/users/by-telegram-id/{}", *REMNAWAVE_API_BASE, telegram_id))
    .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
    .header("Content-Type", "application/json")
    .header("X-Forwarded-For", "127.0.0.1")
    .header("X-Forwarded-Proto", "https")
    .send()
    .await
    {
        Ok(resp) => resp,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to call remnawave API: {}", e)),
    };

    if !api_response.status().is_success() {
        return HttpResponse::InternalServerError().body(format!("Remnawave API error: {}", api_response.status()));
    }

    let json_response = match api_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to parse API response: {}", e)),
    };

    let first_connected = json_response["response"][0]["firstConnectedAt"].as_str();

    let connected = match first_connected {
        Some(_) => true,    
        None => false      
    };
    
    HttpResponse::Ok().json(json!({ "connected": connected }))
}

async fn get_expiring_users(
    pool: web::Data<PgPool>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let days_before = query
        .get("days")
        .and_then(|d| d.parse::<i64>().ok())
        .unwrap_or(1);
    info!("[get_expiring_users] days_before={}", days_before);
    let threshold_date = Utc::now() + chrono::Duration::days(days_before);

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let users = match sqlx::query_as!(
        ExpiringUser,
        r#"
        SELECT telegram_id, subscription_end, username, plan
        FROM users 
        WHERE 
            is_active = 1 AND 
            subscription_end BETWEEN NOW() AND $1
        ORDER BY subscription_end ASC
        "#,
        threshold_date
    )
    .fetch_all(&mut *tx)
    .await {
        Ok(users) => users,
        Err(e) => {
            let _ = tx.rollback().await;
            return HttpResponse::InternalServerError().body(e.to_string());
        }
    };

    if users.is_empty() {
        let _ = tx.commit().await;
        return HttpResponse::Ok().json(users);
    }

    let telegram_ids: Vec<i64> = users.iter().map(|u| u.telegram_id).collect();
    info!("[get_expiring_users] Found {} expiring users: {:?}", users.len(), telegram_ids);

    match sqlx::query!(
        r#"
        UPDATE users
        SET is_active = 2
        WHERE telegram_id = ANY($1)
        "#,
        &telegram_ids
    )
    .execute(&mut *tx)
    .await {
        Ok(_) => (),
        Err(e) => {
            let _ = tx.rollback().await;
            return HttpResponse::InternalServerError().body(e.to_string());
        }
    };
    
    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(e.to_string());
    }
    
    HttpResponse::Ok().json(users)
}

async fn get_expired_users(pool: web::Data<PgPool>) -> HttpResponse {
    info!("[get_expired_users] Checking for expired users");
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let users = match sqlx::query_as!(
        ExpiringUser,
        r#"
        SELECT telegram_id, subscription_end, username, plan
    FROM users 
        WHERE 
            is_active = 2 AND 
            subscription_end < NOW()
        ORDER BY subscription_end ASC
        "#
    )
    .fetch_all(&mut *tx)
    .await {
        Ok(users) => users,
        Err(e) => {
            let _ = tx.rollback().await;
            return HttpResponse::InternalServerError().body(e.to_string());
        }
    };

    if users.is_empty() {
        let _ = tx.commit().await;
        return HttpResponse::Ok().json(users);
    }

    let telegram_ids: Vec<i64> = users.iter().map(|u| u.telegram_id).collect();
    
    match sqlx::query!(
        r#"
        UPDATE users
        SET is_active = 0
        WHERE telegram_id = ANY($1)
        "#,
        &telegram_ids
    )
    .execute(&mut *tx)
    .await {
        Ok(_) => (),
        Err(e) => {
            let _ = tx.rollback().await;
            return HttpResponse::InternalServerError().body(e.to_string());
        }
    };
    
    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    HttpResponse::Ok().json(users)
}

async fn payed_refs(pool: web::Data<PgPool>,telegram_id: web::Path<i64>, data: web::Json<i64>) -> HttpResponse {
    let is_used_trial = data.into_inner();
    let telegram_id = telegram_id.into_inner();
    info!("[payed_refs] telegram_id={}, amount={}", telegram_id, is_used_trial);
    let result = match sqlx::query!(
        r#"
        UPDATE users 
        SET payed_refs = $1
        WHERE telegram_id = $2
        "#,
        is_used_trial,
        telegram_id
    )
    .execute(pool.get_ref())
    .await {
        Ok(result) => {
            if result.rows_affected() == 0 {
                HttpResponse::NotFound().body("User not found")
            }   
            else {
                HttpResponse::Ok().body("Payed refs updated successfully")
            }
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to update payed refs")
    };
    result
}

async fn temp_disable_device_limit(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    info!("[temp_disable_device_limit] telegram_id={}", telegram_id);

    let user = match sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE telegram_id = $1",
        telegram_id
    )
    .fetch_one(pool.get_ref())
    .await {
        Ok(user) => user,
        Err(_) => return HttpResponse::NotFound().body("User not found"),
    };

    // Сохраняем оригинальное значение в глобальной мапе
    let original_limit = user.device_limit;
    // Получаем uuid пользователя
    let uuid = user.uuid;

    // Устанавливаем временный лимит в 0
    let api_response = match HTTP_CLIENT
        .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
        .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", "127.0.0.1")
        .header("X-Forwarded-Proto", "https")
        .json(&json!({
            "uuid": uuid,
            "hwidDeviceLimit": 0
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to call remnawave API: {}", e)),
    };

    if !api_response.status().is_success() {
        return HttpResponse::InternalServerError().body(format!("Remnawave API error: {}", api_response.status()));
    }

    info!("[temp_disable_device_limit] Disabled limit for user {}, original={}, restoring in 30min", telegram_id, original_limit);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(30 * 60)).await;
        info!("[temp_disable_device_limit] Restoring device limit {} for uuid={}", original_limit, uuid);
        let _ = HTTP_CLIENT
            .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
            .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
            .header("Content-Type", "application/json")
            .header("X-Forwarded-For", "127.0.0.1")
            .header("X-Forwarded-Proto", "https")
            .json(&json!({
                "uuid": uuid,
                "hwidDeviceLimit": original_limit
            }))
            .send()
            .await;
    });

    HttpResponse::Ok().json(json!({
        "message": "Device limit temporarily set to 0 for 30 minutes",
        "original_limit": original_limit,
        "telegram_id": telegram_id
    }))
}

async fn get_devices(telegram_id: web::Path<i64>) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    info!("[get_devices] telegram_id={}", telegram_id);

    let api_response = match HTTP_CLIENT
    .get(&format!("{}/users/by-telegram-id/{}", *REMNAWAVE_API_BASE, telegram_id))
    .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
    .header("Content-Type", "application/json")
    .header("X-Forwarded-For", "127.0.0.1")
    .header("X-Forwarded-Proto", "https")
    .send()
    .await
    {
        Ok(resp) => resp,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to call remnawave API get user by tg_id: {}", e)),
    };

    if !api_response.status().is_success() {
        return HttpResponse::InternalServerError().body(format!("Remnawave API get user by tg_id error: {}", api_response.status()));
    }

    let json_response = match api_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to parse API response: {}", e)),
    };

    let uuid_str = match json_response["response"][0]["uuid"].as_str() {
        Some(s) => s,
        None => {
            return HttpResponse::InternalServerError()
                .body("Failed to parse UUID from user API response");
        }
    };

    let api_response = match HTTP_CLIENT
    .get(&format!("{}/hwid/devices/{}", *REMNAWAVE_API_BASE, uuid_str))
    .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
    .header("Content-Type", "application/json")
    .header("X-Forwarded-For", "127.0.0.1")
    .header("X-Forwarded-Proto", "https")
    .send()
    .await
    {
        Ok(resp) => resp,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to call devices remnawave API: {}", e)),
    };

    if !api_response.status().is_success() {
        return HttpResponse::InternalServerError().body(format!("Remnawave devices API error: {}", api_response.status()));
    }

    let json_response = match api_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to parse API response: {}", e)),
    };

    let devices_amount = match json_response["response"]["total"].as_u64() {
        Some(n) => n,
        None => {   
            return HttpResponse::InternalServerError()
                .body("Failed to parse devices amount from user API response");
        }
    };
    
    HttpResponse::Ok().json(json!({ "devices_amount": devices_amount }))
}

async fn create_promo(pool: web::Data<PgPool>, data: web::Json<CreatePromoRequest>) -> HttpResponse {
    info!("[create_promo] code={}, discount={}%, tariffs={:?}, max_uses={}", data.code, data.discount_percent, data.applicable_tariffs, data.max_uses);
    let result = sqlx::query_as::<_, PromoCode>(
        "INSERT INTO promo_codes (code, discount_percent, applicable_tariffs, max_uses) VALUES ($1, $2, $3, $4) RETURNING *"
    )
    .bind(&data.code)
    .bind(data.discount_percent)
    .bind(&data.applicable_tariffs)
    .bind(data.max_uses)
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok(promo) => HttpResponse::Ok().json(promo),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to create promo code: {}", e)),
    }
}

async fn list_promos(pool: web::Data<PgPool>) -> HttpResponse {
    let result = sqlx::query_as::<_, PromoCode>(
        "SELECT * FROM promo_codes ORDER BY created_at DESC"
    )
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(promos) => HttpResponse::Ok().json(promos),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to list promo codes: {}", e)),
    }
}

async fn deactivate_promo(pool: web::Data<PgPool>, code: web::Path<String>) -> HttpResponse {
    let code = code.into_inner();
    info!("[deactivate_promo] code={}", code);
    let result = sqlx::query("UPDATE promo_codes SET is_active = false WHERE code = $1")
        .bind(&code)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                HttpResponse::NotFound().body("Promo code not found")
            } else {
                HttpResponse::Ok().json(json!({"status": "deactivated", "code": code}))
            }
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to deactivate promo code: {}", e)),
    }
}

async fn validate_promo(pool: web::Data<PgPool>, data: web::Json<ValidatePromoRequest>) -> HttpResponse {
    info!("[validate_promo] code={}, tariff={}, telegram_id={}", data.code, data.tariff, data.telegram_id);
    let promo = sqlx::query_as::<_, PromoCode>(
        "SELECT * FROM promo_codes WHERE code = $1"
    )
    .bind(&data.code)
    .fetch_optional(pool.get_ref())
    .await;

    let promo = match promo {
        Ok(Some(p)) => p,
        Ok(None) => return HttpResponse::Ok().json(json!({"valid": false, "reason": "Промокод не найден"})),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    if !promo.is_active {
        return HttpResponse::Ok().json(json!({"valid": false, "reason": "Промокод деактивирован"}));
    }

    if promo.current_uses >= promo.max_uses {
        return HttpResponse::Ok().json(json!({"valid": false, "reason": "Промокод исчерпан"}));
    }

    if !data.tariff.is_empty() && !promo.applicable_tariffs.contains(&data.tariff) {
        return HttpResponse::Ok().json(json!({"valid": false, "reason": "Промокод не применим к этому тарифу"}));
    }

    let already_used: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM promo_usages WHERE promo_code_id = $1 AND telegram_id = $2"
    )
    .bind(promo.id)
    .bind(data.telegram_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    match already_used {
        Some(_) => HttpResponse::Ok().json(json!({"valid": false, "reason": "Вы уже использовали этот промокод"})),
        None => HttpResponse::Ok().json(json!({"valid": true, "discount_percent": promo.discount_percent, "applicable_tariffs": promo.applicable_tariffs})),
    }
}

async fn use_promo(pool: web::Data<PgPool>, data: web::Json<UsePromoRequest>) -> HttpResponse {
    info!("[use_promo] code={}, telegram_id={}", data.code, data.telegram_id);
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let promo: Option<(i32,)> = match sqlx::query_as(
        "SELECT id FROM promo_codes WHERE code = $1 AND is_active = true"
    )
    .bind(&data.code)
    .fetch_optional(&mut *tx)
    .await {
        Ok(p) => p,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let promo_id = match promo {
        Some((id,)) => id,
        None => return HttpResponse::NotFound().body("Promo code not found or inactive"),
    };

    if let Err(e) = sqlx::query(
        "INSERT INTO promo_usages (promo_code_id, telegram_id) VALUES ($1, $2)"
    )
    .bind(promo_id)
    .bind(data.telegram_id)
    .execute(&mut *tx)
    .await {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().body(format!("Failed to record promo usage: {}", e));
    }

    if let Err(e) = sqlx::query(
        "UPDATE promo_codes SET current_uses = current_uses + 1 WHERE id = $1"
    )
    .bind(promo_id)
    .execute(&mut *tx)
    .await {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().body(format!("Failed to update promo usage count: {}", e));
    }

    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    HttpResponse::Ok().json(json!({"status": "ok"}))
}

async fn save_payment_method(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
    data: web::Json<SavePaymentMethodRequest>,
) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    info!("[save_payment_method] telegram_id={}, plan={}, duration={}", telegram_id, data.plan, data.duration);
    let result = sqlx::query(
        "UPDATE users SET payment_method_id = $1, auto_renew_plan = $2, auto_renew_duration = $3 WHERE telegram_id = $4"
    )
    .bind(&data.payment_method_id)
    .bind(&data.plan)
    .bind(&data.duration)
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                HttpResponse::NotFound().body("User not found")
            } else {
                HttpResponse::Ok().json(json!({"status": "ok"}))
            }
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to save payment method: {}", e)),
    }
}

async fn delete_payment_method(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    info!("[delete_payment_method] telegram_id={}", telegram_id);
    let result = sqlx::query(
        "UPDATE users SET payment_method_id = NULL, auto_renew = FALSE, auto_renew_plan = NULL, auto_renew_duration = NULL, auto_renew_fail_count = 0 WHERE telegram_id = $1"
    )
    .bind(telegram_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                HttpResponse::NotFound().body("User not found")
            } else {
                HttpResponse::Ok().json(json!({"status": "ok"}))
            }
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to delete payment method: {}", e)),
    }
}

async fn toggle_auto_renew(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
    data: web::Json<ToggleAutoRenewRequest>,
) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    info!("[toggle_auto_renew] telegram_id={}, auto_renew={}, plan={:?}, duration={:?}", telegram_id, data.auto_renew, data.plan, data.duration);

    if data.auto_renew {
        // Check that payment_method_id exists
        let user: Option<(Option<String>,)> = match sqlx::query_as(
            "SELECT payment_method_id FROM users WHERE telegram_id = $1"
        )
        .bind(telegram_id)
        .fetch_optional(pool.get_ref())
        .await {
            Ok(u) => u,
            Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
        };

        match user {
            None => return HttpResponse::NotFound().body("User not found"),
            Some((None,)) => return HttpResponse::BadRequest().body("No payment method saved. Pay with card first."),
            _ => {}
        }

        let plan = match &data.plan {
            Some(p) => p,
            None => return HttpResponse::BadRequest().body("plan is required when enabling auto_renew"),
        };
        let duration = match &data.duration {
            Some(d) => d,
            None => return HttpResponse::BadRequest().body("duration is required when enabling auto_renew"),
        };

        let result = sqlx::query(
            "UPDATE users SET auto_renew = TRUE, auto_renew_plan = $1, auto_renew_duration = $2, auto_renew_fail_count = 0 WHERE telegram_id = $3"
        )
        .bind(plan)
        .bind(duration)
        .bind(telegram_id)
        .execute(pool.get_ref())
        .await;

        match result {
            Ok(_) => HttpResponse::Ok().json(json!({"status": "ok", "auto_renew": true})),
            Err(e) => HttpResponse::InternalServerError().body(format!("Failed to enable auto_renew: {}", e)),
        }
    } else {
        let result = sqlx::query(
            "UPDATE users SET auto_renew = FALSE WHERE telegram_id = $1"
        )
        .bind(telegram_id)
        .execute(pool.get_ref())
        .await;

        match result {
            Ok(_) => HttpResponse::Ok().json(json!({"status": "ok", "auto_renew": false})),
            Err(e) => HttpResponse::InternalServerError().body(format!("Failed to disable auto_renew: {}", e)),
        }
    }
}

async fn get_auto_renew_users(
    pool: web::Data<PgPool>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let days_before = query
        .get("days")
        .and_then(|d| d.parse::<i64>().ok())
        .unwrap_or(1);

    let threshold_date = Utc::now() + Duration::days(days_before);

    let users = match sqlx::query_as::<_, AutoRenewUser>(
        r#"
        SELECT telegram_id, payment_method_id, auto_renew_plan, auto_renew_duration,
               subscription_end, plan, username, auto_renew_fail_count
        FROM users
        WHERE auto_renew = TRUE
          AND payment_method_id IS NOT NULL
          AND is_active IN (1, 2)
          AND subscription_end BETWEEN NOW() AND $1
          AND (auto_renew_last_attempt IS NULL OR auto_renew_last_attempt < NOW() - INTERVAL '12 hours')
        ORDER BY subscription_end ASC
        "#
    )
    .bind(threshold_date)
    .fetch_all(pool.get_ref())
    .await {
        Ok(users) => users,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to get auto_renew users: {}", e)),
    };

    HttpResponse::Ok().json(users)
}

async fn record_auto_renew_attempt(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
    data: web::Json<AutoRenewAttemptRequest>,
) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    info!("[record_auto_renew_attempt] telegram_id={}, success={}", telegram_id, data.success);

    if data.success {
        let result = sqlx::query(
            "UPDATE users SET auto_renew_fail_count = 0, auto_renew_last_attempt = NOW() WHERE telegram_id = $1"
        )
        .bind(telegram_id)
        .execute(pool.get_ref())
        .await;

        match result {
            Ok(_) => HttpResponse::Ok().json(json!({"status": "ok"})),
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        }
    } else {
        // Increment fail count and update last_attempt
        let result = sqlx::query(
            r#"
            UPDATE users
            SET auto_renew_fail_count = auto_renew_fail_count + 1,
                auto_renew_last_attempt = NOW(),
                auto_renew = CASE WHEN auto_renew_fail_count + 1 >= 3 THEN FALSE ELSE auto_renew END
            WHERE telegram_id = $1
            RETURNING auto_renew_fail_count, auto_renew
            "#
        )
        .bind(telegram_id)
        .execute(pool.get_ref())
        .await;

        match result {
            Ok(_) => HttpResponse::Ok().json(json!({"status": "ok"})),
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        }
    }
}

async fn toggle_pro(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
    data: web::Json<ToggleProRequest>,
) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    let enable = data.is_pro;
    let pro_squad = "b6a4e86b-b769-4c86-a2d9-f31bbe645029";
    info!("[toggle_pro] telegram_id={}, enable={}", telegram_id, enable);

    let user = match sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE telegram_id = $1",
        telegram_id
    )
    .fetch_one(pool.get_ref())
    .await {
        Ok(user) => user,
        Err(_) => {
            warn!("[toggle_pro] User {} not found", telegram_id);
            return HttpResponse::NotFound().body("User not found");
        }
    };

    // Получаем текущие сквады пользователя из Remnawave
    let get_response = match HTTP_CLIENT
        .get(&format!("{}/users/by-telegram-id/{}", *REMNAWAVE_API_BASE, telegram_id))
        .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", "127.0.0.1")
        .header("X-Forwarded-Proto", "https")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("[toggle_pro] Failed to get user {} from Remnawave: {}", telegram_id, e);
            return HttpResponse::InternalServerError().body(format!("Failed to get user from remnawave: {}", e));
        }
    };

    if !get_response.status().is_success() {
        error!("[toggle_pro] Remnawave GET error for {}: {}", telegram_id, get_response.status());
        return HttpResponse::InternalServerError().body(format!("Remnawave API get error: {}", get_response.status()));
    }

    let json_response = match get_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => {
            error!("[toggle_pro] Failed to parse Remnawave response for {}: {}", telegram_id, e);
            return HttpResponse::InternalServerError().body(format!("Failed to parse response: {}", e));
        }
    };

    let mut current_squads: Vec<String> = json_response["response"][0]["activeInternalSquads"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s["uuid"].as_str().map(|v| v.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Добавляем или убираем только PRO сквад
    if enable {
        if !current_squads.contains(&pro_squad.to_string()) {
            current_squads.push(pro_squad.to_string());
        }
    } else {
        current_squads.retain(|s| s != pro_squad);
    }
    info!("[toggle_pro] User {} final squads: {:?}", telegram_id, current_squads);

    // Обновляем сквады в Remnawave
    let api_response = match HTTP_CLIENT
        .patch(&format!("{}/users", *REMNAWAVE_API_BASE))
        .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", "127.0.0.1")
        .header("X-Forwarded-Proto", "https")
        .json(&json!({
            "uuid": user.uuid,
            "activeInternalSquads": json!(current_squads),
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("[toggle_pro] Remnawave PATCH failed for {}: {}", telegram_id, e);
            return HttpResponse::InternalServerError().body(format!("Failed to call remnawave API: {}", e));
        }
    };

    if !api_response.status().is_success() {
        error!("[toggle_pro] Remnawave PATCH error for {}: {}", telegram_id, api_response.status());
        return HttpResponse::InternalServerError().body(format!("Remnawave API error: {}", api_response.status()));
    }

    // Обновляем is_pro в БД
    let result = sqlx::query!(
        "UPDATE users SET is_pro = $1 WHERE telegram_id = $2",
        enable,
        telegram_id
    )
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                HttpResponse::NotFound().body("User not found")
            } else {
                info!("[toggle_pro] Success for user {}: is_pro={}", telegram_id, enable);
                HttpResponse::Ok().json(json!({"status": "ok", "is_pro": enable}))
            }
        }
        Err(e) => {
            error!("[toggle_pro] DB update failed for {}: {}", telegram_id, e);
            HttpResponse::InternalServerError().body(format!("Failed to update is_pro: {}", e))
        }
    }
}

async fn get_user_squads(telegram_id: web::Path<i64>) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    info!("[get_user_squads] telegram_id={}", telegram_id);

    let get_response = match HTTP_CLIENT
        .get(&format!("{}/users/by-telegram-id/{}", *REMNAWAVE_API_BASE, telegram_id))
        .header("Authorization", &format!("Bearer {}", *REMNAWAVE_API_KEY))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", "127.0.0.1")
        .header("X-Forwarded-Proto", "https")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("[get_user_squads] Remnawave API call failed for {}: {}", telegram_id, e);
            return HttpResponse::InternalServerError().body(format!("Failed to call remnawave API: {}", e));
        }
    };

    if !get_response.status().is_success() {
        error!("[get_user_squads] Remnawave API error for {}: {}", telegram_id, get_response.status());
        return HttpResponse::InternalServerError().body(format!("Remnawave API error: {}", get_response.status()));
    }

    let json_response = match get_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => {
            error!("[get_user_squads] Failed to parse response for {}: {}", telegram_id, e);
            return HttpResponse::InternalServerError().body(format!("Failed to parse response: {}", e));
        }
    };

    let squads: Vec<serde_json::Value> = json_response["response"][0]["activeInternalSquads"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|s| {
                    let uuid = s["uuid"].as_str().unwrap_or("unknown").to_string();
                    let tag = s["tag"].as_str().unwrap_or("unknown").to_string();
                    json!({"uuid": uuid, "tag": tag})
                })
                .collect()
        })
        .unwrap_or_default();

    info!("[get_user_squads] User {} has {} squads", telegram_id, squads.len());
    HttpResponse::Ok().json(json!({"squads": squads}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Server starting...");
    dotenv::dotenv().ok();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    info!("DB connected. Starting HTTP server on 0.0.0.0:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(
                web::resource("/users")
                    .route(web::get().to(list_users))
                    .route(web::post().to(create_user)),
            )
            .service(
                web::resource("/users/{telegram_id}/extend")
                    .route(web::patch().to(extend_subscription)),
            )
            .service(web::resource("/users/add_referral").route(web::post().to(add_referral)))
            .service(web::resource("/users/expiring").route(web::get().to(get_expiring_users)))
            .service(web::resource("/users/expired").route(web::get().to(get_expired_users)))
            .service(web::resource("/users/auto_renew_due").route(web::get().to(get_auto_renew_users)))
            .service(web::resource("/users/{telegram_id}/info").route(web::get().to(get_user_info)))
            .service(web::resource("/users/{telegram_id}/trial").route(web::patch().to(trial)))
            .service(web::resource("/users/{telegram_id}/is_connected").route(web::get().to(check_connection)))
            .service(web::resource("/users/{telegram_id}/ref_bonus").route(web::patch().to(ref_bonus)))
            .service(web::resource("/users/{telegram_id}/refs").route(web::patch().to(payed_refs)))
            .service(web::resource("/users/{telegram_id}/disable_device").route(web::post().to(temp_disable_device_limit)))
            .service(web::resource("/users/{uuid}/get_devices").route(web::get().to(get_devices)))
            .service(web::resource("/users/{telegram_id}/payment_method")
                .route(web::post().to(save_payment_method))
                .route(web::delete().to(delete_payment_method)))
            .service(web::resource("/users/{telegram_id}/auto_renew")
                .route(web::patch().to(toggle_auto_renew)))
            .service(web::resource("/users/{telegram_id}/pro")
                .route(web::patch().to(toggle_pro)))
            .service(web::resource("/users/{telegram_id}/squads")
                .route(web::get().to(get_user_squads)))
            .service(web::resource("/users/{telegram_id}/auto_renew_attempt")
                .route(web::post().to(record_auto_renew_attempt)))
            .service(web::resource("/promos").route(web::post().to(create_promo)).route(web::get().to(list_promos)))
            .service(web::resource("/promos/validate").route(web::post().to(validate_promo)))
            .service(web::resource("/promos/use").route(web::post().to(use_promo)))
            .service(web::resource("/promos/{code}/deactivate").route(web::patch().to(deactivate_promo)))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}