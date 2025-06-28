use actix_web::{web, App, HttpResponse, HttpServer};
use serde_json::json;
use sqlx::postgres::PgPool;
use uuid::Uuid;
use chrono::Utc;
mod models;
use models::{User, NewUser, AddReferralData, ExtendSubscriptionRequest, ExpiringUser};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

lazy_static::lazy_static! {
    static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::new();
    static ref REMNAWAVE_API_BASE: String = std::env::var("REMNAWAVE_API_BASE").unwrap_or_else(|_| "http://localhost:3000/api".to_string());
    static ref REMNAWAVE_API_KEY: String = std::env::var("REMNAWAVE_API_KEY").expect("REMNAWAVE_API_KEY must be set");
}

async fn create_user(pool: web::Data<PgPool>, data: web::Json<NewUser>) -> HttpResponse {
    // Сначала проверяем существование пользователя в нашей БД
    let existing_user = sqlx::query!(
        "SELECT telegram_id FROM users WHERE telegram_id = $1",
        data.telegram_id
    )
    .fetch_optional(pool.get_ref())
    .await;

    match existing_user {
        Ok(Some(_)) => {
            return HttpResponse::Conflict().body("User with this telegram_id already exists");
        }
        Err(e) => {
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

    let json_response = match api_response.json::<serde_json::Value>().await {
        Ok(json) => json,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to parse API response: {}", e)),
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

    // Создаем пользователя в нашей БД
    let user = match sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (telegram_id, uuid, subscription_end, is_active, created_at, referral_id, is_used_trial, game_points, is_used_ref_bonus, game_attempts, username, sub_link, payed_refs)
        VALUES ($1, $2, NOW() + $3 * INTERVAL '1 day', 0, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
        0
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
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    HttpResponse::Ok().json(user)
}


async fn list_users(pool: web::Data<PgPool>) -> HttpResponse {
    let users = match sqlx::query_as!(User, "SELECT * FROM users")
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(users) => users,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    HttpResponse::Ok().json(users)
}

async fn extend_subscription(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
    request: web::Json<ExtendSubscriptionRequest>,
) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    let days = request.days;
    let plan = request.plan.clone();

    // Получаем uuid пользователя
    let user = match sqlx::query!(
        "SELECT * FROM users WHERE telegram_id = $1",
        telegram_id
    )
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(record) => record,
        Err(_) => return HttpResponse::NotFound().body("User not found"),
    };

    let uuid = user.uuid;
    let current_days = user.subscription_end;

    let device_limit = match plan.as_str() {
        "base" => 2,
        "family" => 5,
        _ => 2,
    };

    let traffic_limit: u64 = match plan.as_str() {
        "base" => 0,
        "family" => 0,
        "trial" => 26843545600,
        _ => 0,
    };
    let expire_at = current_days + chrono::Duration::days(days as i64);

    let expire_at_str = expire_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let api_response = match HTTP_CLIENT
        .patch(&format!("{}/users/update", *REMNAWAVE_API_BASE))
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
            "expireAt": expire_at_str,
            "telegramId": user.telegram_id,
            "hwidDeviceLimit": device_limit
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

    
    let result = sqlx::query_as!(
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
    .await;
    match result {
        Ok(user) => {
            HttpResponse::Ok().json(json!({
                "telegram_id": user.telegram_id,
                "uuid": uuid,
                "subscription_end": user.subscription_end,
                "is_active": user.is_active,
                "plan":user.plan
            }))
        },
        Err(_e) => {
            return HttpResponse::InternalServerError().body("Failed to update database");
        }
    }
    
}


async fn add_referral(pool: web::Data<PgPool>, data: web::Json<AddReferralData>) -> HttpResponse {
    let referral_id = data.referral_id;
    let referred_telegram_id = data.referred_telegram_id;

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

async fn get_traffic(telegram_id: web::Path<i64>) -> HttpResponse {
    let telegram_id = telegram_id.into_inner();
    let api_response = match HTTP_CLIENT
    .get(&format!("{}/users/tg/{}", *REMNAWAVE_API_BASE, telegram_id))
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

    let traffic_limit = json_response["response"][0]["trafficLimitBytes"].as_i64().unwrap();
    let traffic_used = json_response["response"][0]["usedTrafficBytes"].as_i64().unwrap();
    
    HttpResponse::Ok().json(json!({ "traffic_left": traffic_limit - traffic_used }))
    
}

async fn get_expiring_users(
    pool: web::Data<PgPool>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let days_before = query
        .get("days")
        .and_then(|d| d.parse::<i64>().ok())
        .unwrap_or(1);

    // Рассчитываем дату, после которой подписка считается истекающей
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

    // Сначала получаем текущий device_limit пользователя
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
        .patch(&format!("{}/users/update", *REMNAWAVE_API_BASE))
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

    // Запускаем асинхронную задачу для восстановления лимита через 30 минут
    tokio::spawn(async move {
        sleep(Duration::from_secs(30 * 60)).await; // 30 минут

        let _ = HTTP_CLIENT
            .patch(&format!("{}/users/update", *REMNAWAVE_API_BASE))
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

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
            .service(web::resource("/users/{telegram_id}/info").route(web::get().to(get_user_info)))
            .service(web::resource("/users/{telegram_id}/trial").route(web::patch().to(trial)))
            .service(web::resource("/users/{telegram_id}/traffic").route(web::get().to(get_traffic)))
            .service(web::resource("/users/{telegram_id}/ref_bonus").route(web::patch().to(ref_bonus)))
            .service(web::resource("/users/expiring").route(web::get().to(get_expiring_users)))
            .service(web::resource("/users/expired").route(web::get().to(get_expired_users)))
            .service(web::resource("/users/{telegram_id}/refs").route(web::patch().to(payed_refs)))
            .service(web::resource("/users/{telegram_id}/disable_device").route(web::post().to(temp_disable_device_limit)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}