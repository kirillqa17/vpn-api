use actix_web::{web, App, HttpResponse, HttpServer};
use serde_json::json;
use sqlx::postgres::PgPool;
use uuid::Uuid;
use chrono::Utc;
mod models;
use models::{User, NewUser, AddReferralData, ExtendSubscriptionRequest, ServerConfig};
use urlencoding::encode;
use base64::engine::general_purpose;
use base64::Engine;

async fn create_user(pool: web::Data<PgPool>, data: web::Json<NewUser>) -> HttpResponse {
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

    let uuid = Uuid::new_v4();
    let referral_id = data.referral_id;
    let username = data.username.clone();

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let user = match sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (telegram_id, uuid, subscription_end, is_active, created_at, referral_id, is_used_trial, game_points, is_used_ref_bonus, game_attempts, username)
        VALUES ($1, $2, NOW() + $3 * INTERVAL '1 day', 0, $4, $5, $6, $7, $8, $9, $10)
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
        username
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

    let servers = [
        ("DE", "svoivpn-de.duckdns.org"),
        ("NE", "svoivpn-ne.duckdns.org"),
    ];

    let conn_limit = match plan.as_str() {
        "base" => 2,
        "family" => 5,
        _ => 2,
    };
    
    let mut errors = Vec::new();
    let client = reqwest::Client::new();

    // Отправляем запросы на все серверы
    for (server_code, domain) in servers.iter() {
        let url = format!("https://{}/add/{}", domain, uuid); 
        let response = client.post(&url)
            .json(&conn_limit)
            .send()
            .await;

        if let Err(e) = response {
            errors.push(format!("Failed to connect to {} server: {}", server_code, e));
        } else if let Ok(resp) = response {
            if !resp.status().is_success() {
                errors.push(format!("Failed to sync with {} server: {}", server_code, resp.status()));
            }
        }
    }

    // Если были ошибки при синхронизации с серверами
    if !errors.is_empty() {
        return HttpResponse::InternalServerError().body(errors.join(", "));
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

async fn get_subscription_config(
    pool: web::Data<PgPool>,
    telegram_id: web::Path<i64>,
) -> HttpResponse {
    let user = match sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE telegram_id = $1",
        telegram_id.into_inner()
    )
    .fetch_one(pool.get_ref())
    .await {
        Ok(user) => user,
        Err(_) => return HttpResponse::NotFound().json("User not found"),
    };

    if user.is_active != 1 {
        return HttpResponse::Forbidden().json("Subscription not active");
    }

    // Определяем серверы и их параметры
    let servers = vec![
        ServerConfig {
            address: "103.7.55.172".to_string(),
            sni: "www.apple.com".to_string(),
            fp: "chrome".to_string(),
            name: "🇩🇪 Германия".to_string(),
        },
        ServerConfig {
            address: "46.17.99.157".to_string(),
            sni: "www.cloudflare.com".to_string(),
            fp: "chrome".to_string(),
            name: "🇳🇱 Нидерланды".to_string(),
        },
    ];

    // Общие параметры для всех серверов
    let pbk = "Swx7Lw2oTs19zMXwF3TMIbJdNQD8EBbc-vEL1DjbLAk";
    let sid = "7640cb77";

    // Генерируем VLESS URI для каждого сервера
    let mut configs = Vec::new();
    for server in servers {
        let params = format!(
            "security=reality&type=tcp&headerType=&flow=xtls-rprx-vision&path=&host=&sni={}&fp={}&pbk={}&sid={}#{}",
            server.sni,
            server.fp,
            pbk,
            sid,
            encode(&server.name)
        );

        let uri = format!(
            "vless://{}@{}:8443?{}",
            user.uuid,
            server.address,
            params
        );

        configs.push(uri);
    }

    // Объединяем все конфигурации в одну строку с разделителем новой строки
    let combined_configs = configs.join("\n");

    // Кодируем в base64
    let encoded = general_purpose::STANDARD.encode(combined_configs);

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(encoded)
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
            .service(web::resource("/users/sub/{telegram_id}").route(web::get().to(get_subscription_config)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}