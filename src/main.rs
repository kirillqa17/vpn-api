use actix_web::{web, App, HttpResponse, HttpServer};
use serde_json::json;
use sqlx::postgres::PgPool;
use uuid::Uuid;
use std::fs;
use std::process::Command;
use serde_json::Value;
use std::time::Duration;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

mod models;
use models::{User, NewUser, AddReferralData, ReferralResponse};

const XRAY_CONFIG_PATH: &str = "/usr/local/etc/xray/config.json";

fn update_xray_config(uuid: &str) -> Result<(), String> {
    let config_data = fs::read_to_string(XRAY_CONFIG_PATH)
        .map_err(|e| format!("Ошибка чтения конфигурации: {}", e))?;
    
    let mut config: Value = serde_json::from_str(&config_data)
        .map_err(|e| format!("Ошибка парсинга JSON: {}", e))?;

    if let Some(inbounds) = config["inbounds"].as_array_mut() {
        for inbound in inbounds {
            if inbound["tag"] == "vless-inbound" {
                if let Some(clients) = inbound["settings"]["clients"].as_array_mut() {
                    clients.push(json!({ "id": uuid }));
                }
            }
        }
    }

    fs::write(XRAY_CONFIG_PATH, serde_json::to_string_pretty(&config).unwrap())
        .map_err(|e| format!("Ошибка записи конфигурации: {}", e))?;

    Command::new("pkill")
        .arg("-HUP")
        .arg("xray")
        .output()
        .map_err(|e| format!("Ошибка при отправке SIGHUP: {}", e))?;

    Ok(())
}

fn remove_user_from_xray_config(uuid: &str) -> Result<(), String> {
    let config_data = fs::read_to_string(XRAY_CONFIG_PATH)
        .map_err(|e| format!("Ошибка чтения конфигурации: {}", e))?;

    let mut config: Value = serde_json::from_str(&config_data)
        .map_err(|e| format!("Ошибка парсинга JSON: {}", e))?;

    if let Some(inbounds) = config["inbounds"].as_array_mut() {
        for inbound in inbounds {
            if inbound["tag"] == "vless-inbound" {
                if let Some(clients) = inbound["settings"]["clients"].as_array_mut() {
                    clients.retain(|client| client["id"] != uuid);
                }
            }
        }
    }

    fs::write(XRAY_CONFIG_PATH, serde_json::to_string_pretty(&config).unwrap())
        .map_err(|e| format!("Ошибка записи конфигурации: {}", e))?;

    Command::new("pkill")
        .arg("-HUP")
        .arg("xray")
        .output()
        .map_err(|e| format!("Ошибка при отправке SIGHUP: {}", e))?;

    Ok(())
}

fn check_user_in_xray_config(uuid: &str) -> bool {
    let config_data = match fs::read_to_string(XRAY_CONFIG_PATH) {
        Ok(data) => data,
        Err(_) => return false,  // Если не удалось прочитать конфиг, считаем, что пользователя нет
    };

    let config: Value = match serde_json::from_str(&config_data) {
        Ok(config) => config,
        Err(_) => return false,  // Если не удалось распарсить JSON, считаем, что пользователя нет
    };

    if let Some(inbounds) = config["inbounds"].as_array() {
        for inbound in inbounds {
            if inbound["tag"] == "vless-inbound" {
                if let Some(clients) = inbound["settings"]["clients"].as_array() {
                    for client in clients {
                        if client["id"] == uuid {
                            return true;  // Пользователь найден в конфиге
                        }
                    }
                }
            }
        }
    }

    false  // Если пользователь не найден
}


async fn create_user(pool: web::Data<PgPool>, data: web::Json<NewUser>) -> HttpResponse {
    let uuid = Uuid::new_v4();
    let referral_id = data.referral_id; // Получаем ID пригласившего пользователя

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    // Добавляем нового пользователя в таблицу
    let user = match sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (telegram_id, uuid, subscription_end, is_active, created_at, referral_id)
        VALUES ($1, $2, NOW() + $3 * INTERVAL '1 day', 1, $4, $5)
        RETURNING *
        "#,
        data.telegram_id,
        uuid,
        data.subscription_days as i32,
        Utc::now(),
        referral_id
    )
    .fetch_one(&mut *tx)
    .await {
        Ok(user) => user,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    // Если у пользователя есть реферал, добавляем его telegram_id в массив рефералов
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

    // Обновляем Xray конфигурацию с новым пользователем
    if let Err(e) = update_xray_config(&uuid.to_string()) {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().body(format!("Xray конфиг ошибка: {}", e));
    }

    // Если все прошло успешно, коммитим транзакцию
    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    HttpResponse::Ok().json(user)
}


async fn cleanup_task(pool: web::Data<PgPool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));

    loop {
        interval.tick().await;

        let expired_users = match sqlx::query!("SELECT uuid FROM users WHERE subscription_end < NOW() AND is_active = 1")
            .fetch_all(pool.get_ref())
            .await
        {
            Ok(users) => users,
            Err(_) => continue,
        };

        for user in expired_users {
            if let Err(e) = remove_user_from_xray_config(&user.uuid.to_string()) {
                eprintln!("Ошибка удаления пользователя из Xray: {}", e);
                continue;
            }

            let _ = sqlx::query!("UPDATE users SET is_active = 0 WHERE uuid = $1", user.uuid)
                .execute(pool.get_ref())
                .await;
        }
    }
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

async fn extend_subscription(pool: web::Data<PgPool>, uuid: web::Path<String>, days: web::Json<u32>) -> HttpResponse {
    let uuid = match Uuid::parse_str(&uuid) {
        Ok(uuid) => uuid,
        Err(_) => return HttpResponse::BadRequest().body("Invalid UUID"),
    };

    // Проверяем, существует ли пользователь в конфиге Xray
    let user_exists_in_config = check_user_in_xray_config(&uuid.to_string());

    // Обновляем срок подписки
    let result = match sqlx::query_as!(
        User,
        r#"
        UPDATE users 
        SET subscription_end = GREATEST(subscription_end, NOW()) + $1 * INTERVAL '1 day'
        WHERE uuid = $2
        RETURNING *
        "#,
        days.0 as i32,
        uuid
    )
    .fetch_one(pool.get_ref())
    .await {
        Ok(user) => user,
        Err(_) => return HttpResponse::NotFound().finish(),
    };

    // Если пользователь не был в конфиге Xray, добавляем его обратно
    if !user_exists_in_config {
        if let Err(e) = update_xray_config(&uuid.to_string()) {
            return HttpResponse::InternalServerError().body(format!("Xray конфиг ошибка: {}", e));
        }
    }

    HttpResponse::Ok().json(result)
}


async fn get_referral_id(pool: web::Data<PgPool>, telegram_id: web::Path<i64>) -> HttpResponse {
    let result = match sqlx::query!(
        r#"
        SELECT referral_id FROM users WHERE telegram_id = $1
        "#,
        telegram_id.into_inner()
    )
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(record) => record,
        Err(_) => return HttpResponse::NotFound().body("Referral not found"),
    };

    
    let response = ReferralResponse {
        referral_id: result.referral_id,
    };

    HttpResponse::Ok().json(response)
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

async fn get_referrals_count(pool: web::Data<PgPool>, telegram_id: web::Path<i64>) -> HttpResponse {
    // Выполняем запрос, чтобы получить количество пользователей, которые были приглашены этим пользователем
    let count = match sqlx::query!(
        r#"
        SELECT COUNT(*) AS count
        FROM users
        WHERE referral_id = $1
        "#,
        telegram_id.into_inner()
    )
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(record) => record.count.unwrap_or(0), // Если значение count не присутствует, возвращаем 0
        Err(_) => return HttpResponse::InternalServerError().body("Error fetching referral count"),
    };

    // Возвращаем количество рефералов в ответе
    HttpResponse::Ok().json(json!({ "referrals_count": count }))
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    // Настройка SSL
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_private_key_file("certs/privkey.pem", SslFiletype::PEM)?;
    builder.set_certificate_chain_file("certs/fullchain.pem")?;


    let pool_clone = pool.clone();
    tokio::spawn(async move {
        cleanup_task(web::Data::new(pool_clone)).await
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(
                web::resource("/users")
                    .route(web::get().to(list_users))
                    .route(web::post().to(create_user)),
            )
            .service(
                web::resource("/users/{uuid}/extend")
                    .route(web::patch().to(extend_subscription)),
            )
            .service(web::resource("/users/{telegram_id}/referral_id").route(web::get().to(get_referral_id)))
            .service(web::resource("/users/add_referral").route(web::post().to(add_referral)))
            .service(web::resource("/users/{telegram_id}/referrals_count").route(web::get().to(get_referrals_count)))
    })
    .bind_openssl("0.0.0.0:443", builder)?
    .run()
    .await
}
