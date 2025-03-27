use actix_web::{web, App, HttpResponse, HttpServer};
use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use std::fs;
use std::process::Command;
use serde_json::Value;
use std::time::Duration;

mod models;
use models::{User, NewUser};

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

async fn create_user(pool: web::Data<PgPool>, data: web::Json<NewUser>) -> HttpResponse {
    let uuid = Uuid::new_v4();

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let user = match sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (telegram_id, uuid, subscription_end, is_active, created_at)
        VALUES ($1, $2, NOW() + $3 * INTERVAL '1 day', 1, $4)
        RETURNING *
        "#,
        data.telegram_id,
        uuid,
        data.subscription_days as i32,
        Utc::now()
    )
    .fetch_one(&mut *tx)
    .await {
        Ok(user) => user,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    if let Err(e) = update_xray_config(&uuid.to_string()) {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().body(format!("Xray конфиг ошибка: {}", e));
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

async fn extend_subscription(pool: web::Data<PgPool>, uuid: web::Path<String>, days: web::Json<u32>) -> HttpResponse {
    let uuid = match Uuid::parse_str(&uuid) {
        Ok(uuid) => uuid,
        Err(_) => return HttpResponse::BadRequest().body("Invalid UUID"),
    };

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

    HttpResponse::Ok().json(result)
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

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
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
