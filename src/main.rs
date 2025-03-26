use actix_web::{web, App, HttpResponse, HttpServer};
use reqwest::Client;
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
    // Читаем текущий конфиг
    let config_data = fs::read_to_string(XRAY_CONFIG_PATH)
        .map_err(|e| format!("Ошибка чтения конфигурации: {}", e))?;
    
    let mut config: Value = serde_json::from_str(&config_data)
        .map_err(|e| format!("Ошибка парсинга JSON: {}", e))?;

    // Ищем inbound с тегом "your-inbound-tag"
    if let Some(inbounds) = config["inbounds"].as_array_mut() {
        for inbound in inbounds {
            if inbound["tag"] == "vless-inbound" {
                if let Some(clients) = inbound["settings"]["clients"].as_array_mut() {
                    clients.push(json!({ "id": uuid }));
                }
            }
        }
    }

    // Записываем обновленный конфиг
    fs::write(XRAY_CONFIG_PATH, serde_json::to_string_pretty(&config).unwrap())
        .map_err(|e| format!("Ошибка записи конфигурации: {}", e))?;

    // Отправляем SIGHUP процессу Xray
    Command::new("pkill")
        .arg("-HUP")
        .arg("xray")
        .output()
        .map_err(|e| format!("Ошибка при отправке SIGHUP: {}", e))?;

    Ok(())
}

async fn create_user(
    pool: web::Data<PgPool>,
    data: web::Json<NewUser>,
) -> HttpResponse {
    let uuid = Uuid::new_v4();

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let user = match sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (telegram_id, uuid, subscription_end, is_active, created_at)
        VALUES ($1, $2, NOW() + $3 * INTERVAL '1 day', TRUE, $4)
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

    match update_xray_config( &uuid.to_string()) {
        Ok(_) => (),
        Err(e) => {
            let _ = tx.rollback().await;
            return HttpResponse::InternalServerError().body(format!("Xray конфиг ошибка: {}", e));
        }
    }

    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    HttpResponse::Ok().json(user) 
}

// Получить всех пользователей
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

// Получить пользователя по UUID
async fn get_user(
    pool: web::Data<PgPool>,
    uuid: web::Path<String>,
) -> HttpResponse {
    let uuid = match Uuid::parse_str(&uuid) {
        Ok(uuid) => uuid,
        Err(_) => return HttpResponse::BadRequest().body("Invalid UUID format"),
    };

    match sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE uuid = $1",
        uuid
    )
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(user)) => HttpResponse::Ok().json(user),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn extend_subscription(
    pool: web::Data<PgPool>,
    uuid: web::Path<String>,
    days: web::Json<u32>,
) -> HttpResponse {
    let client = Client::new();
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

    // let _ = client.post(&format!("{}/users", XRAY_API_URL))
    //     .json(&json!({
    //         "email": format!("{}@vpn.com", uuid),
    //         "uuid": uuid,
    //         "inboundTag": "your-inbound-tag"
    //     }))
    //     .send()
    //     .await;

    HttpResponse::Ok().json(result)
}

Фоновая задача для очистки
async fn cleanup_task(pool: web::Data<PgPool>) {
    let client = Client::new();
    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Каждый час
    
    // loop {
    //     interval.tick().await;
        
    //     // Получить просроченных пользователей
    //     let expired_users = match sqlx::query!(
    //         "SELECT uuid FROM users WHERE subscription_end < NOW() OR is_active = TRUE"
    //     )
    //     .fetch_all(pool.get_ref())
    //     .await {
    //         Ok(users) => users,
    //         Err(_) => continue,
    //     };

    //     for user in expired_users {
    //         // Удалить из Xray
    //         let _ = client.delete(&format!("{}/users/{}@vpn.com", XRAY_API_URL, user.uuid.to_string()))
    //             .send()
    //             .await;

    //         // Обновить статус в БД
    //         let _ = sqlx::query!(
    //             "UPDATE users SET is_active = FALSE WHERE uuid = $1",
    //             user.uuid
    //         )
    //         .execute(pool.get_ref())
    //         .await;
    //     }
    // }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    // Запустить фоновую задачу
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
                web::resource("/users/{uuid}")
                    .route(web::get().to(get_user)),
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