use actix_web::{web, App, HttpResponse, HttpServer};
use reqwest::Client;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use std::time::Duration;

mod models;
use models::{User, NewUser};

const XRAY_API_URL: &str = "http://localhost:62789/api";

// Создать пользователя
async fn create_user(
    pool: web::Data<PgPool>,
    data: web::Json<NewUser>,
) -> HttpResponse {
    let uuid = Uuid::new_v4().to_string();
    let client = Client::new();

    // Начать транзакцию
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    // Добавить в БД
    let user = match sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (telegram_id, uuid, subscription_end, is_active)
        VALUES ($1, $2, NOW() + $3 * INTERVAL '1 day', TRUE)
        RETURNING *
        "#,
        data.telegram_id,
        uuid,
        data.subscription_days as i32
    )
    .fetch_one(&mut *tx)
    .await {
        Ok(user) => user,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    // Добавить в Xray
    let xray_response = client.post(&format!("{}/users", XRAY_API_URL))
        .json(&json!({
            "email": format!("{}@vpn.com", uuid),
            "uuid": uuid,
            "inboundTag": "your-inbound-tag"
        }))
        .send()
        .await;

    if let Err(e) = xray_response {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().body(format!("Xray API error: {}", e));
    }

    // Завершить транзакцию
    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    HttpResponse::Ok().json::<User>(user)
}

// Получить пользователя по UUID
async fn get_user(
    pool: web::Data<PgPool>,
    uuid: web::Path<String>,
) -> HttpResponse {
    // Проверка формата UUID
    let uuid = match Uuid::parse_str(&uuid) {
        Ok(uuid) => uuid,
        Err(_) => return HttpResponse::BadRequest().body("Invalid UUID format"),
    };

    // Поиск пользователя в БД
    match sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE uuid = $1",
        uuid.to_string()
    )
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(user)) => HttpResponse::Ok().json(user),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// Продлить подписку
async fn extend_subscription(
    pool: web::Data<PgPool>,
    uuid: web::Path<String>,
    days: web::Json<u32>,
) -> HttpResponse {
    let client = Client::new();
    let uuid = uuid.into_inner();

    // Обновить в БД
    let result = match sqlx::query!(
        r#"
        UPDATE users 
        SET subscription_end = GREATEST(subscription_end, NOW()) + $1 * INTERVAL '1 day'
        WHERE uuid = $2
        RETURNING *
        "#,
        *days as i32,
        uuid
    )
    .fetch_one(pool.get_ref())
    .await {
        Ok(user) => user,
        Err(_) => return HttpResponse::NotFound().finish(),
    };

    // Обновить в Xray (добавить если был удален)
    let _ = client.post(&format!("{}/users", XRAY_API_URL))
        .json(&json!({
            "email": format!("{}@vpn.com", uuid),
            "uuid": uuid,
            "inboundTag": "your-inbound-tag"
        }))
        .send()
        .await;

    HttpResponse::Ok().json::<User>(result)
}

// Фоновая задача для очистки
async fn cleanup_task(pool: web::Data<PgPool>) {
    let client = Client::new();
    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Каждый час
    
    loop {
        interval.tick().await;
        
        // Получить просроченных пользователей
        let expired_users = match sqlx::query!(
            "SELECT uuid FROM users WHERE subscription_end < NOW() AND is_active = TRUE"
        )
        .fetch_all(pool.get_ref())
        .await {
            Ok(users) => users,
            Err(_) => continue,
        };

        for user in expired_users {
            // Удалить из Xray
            let _ = client.delete(&format!("{}/users/{}@vpn.com", XRAY_API_URL, user.uuid.to_string()))
                .send()
                .await;

            // Обновить статус в БД
            let _ = sqlx::query!(
                "UPDATE users SET is_active = FALSE WHERE uuid = $1",
                user.uuid
            )
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