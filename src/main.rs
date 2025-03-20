use actix_web::{web, App, HttpResponse, HttpServer};
use sqlx::PgPool;
use uuid::Uuid;
use std::env;
mod models;
use models::{User, NewUser};

// Создать пользователя
async fn create_user(
    pool: web::Data<PgPool>,
    data: web::Json<NewUser>,
) -> HttpResponse {
    let uuid = Uuid::new_v4().to_string();
    
    let user = sqlx::query_as!(
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
    .fetch_one(pool.get_ref())
    .await;

    match user {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// Получить пользователя по UUID
async fn get_user(pool: web::Data<PgPool>, uuid: web::Path<String>) -> HttpResponse {
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE uuid = $1",
        uuid.into_inner()
    )
    .fetch_one(pool.get_ref())
    .await;

    match user {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

// Продлить подписку
async fn extend_subscription(
    pool: web::Data<PgPool>,
    uuid: web::Path<String>,
    days: web::Json<u32>,
) -> HttpResponse {
    let result = sqlx::query!(
        r#"
        UPDATE users 
        SET subscription_end = subscription_end + INTERVAL '1 day' * $1
        WHERE uuid = $2
        RETURNING *
        "#,
        *days as i32,
        *uuid
    )
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(_) => HttpResponse::NotFound().finish(),
    }
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