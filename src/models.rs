use serde::{Deserialize, Serialize};
use chrono;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub telegram_id: Option<i64>,
    pub uuid: String,
    pub subscription_end: Option<chrono::DateTime<chrono::Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub telegram_id: Option<i64>,
    pub subscription_days: u32,
}
