use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;


#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub telegram_id: i64,
    pub uuid: Uuid,
    pub subscription_end: DateTime<Utc>,
    pub is_active: i16,
    pub created_at: DateTime<Utc>,
    pub referrals: Option<Vec<i64>>,  
    pub referral_id: Option<i64>,
    pub is_used_trial: bool,
    pub game_points: i64,
    pub is_used_ref_bonus: bool,
    pub game_attempts: i32,
    pub server_location: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub telegram_id: Option<i64>,
    pub subscription_days: u32,
    pub referral_id: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddReferralData {
    pub referral_id: i64,          // telegram_id пригласившего пользователя
    pub referred_telegram_id: i64, // telegram_id приглашаемого пользователя
}

#[derive(Deserialize)]
struct ExtendSubscriptionRequest {
    days: u32,
    server: String, 
}