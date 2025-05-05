use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;


#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub telegram_id: i64,
    pub uuid: Uuid,
    pub subscription_end: DateTime<Utc>,
    pub is_active: i32,
    pub created_at: DateTime<Utc>,
    pub referrals: Option<Vec<i64>>,  
    pub referral_id: Option<i64>,
    pub is_used_trial: bool,
    pub game_points: i64,
    pub is_used_ref_bonus: bool,
    pub game_attempts: i64,
    pub next_claim_time: DateTime<Utc>,
    pub record_flappy: i64,
    pub username: Option<String>,
    pub plan: String,
    pub sub_link: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub telegram_id: i64,
    pub referral_id: Option<i64>,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddReferralData {
    pub referral_id: i64,          // telegram_id пригласившего пользователя
    pub referred_telegram_id: i64, // telegram_id приглашаемого пользователя
}

#[derive(Deserialize)]
pub struct ExtendSubscriptionRequest {
    pub days: u32,
    pub plan: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ExpiringUser {
    pub telegram_id: i64,
    pub subscription_end: DateTime<Utc>,
    pub username: Option<String>,
    pub plan: String,
}