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
    pub payed_refs: i64,
    pub device_limit: i64,
    pub auto_renew: bool,
    pub payment_method_id: Option<String>,
    pub auto_renew_plan: Option<String>,
    pub auto_renew_duration: Option<String>,
    pub auto_renew_last_attempt: Option<DateTime<Utc>>,
    pub auto_renew_fail_count: i32,
    pub is_pro: bool,
    pub card_last4: Option<String>,
    pub first_purchase_bonus_used: bool,
    pub first_purchase_bonus_deadline: Option<DateTime<Utc>>,
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
    pub days: i32,
    pub plan: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ExpiringUser {
    pub telegram_id: i64,
    pub subscription_end: DateTime<Utc>,
    pub username: Option<String>,
    pub plan: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct PromoCode {
    pub id: i32,
    pub code: String,
    pub discount_percent: i32,
    pub applicable_tariffs: Vec<String>,
    pub max_uses: i32,
    pub current_uses: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePromoRequest {
    pub code: String,
    pub discount_percent: i32,
    pub applicable_tariffs: Vec<String>,
    pub max_uses: i32,
}

#[derive(Debug, Deserialize)]
pub struct ValidatePromoRequest {
    pub code: String,
    pub tariff: String,
    pub telegram_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct UsePromoRequest {
    pub code: String,
    pub telegram_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct SavePaymentMethodRequest {
    pub payment_method_id: String,
    pub plan: String,
    pub duration: String,
    pub card_last4: Option<String>,
    // Магазин ЮКассы, выдавший payment_method_id: "bot" | "web" (None = "bot")
    pub shop: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ToggleAutoRenewRequest {
    pub auto_renew: bool,
    pub plan: Option<String>,
    pub duration: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AutoRenewUser {
    pub telegram_id: i64,
    pub payment_method_id: Option<String>,
    pub payment_method_shop: Option<String>,
    pub auto_renew_plan: Option<String>,
    pub auto_renew_duration: Option<String>,
    pub subscription_end: DateTime<Utc>,
    pub plan: String,
    pub username: Option<String>,
    pub auto_renew_fail_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct AutoRenewAttemptRequest {
    pub success: bool,
}

#[derive(Debug, Deserialize)]
pub struct ToggleProRequest {
    pub is_pro: bool,
}

#[derive(Debug, Deserialize)]
pub struct SupportChatRequest {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct InternalSupportChatRequest {
    pub telegram_id: i64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct InternalSupportEscalateRequest {
    pub telegram_id: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppSupportMessageResponse {
    pub stored: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub forwarded_to_admin: bool,
    /// support_chats.id of the row just inserted. Returned to the
    /// uploader so the client can immediately render the attachment
    /// (the `attachment` field below) without waiting for a history
    /// re-fetch. Optional for backward-compat with 1.5.x clients that
    /// ignore unknown JSON fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<i64>,
    /// Attachment metadata when this row carries one. None for
    /// text-only messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<SupportAttachmentMeta>,
}

/// Slim attachment descriptor returned alongside every history /
/// upload response that has an attached file. The `id` field is the
/// support_chats row id — it's what the client uses to fetch the file
/// bytes via GET /api/app/support/attachment/{id}.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SupportAttachmentMeta {
    pub id: i64,
    pub kind: String,       // "photo" | "video" | "document"
    pub filename: String,
    pub mime: String,
    pub size: i64,
}

