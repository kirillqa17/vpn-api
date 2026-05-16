-- Apply: sudo -u postgres psql -d vpn_db -f 007_device_tokens.sql
--
-- FCM/APNs device registration table. One row per (device token). A user
-- can have several rows (phone + tablet). Sending a push to a user =
-- SELECT token WHERE telegram_id = $1 AND a per-type opt-in is true.
--
-- Opt-in flags live here (not on user_credentials) because they are a
-- device/app concern and a user may be logged in on the app but manage
-- email prefs separately on the website (user_credentials.notify_*).

CREATE TABLE IF NOT EXISTS device_tokens (
    id            BIGSERIAL PRIMARY KEY,
    telegram_id   BIGINT NOT NULL,
    token         TEXT NOT NULL UNIQUE,
    platform      VARCHAR(16) NOT NULL DEFAULT 'android'
                  CHECK (platform IN ('android', 'ios')),
    -- Per-category opt-in. Default true: the user explicitly granted OS
    -- notification permission to even get here, so they want them; the
    -- in-app toggles let them narrow it later.
    notify_news    BOOLEAN NOT NULL DEFAULT TRUE,
    notify_support BOOLEAN NOT NULL DEFAULT TRUE,
    app_version   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast "all tokens for this user" lookup (support reply → that user).
CREATE INDEX IF NOT EXISTS idx_device_tokens_telegram_id
    ON device_tokens (telegram_id);

-- News blast streams every news-opted token; keep it index-friendly.
CREATE INDEX IF NOT EXISTS idx_device_tokens_news
    ON device_tokens (telegram_id) WHERE notify_news = TRUE;

-- Re-registration: the same token may come back (app reinstall keeps
-- token; or token rotates and the old one is replaced). The UNIQUE on
-- token + ON CONFLICT (token) DO UPDATE in the handler keeps one row
-- per physical device and re-points it at the current user.
