-- Apply: sudo -u postgres psql -d vpn_db -f 010_web_push_subscriptions.sql
--
-- Web Push (VAPID) browser subscriptions for support-chat notifications.
-- Anonymous web users live in the same table — their session_id is hashed
-- into a negative telegram_id by session_to_telegram_id() (same pattern
-- used by support_chats/support_tickets).
--
-- One row per (browser, user). A user with two browsers gets two rows;
-- a subscription expires/changes → new row on next prompt.

CREATE TABLE IF NOT EXISTS web_push_subscriptions (
    id           BIGSERIAL PRIMARY KEY,
    telegram_id  BIGINT NOT NULL,
    endpoint     TEXT NOT NULL UNIQUE,
    p256dh       TEXT NOT NULL,
    auth         TEXT NOT NULL,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Send path: SELECT every subscription for that user.
CREATE INDEX IF NOT EXISTS idx_wps_telegram_id
    ON web_push_subscriptions (telegram_id);

-- vpn-api connects as api_user (not postgres superuser), so the role
-- needs explicit row/sequence permissions or every INSERT returns
-- "permission denied". Same pattern would apply to device_tokens
-- (007), which currently has the same bug in prod — TODO follow-up.
GRANT SELECT, INSERT, UPDATE, DELETE ON web_push_subscriptions TO api_user;
GRANT USAGE, SELECT ON web_push_subscriptions_id_seq TO api_user;
