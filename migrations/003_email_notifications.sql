-- Email notification preferences and unsubscribe support
ALTER TABLE user_credentials
    ADD COLUMN IF NOT EXISTS notify_news      BOOLEAN     NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS notify_expiry    BOOLEAN     NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS notify_support   BOOLEAN     NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS unsubscribe_token UUID       NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN IF NOT EXISTS last_support_email_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_credentials_unsubscribe_token
    ON user_credentials (unsubscribe_token);

-- Track sent expiry notifications so we don't double-send for the same window
CREATE TABLE IF NOT EXISTS email_expiry_sent (
    id BIGSERIAL PRIMARY KEY,
    telegram_id BIGINT NOT NULL,
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('3_days', '1_day', 'expired')),
    subscription_end TIMESTAMPTZ NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (telegram_id, kind, subscription_end)
);
CREATE INDEX IF NOT EXISTS idx_email_expiry_sent_lookup
    ON email_expiry_sent (telegram_id, kind);

-- vpn-api connects as api_user; grant access to the new table.
GRANT ALL ON TABLE email_expiry_sent TO api_user;
GRANT USAGE, SELECT ON SEQUENCE email_expiry_sent_id_seq TO api_user;
