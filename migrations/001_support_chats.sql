-- Apply: sudo -u postgres psql -d vpn_db -f 001_support_chats.sql

CREATE TABLE IF NOT EXISTS support_chats (
    id          BIGSERIAL PRIMARY KEY,
    telegram_id BIGINT NOT NULL,
    role        VARCHAR(16) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_support_chats_telegram_id_created
    ON support_chats (telegram_id, created_at DESC);

-- Auto-cleanup: delete messages older than 30 days
-- Run periodically or at app startup:
-- DELETE FROM support_chats WHERE created_at < NOW() - INTERVAL '30 days';
