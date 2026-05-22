-- Apply: sudo -u postgres psql -d vpn_db -f 009_broadcasts.sql
--
-- Broadcast history: one row per admin push broadcast. `segment` records
-- the recipient selector; `recipients`/`delivered` are filled as the
-- background FCM fan-out progresses.

CREATE TABLE IF NOT EXISTS broadcasts (
    id          BIGSERIAL PRIMARY KEY,
    admin_label TEXT,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    segment     JSONB NOT NULL,
    recipients  INT NOT NULL DEFAULT 0,
    delivered   INT NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'sending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_broadcasts_created ON broadcasts (created_at DESC);
