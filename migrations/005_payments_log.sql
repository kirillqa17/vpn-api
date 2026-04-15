-- Payments log: append-only record of every subscription extension event.
-- Not a replacement for YooKassa/CryptoBot — just a local ledger so we can
-- distinguish paid days from bonus/trial/admin days and compute real ARPU.

CREATE TABLE IF NOT EXISTS payments (
    id            BIGSERIAL PRIMARY KEY,
    telegram_id   BIGINT          NOT NULL,
    source        VARCHAR(32)     NOT NULL,
        -- Expected values:
        --   yookassa              — real card payment via YooKassa (amount_rub set)
        --   crypto                — real crypto payment via CryptoBot (amount_rub set)
        --   trial                 — trial activation, amount=NULL, days=7
        --   first_purchase_bonus  — +14 days onboarding bonus, amount=NULL
        --   ref_bonus_child       — +15 days to referred user on first payment
        --   ref_bonus_parent      — +30 days to referrer per paid referral
        --   ref_milestone_5       — 5-paid-refs reward (currently 180 days family)
        --   ref_milestone_10      — 10-paid-refs reward (currently 365 days family)
        --   admin_extend          — manual /extend by admin
        --   admin_compensate      — mass compensation by admin
        --   promo                 — extension via 100% promo code
        --   other                 — anything else
    amount_rub    NUMERIC(10, 2), -- real money paid (nullable for bonus/admin/trial)
    plan          VARCHAR(16)     NOT NULL,
    duration      VARCHAR(16),    -- '1m' | '3m' | '1y' | NULL
    days_added    INTEGER         NOT NULL,
    external_id   VARCHAR(128),   -- YooKassa payment_id, CryptoBot invoice_id, promo code, etc.
    metadata      JSONB,
    created_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payments_telegram_id_created ON payments (telegram_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payments_source_created      ON payments (source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payments_created_at          ON payments (created_at DESC);

-- vpn-api runs as api_user — grant access so inserts don't silently fail.
GRANT ALL ON TABLE payments TO api_user;
GRANT USAGE, SELECT ON SEQUENCE payments_id_seq TO api_user;
