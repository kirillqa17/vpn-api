-- First-purchase bonus: +14 days on first paid subscription after trial activation.
-- One-time per user, 7-day window from trial activation. NEW users only (no retroactive).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS first_purchase_bonus_used     BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS first_purchase_bonus_deadline TIMESTAMPTZ;

-- Intentionally NO backfill for first_purchase_bonus_deadline —
-- the NULL value marks existing users as ineligible forever.
