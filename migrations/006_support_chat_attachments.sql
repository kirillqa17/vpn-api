-- Apply: sudo -u postgres psql -d vpn_db -f 006_support_chat_attachments.sql
--
-- Adds optional Telegram-hosted attachment metadata to support_chats so a
-- single chat row can carry an attached photo / video / file. Storage
-- lives entirely on Telegram (we keep just the bot file_id) — see the
-- /api/app/support/attachment endpoints for the upload/proxy flow.
--
-- All columns NULL by default → no migration needed for the 2k+ existing
-- text-only rows. The CHECK keeps the row coherent: either all four
-- attachment fields are set, or none are.

ALTER TABLE support_chats
    ADD COLUMN IF NOT EXISTS attachment_file_id   TEXT,
    ADD COLUMN IF NOT EXISTS attachment_filename  TEXT,
    ADD COLUMN IF NOT EXISTS attachment_mime      TEXT,
    ADD COLUMN IF NOT EXISTS attachment_size      BIGINT,
    ADD COLUMN IF NOT EXISTS attachment_kind      VARCHAR(16);

-- attachment_kind ∈ {'photo', 'video', 'document'} when set; determines
-- which Telegram getFile sender method to use when proxying back.

ALTER TABLE support_chats
    ADD CONSTRAINT support_chats_attachment_coherent CHECK (
        (attachment_file_id IS NULL AND attachment_filename IS NULL
         AND attachment_mime IS NULL AND attachment_size IS NULL
         AND attachment_kind IS NULL)
        OR
        (attachment_file_id IS NOT NULL AND attachment_kind IS NOT NULL)
    );

-- An index on telegram_id+created_at is already present from migration 001.
-- We don't add an index on attachment_file_id — lookups go through (id, telegram_id)
-- and the file_id is opaque/non-queryable.
