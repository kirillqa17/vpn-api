-- Apply: sudo -u postgres psql -d vpn_db -f 008_news_media.sql
--
-- News posts can carry photos. The channel bot was only sending
-- {tg_message_id,text,date}, so media_url was always NULL and the app
-- showed an empty skeleton for text posts while photo posts lost their
-- images entirely. Add Telegram photo file_id storage + album grouping.
--
--   media_file_ids : JSON array (text) of Telegram photo file_ids,
--                    e.g. ["AgAC...","AgAC..."]. NULL/'' = text-only.
--   media_group_id : Telegram album id. Album items arrive as separate
--                    channel_post updates sharing this id; the API
--                    appends each photo to the one news row so a
--                    multi-photo post is a single news item.
--
-- Legacy media_url stays for back-compat (always NULL going forward).

ALTER TABLE news_posts
    ADD COLUMN IF NOT EXISTS media_file_ids TEXT,
    ADD COLUMN IF NOT EXISTS media_group_id TEXT;

-- Album-append needs to find the existing row for a media group fast.
CREATE INDEX IF NOT EXISTS idx_news_posts_media_group
    ON news_posts (media_group_id) WHERE media_group_id IS NOT NULL;
