-- Apply: sudo -u postgres psql -d vpn_db -f 010_grants_default.sql
--
-- Fix: every migration here is applied as `postgres` (per the "Apply:"
-- comments), so the resulting tables/sequences are owned by postgres with
-- empty grants — `api_user` (the role vpn-api connects as) is locked out.
-- We hit this in prod on `device_tokens`: register_device INSERTs returned
-- `permission denied for table device_tokens`, the table stayed empty, and
-- no FCM push could ever fan out to anyone.
--
-- This migration:
--   1) Grants api_user full access on every existing table/sequence in
--      public — closes the gap for tables added by past migrations.
--   2) Sets DEFAULT PRIVILEGES so future tables/sequences created by
--      postgres automatically grant api_user — the same hole can't open
--      again on the next migration.
-- Idempotent.

GRANT ALL ON ALL TABLES IN SCHEMA public TO api_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO api_user;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT ALL ON TABLES TO api_user;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT ALL ON SEQUENCES TO api_user;
