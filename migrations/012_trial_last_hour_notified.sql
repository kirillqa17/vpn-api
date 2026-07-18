-- Дедуп-флаг уведомления «последний час пробного периода»:
-- эндпоинт /users/trial_ending помечает юзера в той же транзакции,
-- в которой возвращает его боту (паттерн как у expiring/expired is_active 1→2→0).
ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_last_hour_notified BOOLEAN NOT NULL DEFAULT FALSE;
