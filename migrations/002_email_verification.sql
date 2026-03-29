-- Email verification codes table
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(6) NOT NULL,
    purpose VARCHAR(20) NOT NULL CHECK (purpose IN ('register', 'reset_password')),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_verification_email_purpose ON email_verification_codes (email, purpose, used);

-- Add email_verified flag to user_credentials
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;

-- Mark all existing users as verified
UPDATE user_credentials SET email_verified = TRUE WHERE email_verified = FALSE OR email_verified IS NULL;
