-- M3AK - PostgreSQL schema
-- For a NEW development database. Do not run DROP statements against production.
-- Run this file once, then keep it under version control.

BEGIN;

CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    max_words INTEGER NOT NULL CHECK (max_words >= 0),
    max_images INTEGER NOT NULL CHECK (max_images >= 0),
    price NUMERIC(10, 2) NOT NULL CHECK (price >= 0),
    duration_days INTEGER NOT NULL CHECK (duration_days > 0)
);
-- Compatibility migration for AI recovery worker
ALTER TABLE ai_recovery_jobs
    ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0
    CHECK (attempts >= 0);
INSERT INTO packages (name, max_words, max_images, price, duration_days)
VALUES
    ('trial', 5000, 3, 0.00, 4),
    ('basic', 50000, 50, 199.00, 30),
    ('premium', 200000, 300, 499.00, 30)
ON CONFLICT (name) DO UPDATE
SET max_words = EXCLUDED.max_words,
    max_images = EXCLUDED.max_images,
    price = EXCLUDED.price,
    duration_days = EXCLUDED.duration_days;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(30) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(30) NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    trial_started_at TIMESTAMPTZ,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    firebase_uid VARCHAR(128) UNIQUE,
    agreed_terms BOOLEAN NOT NULL DEFAULT FALSE,
    agreed_privacy BOOLEAN NOT NULL DEFAULT FALSE,
    is_subscribed BOOLEAN NOT NULL DEFAULT FALSE,
    package_id INTEGER REFERENCES packages(id),
    subscription_expires_at TIMESTAMPTZ,
    words_used_count INTEGER NOT NULL DEFAULT 0 CHECK (words_used_count >= 0),
    images_used_count INTEGER NOT NULL DEFAULT 0 CHECK (images_used_count >= 0),
    token_version INTEGER NOT NULL DEFAULT 1
);

-- Safe additive migrations for databases created from earlier M3AK drafts.
-- These statements preserve existing users and do not delete application data.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS trial_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS firebase_uid VARCHAR(128),
    ADD COLUMN IF NOT EXISTS agreed_terms BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS agreed_privacy BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_subscribed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS package_id INTEGER REFERENCES packages(id),
    ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS words_used_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS images_used_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_firebase_uid
    ON users(firebase_uid) WHERE firebase_uid IS NOT NULL;

-- Existing rows are preserved. Assign the trial package only where package_id is missing.
UPDATE users
SET package_id = (SELECT id FROM packages WHERE name = 'trial')
WHERE package_id IS NULL
  AND EXISTS (SELECT 1 FROM packages WHERE name = 'trial');

CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at BIGINT NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rate_limits (
    ip VARCHAR(45) NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 1 CHECK (hit_count >= 0),
    window_start BIGINT NOT NULL,
    PRIMARY KEY (ip, endpoint)
);

CREATE TABLE IF NOT EXISTS chat_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    image_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subscriptions_payments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    transaction_id VARCHAR(255) UNIQUE NOT NULL,
    merchant_order_id VARCHAR(255) UNIQUE,
    paymob_order_id VARCHAR(100),
    package_id INTEGER REFERENCES packages(id),
    amount NUMERIC(10, 2) NOT NULL CHECK (amount >= 0),
    currency VARCHAR(10) NOT NULL DEFAULT 'EGP',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    gateway VARCHAR(50) NOT NULL DEFAULT 'paymob',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Compatibility additions for databases where these tables were created
-- from an earlier draft of the M3AK schema.
ALTER TABLE subscriptions_payments
    ADD COLUMN IF NOT EXISTS merchant_order_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS paymob_order_id VARCHAR(100),
    ADD COLUMN IF NOT EXISTS package_id INTEGER REFERENCES packages(id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_merchant_order
    ON subscriptions_payments(merchant_order_id)
    WHERE merchant_order_id IS NOT NULL;

ALTER TABLE users
    ALTER COLUMN package_id DROP DEFAULT;

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    order_number VARCHAR(100) UNIQUE NOT NULL,
    section_name VARCHAR(100) NOT NULL,
    details TEXT NOT NULL,
    total NUMERIC(10, 2) NOT NULL CHECK (total >= 0),
    status VARCHAR(50) NOT NULL DEFAULT 'قيد المراجعة',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_tickets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'مفتوحة',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_package_id ON users(package_id);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start ON rate_limits(window_start);
CREATE INDEX IF NOT EXISTS idx_chat_history_user_created ON chat_history(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payments_user_created ON subscriptions_payments(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payments_status ON subscriptions_payments(status);
CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_user_created ON support_tickets(user_id, created_at DESC);
-- =========================================================
-- M3AK AI QUOTA SYSTEM
-- Monthly quota, reservations, usage ledger and recovery jobs
-- Safe additive schema
-- =========================================================

-- 1. User quota anchors
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS ai_quota_anchor_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ai_quota_anchor_day SMALLINT;

-- 2. Monthly quota periods
CREATE TABLE IF NOT EXISTS ai_quota_periods (
    id BIGSERIAL PRIMARY KEY,

    user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,

    anchor_day SMALLINT NOT NULL
        CHECK (anchor_day BETWEEN 1 AND 31),

    words_limit INTEGER NOT NULL
        CHECK (words_limit >= 0),

    images_limit INTEGER NOT NULL
        CHECK (images_limit >= 0),

    words_consumed INTEGER NOT NULL DEFAULT 0
        CHECK (words_consumed >= 0),

    images_consumed INTEGER NOT NULL DEFAULT 0
        CHECK (images_consumed >= 0),

    words_reserved INTEGER NOT NULL DEFAULT 0
        CHECK (words_reserved >= 0),

    images_reserved INTEGER NOT NULL DEFAULT 0
        CHECK (images_reserved >= 0),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ai_quota_period_dates_check
        CHECK (period_end > period_start),

    CONSTRAINT ai_quota_period_user_start_unique
        UNIQUE (user_id, period_start)
);

-- 3. AI request reservations
CREATE TABLE IF NOT EXISTS ai_request_reservations (
    reservation_id UUID PRIMARY KEY,

    user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    period_id BIGINT NOT NULL
        REFERENCES ai_quota_periods(id),

    idempotency_key VARCHAR(200) NOT NULL,

    reserved_words INTEGER NOT NULL
        CHECK (reserved_words >= 0),

    reserved_images INTEGER NOT NULL
        CHECK (reserved_images >= 0),

    actual_words INTEGER NOT NULL DEFAULT 0
        CHECK (actual_words >= 0),

    actual_images INTEGER NOT NULL DEFAULT 0
        CHECK (actual_images >= 0),

    status VARCHAR(30) NOT NULL
        CHECK (
            status IN (
                'reserved',
                'provider_succeeded',
                'settled',
                'failed',
                'refunded',
                'unknown'
            )
        ),

    lease_expires_at TIMESTAMPTZ NOT NULL,

    provider_request_id TEXT,
    provider_succeeded_at TIMESTAMPTZ,

    last_error TEXT,

    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ai_request_idempotency_unique
        UNIQUE (user_id, idempotency_key)
);

-- 4. AI usage ledger
CREATE TABLE IF NOT EXISTS ai_usage_ledger (
    id BIGSERIAL PRIMARY KEY,

    event_key VARCHAR(250) NOT NULL UNIQUE,

    reservation_id UUID NOT NULL
        REFERENCES ai_request_reservations(reservation_id),

    user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    period_id BIGINT NOT NULL
        REFERENCES ai_quota_periods(id),

    event_type VARCHAR(30) NOT NULL
        CHECK (
            event_type IN (
                'reserve',
                'settle',
                'refund'
            )
        ),

    words_delta INTEGER NOT NULL DEFAULT 0,
    images_delta INTEGER NOT NULL DEFAULT 0,

    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 5. AI recovery jobs
CREATE TABLE IF NOT EXISTS ai_recovery_jobs (
    id BIGSERIAL PRIMARY KEY,

    reservation_id UUID NOT NULL UNIQUE
        REFERENCES ai_request_reservations(reservation_id)
        ON DELETE CASCADE,

    status VARCHAR(30) NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'processing',
                'completed',
                'failed'
            )
        ),

    next_attempt_at TIMESTAMPTZ NOT NULL,

    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(200),

    last_error TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 6. Supporting indexes
CREATE INDEX IF NOT EXISTS idx_ai_quota_periods_user
    ON ai_quota_periods(user_id, period_start DESC);

CREATE INDEX IF NOT EXISTS idx_ai_reservations_user_status
    ON ai_request_reservations(user_id, status);

CREATE INDEX IF NOT EXISTS idx_ai_reservations_lease
    ON ai_request_reservations(status, lease_expires_at);

CREATE INDEX IF NOT EXISTS idx_ai_ledger_user_created
    ON ai_usage_ledger(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_ledger_period
    ON ai_usage_ledger(period_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_recovery_pending
    ON ai_recovery_jobs(status, next_attempt_at);

-- =========================================================
-- END AI QUOTA SYSTEM
-- =========================================================
COMMIT;
