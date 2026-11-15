BEGIN;

CREATE TABLE IF NOT EXISTS app_users (
    id BIGSERIAL PRIMARY KEY,
    firebase_uid VARCHAR(128) NOT NULL UNIQUE,
    email VARCHAR(255),
    full_name VARCHAR(150),
    phone VARCHAR(30),
    role VARCHAR(20) NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin')),
    account_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (account_status IN ('active', 'suspended', 'deleted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS plan_catalog (
    id BIGSERIAL PRIMARY KEY,
    plan_code VARCHAR(30) NOT NULL UNIQUE,
    plan_name VARCHAR(100) NOT NULL,
    price_egp NUMERIC(10,2) NOT NULL DEFAULT 0
        CHECK (price_egp >= 0),
    duration_days INTEGER NOT NULL
        CHECK (duration_days > 0),
    max_devices INTEGER NOT NULL
        CHECK (max_devices > 0),
    daily_word_limit INTEGER NOT NULL
        CHECK (daily_word_limit >= 0),
    daily_image_limit INTEGER NOT NULL
        CHECK (daily_image_limit >= 0),
    daily_product_search_limit INTEGER NOT NULL
        CHECK (daily_product_search_limit >= 0),
    daily_external_search_limit INTEGER NOT NULL
        CHECK (daily_external_search_limit >= 0),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_users(id),
    plan_id BIGINT NOT NULL REFERENCES plan_catalog(id),
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'expired', 'cancelled')),
    starts_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    payment_reference VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_status
ON subscriptions(user_id, status);

CREATE TABLE IF NOT EXISTS user_devices (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_users(id),
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(150),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, device_id)
);

CREATE TABLE IF NOT EXISTS daily_usage (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_users(id),
    usage_date DATE NOT NULL DEFAULT CURRENT_DATE,
    words_used INTEGER NOT NULL DEFAULT 0 CHECK (words_used >= 0),
    images_used INTEGER NOT NULL DEFAULT 0 CHECK (images_used >= 0),
    product_searches_used INTEGER NOT NULL DEFAULT 0
        CHECK (product_searches_used >= 0),
    external_searches_used INTEGER NOT NULL DEFAULT 0
        CHECK (external_searches_used >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, usage_date)
);

CREATE TABLE IF NOT EXISTS conversations (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_users(id),
    title VARCHAR(200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_conversations_user
ON conversations(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS conversation_messages (
    id BIGSERIAL PRIMARY KEY,
    conversation_id BIGINT NOT NULL
        REFERENCES conversations(id) ON DELETE CASCADE,
    sender VARCHAR(20) NOT NULL
        CHECK (sender IN ('user', 'assistant')),
    message_text TEXT,
    image_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation
ON conversation_messages(conversation_id, created_at);

CREATE TABLE IF NOT EXISTS ai_request_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES app_users(id),
    model_name VARCHAR(100),
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    request_status VARCHAR(20) NOT NULL
        CHECK (request_status IN ('success', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_logs_user_date
ON ai_request_logs(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS app_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO app_settings (setting_key, setting_value)
VALUES ('free_trial_days', '7'::jsonb)
ON CONFLICT (setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value,
    updated_at = NOW();

COMMIT;
