-- =========================================================
-- M3AK DATABASE SCHEMA
-- PostgreSQL
-- Version: 1.0.0
-- =========================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================================================
-- 1. USERS
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(30),

    password_hash TEXT NOT NULL,

    role VARCHAR(20) NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin', 'support')),

    account_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (account_status IN ('active', 'suspended', 'deleted')),

    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    phone_verified BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_email_unique UNIQUE (email)
);

CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique
ON users(phone)
WHERE phone IS NOT NULL;


-- =========================================================
-- 2. PACKAGES
-- =========================================================

CREATE TABLE IF NOT EXISTS packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    code VARCHAR(30) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,

    monthly_price NUMERIC(10,2) NOT NULL DEFAULT 0,
    quarterly_price NUMERIC(10,2) NOT NULL DEFAULT 0,
    semiannual_price NUMERIC(10,2) NOT NULL DEFAULT 0,
    annual_price NUMERIC(10,2) NOT NULL DEFAULT 0,

    duration_days INTEGER NOT NULL,

    daily_word_limit INTEGER NOT NULL,
    daily_image_limit INTEGER NOT NULL,
    daily_product_search_limit INTEGER NOT NULL,
    daily_out_of_range_limit INTEGER NOT NULL,

    max_devices INTEGER NOT NULL DEFAULT 1,
    max_members INTEGER NOT NULL DEFAULT 1,

    is_trial BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT packages_prices_nonnegative CHECK (
        monthly_price >= 0
        AND quarterly_price >= 0
        AND semiannual_price >= 0
        AND annual_price >= 0
    ),

    CONSTRAINT packages_limits_nonnegative CHECK (
        daily_word_limit >= 0
        AND daily_image_limit >= 0
        AND daily_product_search_limit >= 0
        AND daily_out_of_range_limit >= 0
    ),

    CONSTRAINT packages_duration_positive CHECK (duration_days > 0),
    CONSTRAINT packages_devices_positive CHECK (max_devices >= 1),
    CONSTRAINT packages_members_positive CHECK (max_members >= 1)
);


-- =========================================================
-- 3. PACKAGE SEED DATA
-- Prices in EGP
-- =========================================================

INSERT INTO packages (
    code,
    name,
    monthly_price,
    quarterly_price,
    semiannual_price,
    annual_price,
    duration_days,
    daily_word_limit,
    daily_image_limit,
    daily_product_search_limit,
    daily_out_of_range_limit,
    max_devices,
    max_members,
    is_trial
)
VALUES

(
    'TRIAL',
    'Free Trial',
    0, 0, 0, 0,
    4,
    1000,
    2,
    75,
    150,
    1,
    1,
    TRUE
),

(
    'PLUS',
    'PLUS',
    120,
    300,
    650,
    1350,
    30,
    2000,
    3,
    10,
    30,
    1,
    1,
    FALSE
),

(
    'FAMILY',
    'FAMILY',
    230,
    650,
    1300,
    2750,
    30,
    5000,
    6,
    20,
    50,
    3,
    1,
    FALSE
),

(
    'ELITE',
    'ELITE',
    400,
    1100,
    2200,
    4500,
    30,
    10000,
    11,
    35,
    75,
    1,
    3,
    FALSE
)

ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    monthly_price = EXCLUDED.monthly_price,
    quarterly_price = EXCLUDED.quarterly_price,
    semiannual_price = EXCLUDED.semiannual_price,
    annual_price = EXCLUDED.annual_price,
    duration_days = EXCLUDED.duration_days,
    daily_word_limit = EXCLUDED.daily_word_limit,
    daily_image_limit = EXCLUDED.daily_image_limit,
    daily_product_search_limit = EXCLUDED.daily_product_search_limit,
    daily_out_of_range_limit = EXCLUDED.daily_out_of_range_limit,
    max_devices = EXCLUDED.max_devices,
    max_members = EXCLUDED.max_members,
    is_trial = EXCLUDED.is_trial,
    updated_at = NOW();


-- =========================================================
-- 4. SUBSCRIPTIONS
-- =========================================================

CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id),
    package_id UUID NOT NULL REFERENCES packages(id),

    billing_cycle VARCHAR(20) NOT NULL DEFAULT 'monthly'
        CHECK (
            billing_cycle IN (
                'trial',
                'monthly',
                'quarterly',
                'semiannual',
                'annual'
            )
        ),

    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'active',
                'expired',
                'cancelled',
                'suspended'
            )
        ),

    started_at TIMESTAMPTZ,
    ends_at TIMESTAMPTZ,

    trial_expires_at TIMESTAMPTZ,

    auto_renew BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT subscriptions_valid_dates CHECK (
        ends_at IS NULL
        OR started_at IS NULL
        OR ends_at > started_at
    )
);

CREATE INDEX IF NOT EXISTS subscriptions_user_idx
ON subscriptions(user_id);

CREATE INDEX IF NOT EXISTS subscriptions_status_idx
ON subscriptions(status);

CREATE INDEX IF NOT EXISTS subscriptions_expiry_idx
ON subscriptions(ends_at);


-- =========================================================
-- 5. SUBSCRIPTION MEMBERS
-- ELITE: Three email accounts total
-- FAMILY: One subscribing email
-- =========================================================

CREATE TABLE IF NOT EXISTS subscription_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    subscription_id UUID NOT NULL
        REFERENCES subscriptions(id) ON DELETE CASCADE,

    user_id UUID NOT NULL REFERENCES users(id),

    member_email VARCHAR(255) NOT NULL,

    member_role VARCHAR(20) NOT NULL DEFAULT 'member'
        CHECK (member_role IN ('owner', 'member')),

    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'removed')),

    invited_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    joined_at TIMESTAMPTZ,

    UNIQUE (subscription_id, member_email),
    UNIQUE (subscription_id, user_id)
);

CREATE INDEX IF NOT EXISTS subscription_members_user_idx
ON subscription_members(user_id);


-- =========================================================
-- 6. DEVICES
-- =========================================================

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    subscription_id UUID REFERENCES subscriptions(id)
        ON DELETE SET NULL,

    device_identifier VARCHAR(255) NOT NULL,
    device_name VARCHAR(150),

    platform VARCHAR(50),

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (user_id, device_identifier)
);

CREATE INDEX IF NOT EXISTS devices_user_idx
ON devices(user_id);

CREATE INDEX IF NOT EXISTS devices_subscription_idx
ON devices(subscription_id);


-- =========================================================
-- 7. VERIFICATION CODES
-- =========================================================

CREATE TABLE IF NOT EXISTS verification_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID REFERENCES users(id) ON DELETE CASCADE,

    destination VARCHAR(255) NOT NULL,

    code_hash TEXT NOT NULL,

    purpose VARCHAR(30) NOT NULL
        CHECK (
            purpose IN (
                'email_verification',
                'phone_verification',
                'password_reset'
            )
        ),

    expires_at TIMESTAMPTZ NOT NULL,

    attempts INTEGER NOT NULL DEFAULT 0,

    verified_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS verification_destination_idx
ON verification_codes(destination, purpose);

CREATE INDEX IF NOT EXISTS verification_expiry_idx
ON verification_codes(expires_at);


-- =========================================================
-- 8. PASSWORD RESET TOKENS
-- =========================================================

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    token_hash TEXT NOT NULL UNIQUE,

    expires_at TIMESTAMPTZ NOT NULL,

    used_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS password_reset_user_idx
ON password_reset_tokens(user_id);


-- =========================================================
-- 9. DAILY USAGE
-- =========================================================

CREATE TABLE IF NOT EXISTS usage_daily (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    usage_date DATE NOT NULL DEFAULT CURRENT_DATE,

    words_used INTEGER NOT NULL DEFAULT 0,
    images_used INTEGER NOT NULL DEFAULT 0,
    product_searches_used INTEGER NOT NULL DEFAULT 0,
    out_of_range_searches_used INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT usage_nonnegative CHECK (
        words_used >= 0
        AND images_used >= 0
        AND product_searches_used >= 0
        AND out_of_range_searches_used >= 0
    ),

    UNIQUE (user_id, usage_date)
);

CREATE INDEX IF NOT EXISTS usage_daily_user_date_idx
ON usage_daily(user_id, usage_date);


-- =========================================================
-- 10. API RATE LIMITS
-- =========================================================

CREATE TABLE IF NOT EXISTS api_rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    rate_key VARCHAR(255) NOT NULL UNIQUE,

    request_count INTEGER NOT NULL DEFAULT 0,

    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT rate_count_nonnegative CHECK (request_count >= 0)
);

CREATE INDEX IF NOT EXISTS api_rate_limits_expiry_idx
ON api_rate_limits(expires_at);


-- =========================================================
-- 11. ORDERS
-- =========================================================

CREATE TABLE IF NOT EXISTS orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id),

    order_number VARCHAR(80) NOT NULL UNIQUE,

    order_type VARCHAR(50) NOT NULL DEFAULT 'service',

    description TEXT,

    status VARCHAR(30) NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'confirmed',
                'processing',
                'completed',
                'cancelled',
                'rejected'
            )
        ),

    total_amount NUMERIC(10,2) NOT NULL DEFAULT 0,

    currency VARCHAR(10) NOT NULL DEFAULT 'EGP',

    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT orders_amount_nonnegative CHECK (total_amount >= 0)
);

CREATE INDEX IF NOT EXISTS orders_user_idx
ON orders(user_id);

CREATE INDEX IF NOT EXISTS orders_status_idx
ON orders(status);


-- =========================================================
-- 12. NOTIFICATIONS
-- =========================================================

CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,

    notification_type VARCHAR(50) NOT NULL DEFAULT 'general',

    is_read BOOLEAN NOT NULL DEFAULT FALSE,

    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    read_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS notifications_user_created_idx
ON notifications(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS notifications_unread_idx
ON notifications(user_id, is_read);


-- =========================================================
-- 13. SUPPORT TICKETS
-- =========================================================

CREATE TABLE IF NOT EXISTS support_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id),

    subject VARCHAR(200) NOT NULL,

    message TEXT NOT NULL,

    category VARCHAR(50) NOT NULL DEFAULT 'general',

    status VARCHAR(30) NOT NULL DEFAULT 'open'
        CHECK (
            status IN (
                'open',
                'in_progress',
                'waiting_user',
                'resolved',
                'closed'
            )
        ),

    priority VARCHAR(20) NOT NULL DEFAULT 'normal'
        CHECK (priority IN ('low', 'normal', 'high', 'urgent')),

    admin_reply TEXT,

    replied_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS support_tickets_user_idx
ON support_tickets(user_id);

CREATE INDEX IF NOT EXISTS support_tickets_status_idx
ON support_tickets(status);


-- =========================================================
-- 14. PAYMENT TRANSACTIONS
-- =========================================================

CREATE TABLE IF NOT EXISTS payment_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id),

    subscription_id UUID REFERENCES subscriptions(id),

    order_id UUID REFERENCES orders(id),

    provider VARCHAR(50) NOT NULL DEFAULT 'paymob',

    provider_transaction_id VARCHAR(255),

    provider_order_id VARCHAR(255),

    amount NUMERIC(10,2) NOT NULL,

    currency VARCHAR(10) NOT NULL DEFAULT 'EGP',

    status VARCHAR(30) NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'paid',
                'failed',
                'cancelled',
                'refunded'
            )
        ),

    payment_method VARCHAR(50),

    webhook_verified BOOLEAN NOT NULL DEFAULT FALSE,

    webhook_payload JSONB,

    paid_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT payments_amount_nonnegative CHECK (amount >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS payment_provider_transaction_unique
ON payment_transactions(provider, provider_transaction_id)
WHERE provider_transaction_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS payment_provider_order_unique
ON payment_transactions(provider, provider_order_id)
WHERE provider_order_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS payments_user_idx
ON payment_transactions(user_id);

CREATE INDEX IF NOT EXISTS payments_status_idx
ON payment_transactions(status);


-- =========================================================
-- 15. AUDIT LOGS
-- =========================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    action VARCHAR(150) NOT NULL,

    entity_type VARCHAR(100),

    entity_id VARCHAR(150),

    ip_address INET,

    user_agent TEXT,

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_user_idx
ON audit_logs(user_id);

CREATE INDEX IF NOT EXISTS audit_logs_created_idx
ON audit_logs(created_at DESC);


-- =========================================================
-- 16. UPDATED_AT TRIGGER FUNCTION
-- =========================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- =========================================================
-- 17. UPDATED_AT TRIGGERS
-- =========================================================

DROP TRIGGER IF EXISTS users_updated_at ON users;
CREATE TRIGGER users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


DROP TRIGGER IF EXISTS packages_updated_at ON packages;
CREATE TRIGGER packages_updated_at
BEFORE UPDATE ON packages
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


DROP TRIGGER IF EXISTS subscriptions_updated_at ON subscriptions;
CREATE TRIGGER subscriptions_updated_at
BEFORE UPDATE ON subscriptions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


DROP TRIGGER IF EXISTS usage_daily_updated_at ON usage_daily;
CREATE TRIGGER usage_daily_updated_at
BEFORE UPDATE ON usage_daily
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


DROP TRIGGER IF EXISTS orders_updated_at ON orders;
CREATE TRIGGER orders_updated_at
BEFORE UPDATE ON orders
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


DROP TRIGGER IF EXISTS support_tickets_updated_at ON support_tickets;
CREATE TRIGGER support_tickets_updated_at
BEFORE UPDATE ON support_tickets
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


DROP TRIGGER IF EXISTS payment_transactions_updated_at ON payment_transactions;
CREATE TRIGGER payment_transactions_updated_at
BEFORE UPDATE ON payment_transactions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
    -- =========================================================
-- M3AK DATABASE SCHEMA - PHASE 2
-- Merchants, Catalog, Offers, Messages, Budget, Protection
-- =========================================================

BEGIN;

-- =========================================================
-- 18. USER ROLES
-- =========================================================

ALTER TABLE users
DROP CONSTRAINT IF EXISTS users_role_check;

ALTER TABLE users
ADD CONSTRAINT users_role_check
CHECK (role IN ('user', 'admin', 'support', 'merchant'));


-- =========================================================
-- 19. MERCHANTS
-- الإدارة تنشئ وتدير بيانات المتاجر
-- =========================================================

CREATE TABLE IF NOT EXISTS merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL UNIQUE
        REFERENCES users(id) ON DELETE RESTRICT,

    business_name VARCHAR(200) NOT NULL,
    business_type VARCHAR(100),

    description TEXT,
    phone VARCHAR(30),
    email VARCHAR(255),

    address TEXT,
    city VARCHAR(100),
    latitude NUMERIC(10,7),
    longitude NUMERIC(10,7),

    logo_url TEXT,
    cover_image_url TEXT,

    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'suspended', 'closed')),

    created_by_admin UUID REFERENCES users(id),
    is_visible BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS merchants_status_idx
ON merchants(status);

CREATE INDEX IF NOT EXISTS merchants_city_idx
ON merchants(city);


-- =========================================================
-- 20. MERCHANT SUBSCRIPTION PLANS
-- الأسعار تضاف لاحقًا بواسطة الإدارة بعد اعتمادها
-- =========================================================

CREATE TABLE IF NOT EXISTS merchant_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    code VARCHAR(30) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,

    monthly_price NUMERIC(10,2),
    quarterly_price NUMERIC(10,2),
    semiannual_price NUMERIC(10,2),
    annual_price NUMERIC(10,2),

    description TEXT,
    features JSONB NOT NULL DEFAULT '{}'::JSONB,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT merchant_plan_prices_nonnegative CHECK (
        (monthly_price IS NULL OR monthly_price >= 0)
        AND (quarterly_price IS NULL OR quarterly_price >= 0)
        AND (semiannual_price IS NULL OR semiannual_price >= 0)
        AND (annual_price IS NULL OR annual_price >= 0)
    )
);


-- =========================================================
-- 21. MERCHANT SUBSCRIPTIONS
-- شهر مجاني عند بداية التعاقد
-- =========================================================

CREATE TABLE IF NOT EXISTS merchant_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    merchant_id UUID NOT NULL
        REFERENCES merchants(id) ON DELETE RESTRICT,

    plan_id UUID REFERENCES merchant_plans(id),

    billing_cycle VARCHAR(20) NOT NULL DEFAULT 'monthly'
        CHECK (billing_cycle IN (
            'monthly', 'quarterly', 'semiannual', 'annual', 'free_trial'
        )),

    status VARCHAR(20) NOT NULL DEFAULT 'trial'
        CHECK (status IN (
            'trial', 'active', 'expired', 'suspended', 'cancelled'
        )),

    amount NUMERIC(10,2) NOT NULL DEFAULT 0,
    currency VARCHAR(10) NOT NULL DEFAULT 'EGP',

    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ends_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),

    reminder_sent_at TIMESTAMPTZ,
    renewed_at TIMESTAMPTZ,

    payment_method VARCHAR(50),
    auto_renew BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT merchant_subscription_dates CHECK (ends_at > started_at),
    CONSTRAINT merchant_subscription_amount CHECK (amount >= 0)
);

CREATE INDEX IF NOT EXISTS merchant_subscriptions_merchant_idx
ON merchant_subscriptions(merchant_id);

CREATE INDEX IF NOT EXISTS merchant_subscriptions_expiry_idx
ON merchant_subscriptions(ends_at, status);


-- =========================================================
-- 22. CATALOG ITEMS
-- المنتجات والخدمات التي تتحكم بها الإدارة فقط
-- =========================================================

CREATE TABLE IF NOT EXISTS catalog_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    merchant_id UUID NOT NULL
        REFERENCES merchants(id) ON DELETE RESTRICT,

    section_code VARCHAR(60) NOT NULL,
    category_name VARCHAR(150),

    item_type VARCHAR(20) NOT NULL
        CHECK (item_type IN ('product', 'service')),

    name VARCHAR(200) NOT NULL,
    description TEXT,

    specifications JSONB NOT NULL DEFAULT '{}'::JSONB,

    price NUMERIC(10,2),
    currency VARCHAR(10) NOT NULL DEFAULT 'EGP',

    stock_quantity INTEGER,

    main_image_url TEXT,

    status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'published', 'hidden', 'archived')),

    created_by_admin UUID REFERENCES users(id),
    updated_by_admin UUID REFERENCES users(id),

    published_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT catalog_price_nonnegative CHECK (
        price IS NULL OR price >= 0
    ),

    CONSTRAINT catalog_stock_nonnegative CHECK (
        stock_quantity IS NULL OR stock_quantity >= 0
    )
);

CREATE INDEX IF NOT EXISTS catalog_items_merchant_idx
ON catalog_items(merchant_id);

CREATE INDEX IF NOT EXISTS catalog_items_section_idx
ON catalog_items(section_code, status);

CREATE INDEX IF NOT EXISTS catalog_items_published_idx
ON catalog_items(status, published_at DESC);


-- =========================================================
-- 23. CATALOG ITEM IMAGES
-- =========================================================

CREATE TABLE IF NOT EXISTS catalog_item_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    item_id UUID NOT NULL
        REFERENCES catalog_items(id) ON DELETE CASCADE,

    image_url TEXT NOT NULL,
    alt_text VARCHAR(250),

    sort_order INTEGER NOT NULL DEFAULT 0,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT catalog_image_sort_nonnegative CHECK (sort_order >= 0)
);

CREATE INDEX IF NOT EXISTS catalog_item_images_item_idx
ON catalog_item_images(item_id, sort_order);


-- =========================================================
-- 24. OFFERS AND DISCOUNTS
-- =========================================================

CREATE TABLE IF NOT EXISTS offers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    merchant_id UUID NOT NULL
        REFERENCES merchants(id) ON DELETE RESTRICT,

    item_id UUID
        REFERENCES catalog_items(id) ON DELETE CASCADE,

    title VARCHAR(200) NOT NULL,
    description TEXT,

    image_url TEXT,

    original_price NUMERIC(10,2) NOT NULL,
    discounted_price NUMERIC(10,2) NOT NULL,

    discount_percentage NUMERIC(5,2)
        GENERATED ALWAYS AS (
            CASE
                WHEN original_price > 0
                THEN ROUND(
                    ((original_price - discounted_price)
                    / original_price) * 100,
                    2
                )
                ELSE 0
            END
        ) STORED,

    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,

    status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'published', 'hidden', 'expired')),

    created_by_admin UUID REFERENCES users(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT offer_prices_valid CHECK (
        original_price > 0
        AND discounted_price >= 0
        AND discounted_price < original_price
    ),

    CONSTRAINT offer_dates_valid CHECK (ends_at > starts_at)
);

CREATE INDEX IF NOT EXISTS offers_merchant_idx
ON offers(merchant_id);

CREATE INDEX IF NOT EXISTS offers_active_idx
ON offers(status, starts_at, ends_at);


-- =========================================================
-- 25. ORDERS - MERCHANT ASSIGNMENT
-- =========================================================

ALTER TABLE orders
ADD COLUMN IF NOT EXISTS merchant_id UUID
REFERENCES merchants(id) ON DELETE RESTRICT;

ALTER TABLE orders
ADD COLUMN IF NOT EXISTS customer_notes TEXT;

ALTER TABLE orders
ADD COLUMN IF NOT EXISTS merchant_notes TEXT;

CREATE INDEX IF NOT EXISTS orders_merchant_idx
ON orders(merchant_id, created_at DESC);


-- =========================================================
-- 26. ORDER ITEMS
-- =========================================================

CREATE TABLE IF NOT EXISTS order_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    order_id UUID NOT NULL
        REFERENCES orders(id) ON DELETE CASCADE,

    item_id UUID REFERENCES catalog_items(id) ON DELETE SET NULL,

    item_name VARCHAR(200) NOT NULL,
    item_type VARCHAR(20) NOT NULL
        CHECK (item_type IN ('product', 'service')),

    quantity INTEGER NOT NULL DEFAULT 1,
    unit_price NUMERIC(10,2) NOT NULL,
    total_price NUMERIC(10,2) NOT NULL,

    item_snapshot JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT order_item_quantity_positive CHECK (quantity > 0),
    CONSTRAINT order_item_prices_valid CHECK (
        unit_price >= 0 AND total_price >= 0
    )
);

CREATE INDEX IF NOT EXISTS order_items_order_idx
ON order_items(order_id);


-- =========================================================
-- 27. CUSTOMER-MERCHANT CONVERSATIONS
-- =========================================================

CREATE TABLE IF NOT EXISTS conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    customer_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    merchant_id UUID NOT NULL
        REFERENCES merchants(id) ON DELETE RESTRICT,

    order_id UUID REFERENCES orders(id) ON DELETE SET NULL,

    status VARCHAR(20) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'closed', 'archived')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (customer_id, merchant_id, order_id)
);

CREATE INDEX IF NOT EXISTS conversations_customer_idx
ON conversations(customer_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS conversations_merchant_idx
ON conversations(merchant_id, updated_at DESC);


-- =========================================================
-- 28. CONVERSATION MESSAGES
-- =========================================================

CREATE TABLE IF NOT EXISTS conversation_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    conversation_id UUID NOT NULL
        REFERENCES conversations(id) ON DELETE CASCADE,

    sender_user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    message_text TEXT NOT NULL,

    attachment_url TEXT,

    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    read_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT conversation_message_not_empty
        CHECK (LENGTH(TRIM(message_text)) > 0 OR attachment_url IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS conversation_messages_conversation_idx
ON conversation_messages(conversation_id, created_at);


-- =========================================================
-- 29. PERSONAL BUDGET RECORDS
-- بيانات مالية خاصة بكل مستخدم
-- =========================================================

CREATE TABLE IF NOT EXISTS budget_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    record_type VARCHAR(20) NOT NULL
        CHECK (record_type IN ('income', 'expense', 'saving')),

    title VARCHAR(200) NOT NULL,
    category VARCHAR(100),

    amount NUMERIC(12,2) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'EGP',

    record_date DATE NOT NULL DEFAULT CURRENT_DATE,

    notes TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT budget_amount_positive CHECK (amount > 0)
);

CREATE INDEX IF NOT EXISTS budget_records_user_date_idx
ON budget_records(user_id, record_date DESC);


-- =========================================================
-- 30. PURCHASE PROTECTION
-- =========================================================

CREATE TABLE IF NOT EXISTS protected_purchases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    order_id UUID REFERENCES orders(id) ON DELETE SET NULL,

    merchant_id UUID REFERENCES merchants(id) ON DELETE SET NULL,

    product_name VARCHAR(200) NOT NULL,
    purchase_date DATE,

    purchase_price NUMERIC(10,2),
    currency VARCHAR(10) NOT NULL DEFAULT 'EGP',

    invoice_reference VARCHAR(200),
    invoice_file_url TEXT,

    notes TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT protected_purchase_price_valid CHECK (
        purchase_price IS NULL OR purchase_price >= 0
    )
);

CREATE INDEX IF NOT EXISTS protected_purchases_user_idx
ON protected_purchases(user_id, created_at DESC);


-- =========================================================
-- 31. WARRANTIES
-- =========================================================

CREATE TABLE IF NOT EXISTS warranties (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    purchase_id UUID NOT NULL
        REFERENCES protected_purchases(id) ON DELETE CASCADE,

    provider_name VARCHAR(200),

    warranty_number VARCHAR(150),

    starts_at DATE,
    ends_at DATE,

    terms TEXT,
    document_url TEXT,

    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'expired', 'claimed', 'cancelled')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT warranty_dates_valid CHECK (
        ends_at IS NULL OR starts_at IS NULL OR ends_at >= starts_at
    )
);

CREATE INDEX IF NOT EXISTS warranties_purchase_idx
ON warranties(purchase_id);

CREATE INDEX IF NOT EXISTS warranties_expiry_idx
ON warranties(ends_at, status);


-- =========================================================
-- 32. PURCHASE COMPLAINTS
-- =========================================================

CREATE TABLE IF NOT EXISTS purchase_complaints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    purchase_id UUID NOT NULL
        REFERENCES protected_purchases(id) ON DELETE CASCADE,

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    complaint_type VARCHAR(80) NOT NULL,

    subject VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,

    status VARCHAR(25) NOT NULL DEFAULT 'open'
        CHECK (status IN (
            'open', 'under_review', 'waiting_customer',
            'resolved', 'rejected', 'closed'
        )),

    admin_response TEXT,
    resolved_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS purchase_complaints_user_idx
ON purchase_complaints(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS purchase_complaints_status_idx
ON purchase_complaints(status);


-- =========================================================
-- 33. UPDATED_AT TRIGGERS FOR NEW TABLES
-- =========================================================

DROP TRIGGER IF EXISTS merchants_updated_at ON merchants;
CREATE TRIGGER merchants_updated_at
BEFORE UPDATE ON merchants
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS merchant_plans_updated_at ON merchant_plans;
CREATE TRIGGER merchant_plans_updated_at
BEFORE UPDATE ON merchant_plans
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS merchant_subscriptions_updated_at ON merchant_subscriptions;
CREATE TRIGGER merchant_subscriptions_updated_at
BEFORE UPDATE ON merchant_subscriptions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS catalog_items_updated_at ON catalog_items;
CREATE TRIGGER catalog_items_updated_at
BEFORE UPDATE ON catalog_items
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS offers_updated_at ON offers;
CREATE TRIGGER offers_updated_at
BEFORE UPDATE ON offers
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS conversations_updated_at ON conversations;
CREATE TRIGGER conversations_updated_at
BEFORE UPDATE ON conversations
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS budget_records_updated_at ON budget_records;
CREATE TRIGGER budget_records_updated_at
BEFORE UPDATE ON budget_records
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS protected_purchases_updated_at ON protected_purchases;
CREATE TRIGGER protected_purchases_updated_at
BEFORE UPDATE ON protected_purchases
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS warranties_updated_at ON warranties;
CREATE TRIGGER warranties_updated_at
BEFORE UPDATE ON warranties
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS purchase_complaints_updated_at ON purchase_complaints;
CREATE TRIGGER purchase_complaints_updated_at
BEFORE UPDATE ON purchase_complaints
FOR EACH ROW EXECUTE FUNCTION 
COMMIT;


-- =========================================================
-- END OF M3AK DATABASE SCHEMA
-- =========================================================
