-- M3AK - Unified Production Database Schema for PostgreSQL
-- Fixed: Dynamic trial package assignment moved to application logic.

CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    max_words INT NOT NULL,
    max_images INT NOT NULL,
    price NUMERIC(10, 2) NOT NULL,
    duration_days INT NOT NULL
);

INSERT INTO packages (name, max_words, max_images, price, duration_days) 
VALUES 
('trial', 5000, 3, 0.00, 4),
('basic', 50000, 50, 199.00, 30),
('premium', 200000, 300, 499.00, 30)
ON CONFLICT (name) DO UPDATE 
SET 
    max_words = EXCLUDED.max_words,
    max_images = EXCLUDED.max_images,
    price = EXCLUDED.price,
    duration_days = EXCLUDED.duration_days;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(30) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(30) DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    trial_started_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    firebase_uid VARCHAR(128) UNIQUE,
    agreed_terms BOOLEAN DEFAULT FALSE,
    agreed_privacy BOOLEAN DEFAULT FALSE,
    is_subscribed BOOLEAN DEFAULT FALSE,
    package_id INT REFERENCES packages(id),
    subscription_expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    words_used_count INT DEFAULT 0,
    images_used_count INT DEFAULT 0,
    token_version INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at BIGINT NOT NULL,
    is_used BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS rate_limits (
    ip VARCHAR(45) NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    hit_count INT DEFAULT 1,
    window_start BIGINT NOT NULL,
    PRIMARY KEY (ip, endpoint)
);

CREATE TABLE IF NOT EXISTS chat_history (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    image_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subscriptions_payments (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    transaction_id VARCHAR(255) UNIQUE NOT NULL,
    amount NUMERIC(10, 2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'EGP',
    status VARCHAR(50) DEFAULT 'pending',
    gateway VARCHAR(50) DEFAULT 'paymob',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    order_number VARCHAR(100) UNIQUE NOT NULL,
    section_name VARCHAR(100) NOT NULL,
    details TEXT NOT NULL,
    total NUMERIC(10, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'قيد المراجعة',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_tickets (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    subject VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'مفتوحة',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_rate_limits ON rate_limits(ip, endpoint);
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_transaction ON subscriptions_payments(transaction_id);
