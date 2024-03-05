CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    profile_picture VARCHAR,

    -- Auth
    email_verified BOOLEAN NOT NULL DEFAULT false,
    email_verification_token VARCHAR,
    reset_password_token VARCHAR,
    reset_password_expires_at TIMESTAMP,
    password_hash VARCHAR NOT NULL,
    refresh_token VARCHAR,
    refresh_token_expires_at TIMESTAMP,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
