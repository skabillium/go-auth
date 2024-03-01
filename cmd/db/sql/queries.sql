-- name: CreateUser :one
INSERT INTO users (id, email, profile_picture, password_hash, email_verification_token,
refresh_token, refresh_token_expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING * ;
