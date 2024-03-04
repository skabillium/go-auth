-- name: CreateUser :one
INSERT INTO users (id, email, profile_picture, password_hash, email_verification_token,
refresh_token, refresh_token_expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING * ;

-- name: GetUserById :one
SELECT * FROM users WHERE id = $1 ;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 ;

-- name: GetUserByVerificationToken :one
SELECT * FROM users WHERE email_verification_token = $1 ;

-- name: VerifyUserById :exec
UPDATE users SET email_verified='t' WHERE id = $1 ;

-- name: UpdateUserPasswordById :exec
UPDATE users SET password_hash = $2 WHERE id = $1 ;
