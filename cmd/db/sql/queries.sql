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

-- name: GetUserByRefreshToken :one
SELECT * FROM users WHERE refresh_token = $1 ;

-- name: GetUserPasswordResetInfo :one
SELECT id, reset_password_expires_at FROM users WHERE reset_password_token = $1 ;

-- name: VerifyUserById :exec
UPDATE users SET email_verified='t' WHERE id = $1 ;

-- name: UpdateUserPasswordById :exec
UPDATE users SET password_hash = $2 WHERE id = $1 ;

-- name: UpdateUserPasswordResetInfoById :exec
UPDATE users SET reset_password_token = $2, reset_password_expires_at = 
COALESCE(reset_password_expires_at, CURRENT_TIMESTAMP) + INTERVAL '15 minutes' WHERE
id = $1 ;

-- name: RemoveUserRefreshTokenById :exec
UPDATE users SET refresh_token = NULL, refresh_token_expires_at = NULL WHERE 
id = $1 ;

-- name: UpdateUserProfilePictureById :exec
UPDATE users SET profile_picture = $2 WHERE id = $1 ;
