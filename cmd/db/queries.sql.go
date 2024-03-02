// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: queries.sql

package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, email, profile_picture, password_hash, email_verification_token,
refresh_token, refresh_token_expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, profile_picture, email_verified, email_verification_token, password_hash, refresh_token, refresh_token_expires_at, created_at, updated_at
`

type CreateUserParams struct {
	ID                     pgtype.UUID
	Email                  string
	ProfilePicture         pgtype.Text
	PasswordHash           string
	EmailVerificationToken pgtype.Text
	RefreshToken           pgtype.Text
	RefreshTokenExpiresAt  pgtype.Timestamp
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRow(ctx, createUser,
		arg.ID,
		arg.Email,
		arg.ProfilePicture,
		arg.PasswordHash,
		arg.EmailVerificationToken,
		arg.RefreshToken,
		arg.RefreshTokenExpiresAt,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.ProfilePicture,
		&i.EmailVerified,
		&i.EmailVerificationToken,
		&i.PasswordHash,
		&i.RefreshToken,
		&i.RefreshTokenExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, email, profile_picture, email_verified, email_verification_token, password_hash, refresh_token, refresh_token_expires_at, created_at, updated_at FROM users WHERE email = $1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRow(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.ProfilePicture,
		&i.EmailVerified,
		&i.EmailVerificationToken,
		&i.PasswordHash,
		&i.RefreshToken,
		&i.RefreshTokenExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getUserByVerificationToken = `-- name: GetUserByVerificationToken :one
SELECT id, email, profile_picture, email_verified, email_verification_token, password_hash, refresh_token, refresh_token_expires_at, created_at, updated_at FROM users WHERE email_verification_token = $1
`

func (q *Queries) GetUserByVerificationToken(ctx context.Context, emailVerificationToken pgtype.Text) (User, error) {
	row := q.db.QueryRow(ctx, getUserByVerificationToken, emailVerificationToken)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.ProfilePicture,
		&i.EmailVerified,
		&i.EmailVerificationToken,
		&i.PasswordHash,
		&i.RefreshToken,
		&i.RefreshTokenExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const verifyUserById = `-- name: VerifyUserById :exec
UPDATE users SET email_verified='t' WHERE id = $1
`

func (q *Queries) VerifyUserById(ctx context.Context, id pgtype.UUID) error {
	_, err := q.db.Exec(ctx, verifyUserById, id)
	return err
}
