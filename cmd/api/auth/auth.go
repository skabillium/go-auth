package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"skabillium.io/auth-service/cmd/db"
)

var queries *db.Queries
var ctx context.Context

type ErrorResponse struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

func InitAuth(q *db.Queries, contx context.Context) {
	queries = q
	ctx = contx
}

type CreateUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type CreateUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"`
}

func UuidToString(uid pgtype.UUID) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", uid.Bytes[0:4], uid.Bytes[4:6], uid.Bytes[6:8], uid.Bytes[8:10], uid.Bytes[10:16])
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// @Tags Auth
// @Description Register a new user
// @Success 201 {object} CreateUserResponse
// @Param data body CreateUserRequest true "User credentials"
// @Error 400 {object} ErrorResponse
// @Router /auth/register [POST]
func Register(c echo.Context) error {
	// Validate request
	createUserReq := new(CreateUserRequest)
	if err := c.Bind(createUserReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(createUserReq); err != nil {
		return err
	}

	passwordHash, err := HashPassword(createUserReq.Password)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Error while creating user"})
	}

	user, err := queries.CreateUser(ctx, db.CreateUserParams{
		ID: pgtype.UUID{
			Bytes: uuid.New(),
			Valid: true,
		},
		Email:        createUserReq.Email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		fmt.Println(err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Error while creating user", Error: err.Error()})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    UuidToString(user.ID),
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenStr, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Error while creating jwt", Error: err.Error()})
	}

	/*
		TODO:
		- Send verification email
	*/

	return c.JSON(http.StatusCreated, CreateUserResponse{
		ID: UuidToString(user.ID), Email: user.Email, Token: tokenStr,
	})
}
