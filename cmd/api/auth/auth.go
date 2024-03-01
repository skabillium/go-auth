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

func ComparePassword(password string, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

func GenerateJwt(id string, email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    id,
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

// @Tags Auth
// @Description Register a new user
// @Success 201 {object} CreateUserResponse
// @Param data body CreateUserRequest true "User credentials"
// @Error 400 {object} ErrorResponse
// @Router /auth/register [POST]
func Register(c echo.Context) error {
	/*
		TODO:
		- Send verification email
		- Handle profile picture
	*/

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

	return c.JSON(http.StatusCreated, CreateUserResponse{
		ID: UuidToString(user.ID), Email: user.Email, Token: tokenStr,
	})
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"`
}

// @Tags Auth
// @Description Login with credentials
// @Param data body LoginRequest true "User credentials"
// @Success 201 {object} LoginResponse
// @Error 400 {object} ErrorResponse
// @Router /auth/login [POST]
func Login(c echo.Context) error {
	loginReq := new(LoginRequest)
	if err := c.Bind(loginReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(loginReq); err != nil {
		return err
	}

	user, err := queries.GetUserByEmail(ctx, loginReq.Email)
	if err != nil {
		return err
	}

	isCorrect, err := ComparePassword(loginReq.Password, user.PasswordHash)
	if err != nil {
		return err
	}

	if !isCorrect {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	if !user.EmailVerified {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not verified")
	}

	userId := UuidToString(user.ID)
	token, err := GenerateJwt(userId, user.Email)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusCreated, LoginResponse{
		ID: userId, Email: user.Email, Token: token,
	})
}
