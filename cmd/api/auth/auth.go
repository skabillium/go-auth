package auth

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
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

func InitAuth(g *echo.Group, q *db.Queries, contx context.Context) {
	queries = q
	ctx = contx

	g.POST("/auth/register", Register)
	g.POST("/auth/login", Login)
	g.GET("/auth/verify-email/:token", VerifyEmail)
	g.PATCH("/auth/password", UpdatePassword)
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

func GenerateRandomString(length int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func UuidToString(uid pgtype.UUID) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", uid.Bytes[0:4], uid.Bytes[4:6], uid.Bytes[6:8], uid.Bytes[8:10], uid.Bytes[10:16])
}

func StringUuidToBytes(uid string) [16]byte {
	id := []byte(strings.ReplaceAll(uid, "-", ""))
	return [16]byte(id[:16])
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

// type JwtInfo struct {
// 	id    string
// 	email string
// 	exp   int
// }

// func DecodeJwt(jwt string) {}

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
		return echo.NewHTTPError(http.StatusBadRequest, "Error while creating user")
	}

	user, err := queries.CreateUser(ctx, db.CreateUserParams{
		ID: pgtype.UUID{
			Bytes: uuid.New(),
			Valid: true,
		},
		Email:                  createUserReq.Email,
		PasswordHash:           passwordHash,
		EmailVerificationToken: pgtype.Text{String: GenerateRandomString(12), Valid: true},
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while creating user")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    UuidToString(user.ID),
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenStr, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while creating jwt")
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

// @Tags Auth
// @Description Verify email with token
// @Success 204
// @Param token path string true "Email verification token"
// @Router /auth/verify-email/{token} [GET]
func VerifyEmail(c echo.Context) error {
	verificationToken := c.Param("token")

	user, err := queries.GetUserByVerificationToken(ctx, pgtype.Text{String: verificationToken, Valid: true})
	if err != nil {
		// TODO: Handle no rows returned
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	if user.EmailVerified {
		return echo.NewHTTPError(http.StatusBadRequest, "User already verified")
	}

	err = queries.VerifyUserById(ctx, user.ID)
	if err != nil {
		return err
	}

	return c.NoContent(http.StatusNoContent)
}

type UpdatePasswordRequest struct {
	Password string `json:"password" validate:"required"`
}

type Claims struct {
	Id    string
	Email string
	jwt.Claims
}

// @Tags Auth
// @Description Update password
// @Security BearerAuth
// @Param data body UpdatePasswordRequest true "Password to set"
// @Success 204
// @Router /auth/password [PATCH]
func UpdatePassword(c echo.Context) error {
	updatePasswordReq := new(UpdatePasswordRequest)
	if err := c.Bind(updatePasswordReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(updatePasswordReq); err != nil {
		return err
	}

	passwordHash, err := HashPassword(updatePasswordReq.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while updating password")
	}

	tokenStr := strings.Split(c.Request().Header["Authorization"][0], " ")[1]
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	}

	if !token.Valid {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		// TODO: Handle all error cases
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	}

	var userIdStr string
	if userIdStr, ok = claims["id"].(string); !ok {
		// The type assertion succeeded, and str now holds the string value
		// TODO: Handle error
		fmt.Println("Not ok")
	}

	userUuid, err := uuid.Parse(userIdStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while fetching user")
	}

	err = queries.UpdateUserPasswordById(ctx, db.UpdateUserPasswordByIdParams{
		ID:           pgtype.UUID{Bytes: userUuid, Valid: true},
		PasswordHash: passwordHash,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while updating password")
	}

	return c.NoContent(http.StatusNoContent)
}

func ForgotPassword(c echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "Method not implemented")
}

func Refresh(c echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "Method not implemented")
}

func ResendVerificationEmail(c echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "Method not implemented")
}

func Logout(c echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "Method not implemented")
}
