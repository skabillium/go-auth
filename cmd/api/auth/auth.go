package auth

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"skabillium.io/auth-service/cmd/db"
	"skabillium.io/auth-service/cmd/shared/blacklist"
	"skabillium.io/auth-service/cmd/shared/email"
	"skabillium.io/auth-service/cmd/shared/tokens"
	"skabillium.io/auth-service/cmd/shared/util"
)

var (
	queries     *db.Queries
	redisClient *redis.Client
	blist       *blacklist.BlacklistService
	ctx         context.Context
)

type ErrorResponse struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

func InitAuth(g *echo.Group, q *db.Queries, r *redis.Client, contx context.Context) {
	queries = q
	redisClient = r
	ctx = contx
	blist = blacklist.NewBlacklistService(ctx, redisClient)

	IsLoggedIn := echojwt.JWT([]byte(os.Getenv("JWT_SECRET")))

	g.GET("/auth/verify-email/:token", VerifyEmail)
	g.GET("/auth/refresh", Refresh, IsLoggedIn)

	g.POST("/auth/register", Register)
	g.POST("/auth/login", Login)
	g.POST("/auth/logout", Logout, IsLoggedIn)
	g.POST("/auth/forgot-password", ForgotPassword)
	g.POST("/auth/reset-password", ResetPassword)

	g.PATCH("/auth/password", UpdatePassword, IsLoggedIn)
}

type CreateUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type CreateUserResponse struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
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

	passwordHash, err := util.HashPassword(createUserReq.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while creating user")
	}

	refreshToken := tokens.GenerateRefreshToken()
	verificationToken := util.GenerateRandomString(12)

	user, err := queries.CreateUser(ctx, db.CreateUserParams{
		ID: pgtype.UUID{
			Bytes: uuid.New(),
			Valid: true,
		},
		Email:                  createUserReq.Email,
		PasswordHash:           passwordHash,
		EmailVerificationToken: pgtype.Text{String: verificationToken, Valid: true},
		RefreshToken:           pgtype.Text{String: refreshToken, Valid: true},
		RefreshTokenExpiresAt:  pgtype.Timestamp{Time: time.Now().AddDate(0, 1, 0), Valid: true},
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while creating user")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":           util.UuidToString(user.ID),
		"email":        user.Email,
		"refreshToken": refreshToken,
		"exp":          time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenStr, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while creating jwt")
	}

	verificationUrl := os.Getenv("SERVER_URL") + "/v1/auth/verify-email/" + verificationToken
	email.SendRegistrationEmail(createUserReq.Email, verificationUrl)

	return c.JSON(http.StatusCreated, CreateUserResponse{
		ID: util.UuidToString(user.ID), Email: user.Email, Token: tokenStr,
		RefreshToken: refreshToken,
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

	isCorrect, err := util.ComparePassword(loginReq.Password, user.PasswordHash)
	if err != nil {
		return err
	}

	if !isCorrect {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	if !user.EmailVerified {
		return echo.NewHTTPError(http.StatusUnauthorized, "User not verified")
	}

	userId := util.UuidToString(user.ID)
	refreshToken := tokens.GenerateRefreshToken() // TODO: Save token to db
	token, err := util.GenerateJwt(util.GenerateJwtOptions{
		ID:           userId,
		Email:        user.Email,
		RefreshToken: refreshToken,
	})
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

	passwordHash, err := util.HashPassword(updatePasswordReq.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while updating password")
	}

	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while fetching token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while fetching token")
	}

	var userIdStr string
	if userIdStr, ok = claims["id"].(string); !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while fetching token")
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

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// @Tags Auth
// @Description Trigger a "forgot password email"
// @Success 204
// @Param data body ForgotPasswordRequest true "User email"
// @Error 400 {object} ErrorResponse
// @Router /auth/forgot-password [POST]
func ForgotPassword(c echo.Context) error {
	forgotPasswordReq := new(ForgotPasswordRequest)
	if err := c.Bind(forgotPasswordReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(forgotPasswordReq); err != nil {
		return err
	}

	resetPasswordToken := util.GenerateRandomString(12)
	user, err := queries.GetUserByEmail(ctx, forgotPasswordReq.Email)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	err = queries.UpdateUserPasswordResetInfoById(ctx, db.UpdateUserPasswordResetInfoByIdParams{
		ID:                 user.ID,
		ResetPasswordToken: pgtype.Text{String: resetPasswordToken, Valid: true},
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}

	passwordResetUrl := os.Getenv("FRONTEND_URL") + "/reset-password/" + resetPasswordToken
	email.SendPasswordResetEmail(user.Email, passwordResetUrl)

	return c.NoContent(http.StatusNoContent)
}

type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// @Tags Auth
// @Description Reset password from token
// @Success 204
// @Param data body ResetPasswordRequest true "Token and new password"
// @Error 400 {object} ErrorResponse
// @Router /auth/reset-password [POST]
func ResetPassword(c echo.Context) error {
	resetPasswordReq := new(ResetPasswordRequest)
	if err := c.Bind(resetPasswordReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(resetPasswordReq); err != nil {
		return err
	}

	user, err := queries.GetUserPasswordResetInfo(ctx, pgtype.Text{String: resetPasswordReq.Token, Valid: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	if user.ResetPasswordExpiresAt.Time.Before(time.Now()) {
		return echo.NewHTTPError(http.StatusBadRequest, "Password reset has expired")
	}

	passwordHash, err := util.HashPassword(resetPasswordReq.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while updating password")
	}

	err = queries.UpdateUserPasswordById(ctx, db.UpdateUserPasswordByIdParams{
		ID:           user.ID,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while updating password")
	}

	return c.NoContent(http.StatusNoContent)
}

type RefreshJwtResponse struct {
	Jwt string `json:"jwt"`
}

// @Tags Auth
// @Description Refresh JWT
// @Security BearerAuth
// @Success 201 {object} RefreshJwtResponse
// @Router /auth/refresh [GET]
func Refresh(c echo.Context) error {
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while fetching token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while fetching token")
	}

	refreshToken, ok := claims["refreshToken"].(string)
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while fetching token")
	}

	user, err := queries.GetUserByRefreshToken(ctx, pgtype.Text{String: refreshToken, Valid: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while refreshing token")
	}

	if user.RefreshTokenExpiresAt.Time.Before(time.Now()) {
		return echo.NewHTTPError(http.StatusBadRequest, "Refresh token has expired")
	}

	newToken, err := util.GenerateJwt(util.GenerateJwtOptions{
		ID:           util.UuidToString(user.ID),
		Email:        user.Email,
		RefreshToken: refreshToken,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while creating token")
	}

	return c.JSON(http.StatusCreated, RefreshJwtResponse{Jwt: newToken})
}

type ResendVerificationEmailRequest struct {
	Email string `json:"email" validate:"email,required"`
}

// @Tags Auth
// @Description Refresh JWT
// @Security BearerAuth
// @Param data body ResendVerificationEmailRequest true "email address"
// @Success 204
// @Router /auth/verify-email/resend [POST]
func ResendVerificationEmail(c echo.Context) error {
	resendVerificationEmailReq := new(ResendVerificationEmailRequest)
	if err := c.Bind(resendVerificationEmailReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(resendVerificationEmailReq); err != nil {
		return err
	}

	user, err := queries.GetUserByEmail(ctx, resendVerificationEmailReq.Email)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	if user.EmailVerified {
		return echo.NewHTTPError(http.StatusBadRequest, "User already verified")
	}

	verificationUrl := os.Getenv("SERVER_URL") + "/v1/auth/verify-email/" + user.EmailVerificationToken.String
	email.SendVerificationEmail(user.Email, verificationUrl)

	return c.NoContent(http.StatusNoContent)
}

// @Tags Auth
// @Description Logout
// @Security BearerAuth
// @Success 204
// @Router /auth/logout [POST]
func Logout(c echo.Context) error {
	// TODO: Find a better way to decode tokens
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while fetching token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while fetching token")
	}

	id, ok := claims["id"].(string)
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Error while fetching token")
	}

	userUuid, err := uuid.Parse(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = queries.RemoveUserRefreshTokenById(ctx, pgtype.UUID{Bytes: userUuid, Valid: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error while logging out")
	}

	// Get token string from header
	jwtStr := strings.Split(c.Request().Header.Get("Authorization"), " ")[1]
	blist.Add(jwtStr)

	return c.NoContent(http.StatusNoContent)
}
