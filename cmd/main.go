package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	echoSwagger "github.com/swaggo/echo-swagger"

	"skabillium.io/auth-service/cmd/api/auth"
	"skabillium.io/auth-service/cmd/api/health"
	"skabillium.io/auth-service/cmd/db"
	_ "skabillium.io/auth-service/cmd/docs"
	"skabillium.io/auth-service/cmd/middleware"
)

var defaultCtx = context.Background()

type Validator struct {
	validator *validator.Validate
}

func (v *Validator) Validate(i interface{}) error {
	if err := v.validator.Struct(i); err != nil {
		// Optionally, you could return the error to give each route more control over the status code
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func RedisClient() (*redis.Client, error) {
	redisClient := redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_URL")})
	if _, err := redisClient.Ping(defaultCtx).Result(); err != nil {
		return nil, err
	}

	return redisClient, nil
}

// @title Auth service
// @version 1.0
// @description Example user auth service
// @termsOfService http://swagger.io/terms/
// @license.name MIT
// @license.url https://opensource.org/license/mit
// @host localhost:1323
// @BasePath /v1
// @securityDefinitions.apiKey BearerAuth
// @in header
// @name Authorization
func main() {
	conn, err := pgx.Connect(defaultCtx, os.Getenv("POSTGRES_URL"))
	if err != nil {
		panic(err)
	}
	queries := db.New(conn)
	defer conn.Close(defaultCtx)

	redisClient, err := RedisClient()
	if err != nil {
		panic(err)
	}
	defer redisClient.Close()

	e := echo.New()
	e.Validator = &Validator{validator: validator.New()}

	middleware.InitMiddleware(defaultCtx, redisClient)

	e.Use(middleware.IsBlacklisted)

	v1 := e.Group("v1")

	// Map handlers to routes
	v1.GET("/status", health.GetHealth)
	v1.GET("/swagger*", echoSwagger.WrapHandler)

	auth.InitAuth(v1, queries, redisClient, defaultCtx)

	// Start server
	e.Logger.Fatal(e.Start(":" + os.Getenv("PORT")))
}
