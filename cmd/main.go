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
	echoSwagger "github.com/swaggo/echo-swagger"

	"skabillium.io/auth-service/cmd/api/auth"
	"skabillium.io/auth-service/cmd/api/health"
	"skabillium.io/auth-service/cmd/db"
	_ "skabillium.io/auth-service/cmd/docs"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

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

// @title Auth service
// @version 1.0
// @description Example user auth service
// @termsOfService http://swagger.io/terms/
// @license.name MIT
// @license.url https://opensource.org/license/mit
// @host localhost:1323
// @BasePath /v1
func main() {

	// Connect to database
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, os.Getenv("POSTGRES_URL"))
	if err != nil {
		// TODO: Handle this differently
		panic(err)
	}
	defer conn.Close(ctx)

	queries := db.New(conn)

	auth.InitAuth(queries, ctx)

	e := echo.New()
	e.Validator = &Validator{validator: validator.New()}
	v1 := e.Group("v1")

	// Map handlers to routes
	v1.GET("/status", health.GetHealth)
	v1.GET("/swagger*", echoSwagger.WrapHandler)

	v1.POST("/auth/register", auth.Register)

	// Start server
	e.Logger.Fatal(e.Start(":" + os.Getenv("PORT")))
}
