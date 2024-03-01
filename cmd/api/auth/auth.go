package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"skabillium.io/auth-service/cmd/db"
)

var queries *db.Queries
var ctx context.Context

type ErrorResponse struct {
	Message string `json:"message"`
}

type CreateUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func InitAuth(q *db.Queries, contx context.Context) {
	queries = q
	ctx = contx
}

// @Tags Auth
// @Description Register a new user
// @Success 201 {object} CreateUserResponse
// @Error 400 {object} ErrorResponse
// @Router /auth/register [POST]
func Register(c echo.Context) error {
	user, err := queries.CreateUser(ctx, db.CreateUserParams{
		ID: pgtype.UUID{
			Bytes: uuid.New(),
			Valid: true,
		},
		Email:        "example2@email.com",
		PasswordHash: "hash",
	})
	if err != nil {
		fmt.Println(err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{Message: "Error while creating user"})
	}

	return c.JSON(http.StatusCreated, CreateUserResponse{ID: string(user.ID.Bytes[:]), Email: user.Email})

}
