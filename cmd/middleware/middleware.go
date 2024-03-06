package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"skabillium.io/auth-service/cmd/shared/blacklist"
)

var (
	blist *blacklist.BlacklistService
)

func InitMiddleware(ctx context.Context, redisClient *redis.Client) {
	blist = blacklist.NewBlacklistService(ctx, redisClient)
}

func IsBlacklisted(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return next(c)
		}

		tokenStr := strings.Split(authHeader, " ")[1]
		exists, err := blist.Has(tokenStr)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		if exists {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized access, pleased log in again")
		}

		return next(c)
	}
}
