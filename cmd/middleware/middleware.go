package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var (
	ctx         context.Context
	redisClient *redis.Client
)

func InitMiddleware(contx context.Context, r *redis.Client) {
	ctx = contx
	redisClient = r
}

func IsBlacklisted(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return next(c)
		}

		tokenStr := strings.Split(authHeader, " ")[1]
		redisKey := "blacklist:" + tokenStr
		exists, err := redisClient.Exists(ctx, redisKey).Result()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		if exists == 1 {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized access, pleased log in again")
		}

		return next(c)
	}
}
