package util

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

type GenerateJwtOptions struct {
	ID           string
	Email        string
	RefreshToken string
}

func GenerateJwt(options GenerateJwtOptions) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":           options.ID,
		"email":        options.Email,
		"refreshToken": options.RefreshToken,
		"exp":          time.Now().Add(time.Hour * 24).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
