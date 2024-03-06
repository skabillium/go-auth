package tokens

import "skabillium.io/auth-service/cmd/shared/util"

const (
	RefreshTokenLength           = 100
	EmailVerificationTokenLength = 12
)

func GenerateRefreshToken() string {
	return util.GenerateRandomString(RefreshTokenLength)
}
