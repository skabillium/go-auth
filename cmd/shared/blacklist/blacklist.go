package blacklist

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const BlacklistKeyPrefix = "blacklist:"

type BlacklistService struct {
	ctx         context.Context
	redisClient *redis.Client
}

func NewBlacklistService(ctx context.Context, redisClient *redis.Client) *BlacklistService {
	return &BlacklistService{ctx: ctx, redisClient: redisClient}
}

func (b *BlacklistService) Add(token string) error {
	return b.redisClient.Set(b.ctx, BlacklistKeyPrefix+token, "1", 24*time.Hour).Err()
}

func (b *BlacklistService) Has(token string) (bool, error) {
	exists, err := b.redisClient.Exists(b.ctx, BlacklistKeyPrefix+token).Result()
	if err != nil {
		return false, err
	}

	return exists == 1, nil
}
