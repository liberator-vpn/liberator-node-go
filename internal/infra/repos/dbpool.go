package repos

import (
	"context"
	"fmt"
	"liberator-node-go/internal/appconfig"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DbPool struct {
	pool *pgxpool.Pool
}

func NewDbPool(cfg appconfig.DatabaseConfig) (*DbPool, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database)
	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	return &DbPool{pool: pool}, nil
}

func (r *DbPool) Close() {
	if r.pool != nil {
		r.pool.Close()
	}
}

func (r *DbPool) Query() *Queries {
	return New(r.pool)
}
