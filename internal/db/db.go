package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func EnsureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	ddl := `
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  account_id TEXT NOT NULL UNIQUE,
  password_hash BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT;

ALTER TABLE users ADD COLUMN IF NOT EXISTS credits_balance BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_filename TEXT NOT NULL,
	file_size BIGINT,
	md5 TEXT,
	sha1 TEXT,
  sha256 TEXT NOT NULL,
	crc32 TEXT,
	ssdeep TEXT,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS file_size BIGINT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS md5 TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS sha1 TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS crc32 TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS ssdeep TEXT;

CREATE INDEX IF NOT EXISTS scans_sha256_idx ON scans(sha256);

CREATE TABLE IF NOT EXISTS scan_results (
  id UUID PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  av_name TEXT NOT NULL,
  status TEXT NOT NULL,
  deleted BOOLEAN,
  raw_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, av_name)
);
`
	_, err := pool.Exec(ctx, ddl)
	if err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	return nil
}
