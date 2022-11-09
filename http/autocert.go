package http

import "context"

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, data []byte) error
	Delete(ctx context.Context, key string) error
}

type HostPolicy func(ctx context.Context, host string) error
