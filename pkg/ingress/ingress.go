package ingress

import (
	"context"
)

type Ingress interface {
	Run()
	KickUser(ctx context.Context, userID string) bool
}
