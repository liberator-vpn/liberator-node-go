package ingress

import (
	"context"
	"liberator-node-go/internal/utils/routingtable"
)

type Ingress interface {
	Run(fromIng chan *routingtable.DatagramMessage)
	KickUser(ctx context.Context, userID string) bool
}
