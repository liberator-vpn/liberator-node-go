package mesh

import (
	"context"

	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/pkg/router"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

type Router interface {
	SubscribeEvents(ctx context.Context) (<-chan router.RouterEvent, context.CancelFunc)
	DumpRoutingTable() []routingtable.RoutingTableRecordDump

	AddRemoteRoutingObject(obj routingtable.RoutingObject) error
	DeleteRemoteRoutingObject(ip uint32) error
	GetRemoteRoutingObject(ip uint32) (routingtable.RoutingObject, bool)

	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleMeshPacket(packet *dgmessage.DatagramMessage)
}
