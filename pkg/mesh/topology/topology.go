package topology

import (
	"context"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
)

type PeerInfo struct {
	ID       string    `json:"id"`
	Address  string    `json:"address"`
	LastSeen time.Time `json:"last_seen"`
}

func (p *PeerInfo) Clone() *PeerInfo {
	if p == nil {
		return nil
	}
	return &PeerInfo{
		ID:       p.ID,
		Address:  p.Address,
		LastSeen: p.LastSeen,
	}
}

// PeerRepository — единственный публичный интерфейс пакета для внешних слоев
type PeerRepository interface {
	InsertMerge(update PeerInfo) (changed bool)
	Get(id string) (PeerInfo, bool)
	List() []PeerInfo
	Remove(id string)
	Count() int
	Subscribe(ctx context.Context) (<-chan *proto.PeerEvent, context.CancelFunc)
}

// FilePersister отвечает исключительно за сохранение/загрузку JSON на диск
type FilePersister interface {
	Load() (map[string]*PeerInfo, error)
	Save(peers map[string]*PeerInfo) error
}
