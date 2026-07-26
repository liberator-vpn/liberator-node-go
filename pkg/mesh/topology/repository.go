package topology

import (
	"context"
	"log"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
)

type peerRepository struct {
	memory *inMemoryState
	disk   FilePersister
}

func NewPeerRepository(ctx context.Context, disk FilePersister) PeerRepository {
	repo := &peerRepository{
		memory: newInMemoryState(),
		disk:   disk,
	}

	if loaded, err := disk.Load(); err == nil {
		repo.memory.peers = loaded
	} else {
		log.Printf("[Topology] Warning: failed to load peers from disk: %v", err)
	}
	go repo.startSaveLoop(ctx)

	return repo
}

func (r *peerRepository) InsertMerge(update PeerInfo) bool {
	return r.memory.InsertMerge(update)
}

func (r *peerRepository) Get(id string) (PeerInfo, bool) {
	return r.memory.Get(id)
}

func (r *peerRepository) List() []PeerInfo {
	return r.memory.List()
}

func (r *peerRepository) Remove(id string) {
	r.memory.Remove(id)
}

func (r *peerRepository) Count() int {
	return r.memory.Count()
}

func (r *peerRepository) Subscribe(ctx context.Context) (<-chan *proto.PeerEvent, context.CancelFunc) {
	return r.memory.Subscribe(ctx)
}

func (r *peerRepository) startSaveLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.flushToDisk()
			return
		case <-ticker.C:
			r.flushToDisk()
		}
	}
}

func (r *peerRepository) flushToDisk() {
	r.memory.mu.RLock()
	snapshot := make(map[string]*PeerInfo, len(r.memory.peers))
	for k, v := range r.memory.peers {
		snapshot[k] = v.Clone()
	}
	r.memory.mu.RUnlock()

	if err := r.disk.Save(snapshot); err != nil {
		log.Printf("[Topology] Error saving peers to disk: %v", err)
	}
}
