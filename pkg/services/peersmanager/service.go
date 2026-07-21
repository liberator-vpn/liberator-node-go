package peersmanager

import (
	"context"
	"fmt"
	"log"

	"github.com/TexHik620953/liberator-node-go/internal/infra/repos"
	"github.com/TexHik620953/liberator-node-go/internal/utils/safemap"
	"github.com/TexHik620953/liberator-node-go/pkg/model"
	"github.com/TexHik620953/liberator-node-go/pkg/services/firewallmanager"
	"github.com/TexHik620953/liberator-node-go/pkg/transport"
)

type PeersManager struct {
	ctx             context.Context
	db              *repos.Queries
	firewallManager *firewallmanager.Firewallmanager

	transports safemap.Safemap[string, transport.Transport]

	statsDrain chan transport.TransportPeerStats
}

func New(
	ctx context.Context,
	db repos.DBTX,
	firewallManager *firewallmanager.Firewallmanager,
) *PeersManager {
	return &PeersManager{
		ctx:             ctx,
		db:              repos.New(db),
		firewallManager: firewallManager,
		transports:      safemap.New[string, transport.Transport](),
		statsDrain:      make(chan transport.TransportPeerStats, 1000),
	}
}

func (pm *PeersManager) RegisterTransport(name string, trp transport.Transport) {
	pm.transports.Set(name, trp)
	go func() {
		for {
			select {
			case <-pm.ctx.Done():
				return
			case data := <-trp.DeltaChan():
				pm.statsDrain <- data
			}
		}
	}()
}

func (pm *PeersManager) Run() error {
	rows, err := pm.db.ListPeers(pm.ctx)
	if err != nil {
		return fmt.Errorf("failed to load peers: %w", err)
	}

	for _, row := range rows {
		peer := peerFromRow(row)
		transport, ex := pm.transports.Get(peer.Type)
		if !ex {
			log.Printf("failed to prepare peer %d - transport with corresponding name %s not found", peer.ID, peer.Type)
			continue
		}

		err = transport.PreparePeer(peer)
		if err != nil {
			log.Printf("failed to prepare peer: %v", err)
			continue
		}
	}

	go func() {
		for {
			select {
			case <-pm.ctx.Done():
				return
			case data := <-pm.statsDrain:
				err := pm.db.UpdatePeerStats(pm.ctx, repos.UpdatePeerStatsParams{
					VirtualIp: int64(data.VirtualIP),
					LastSeen:  data.LastSeen,
					FromInc:   int64(data.DeltaFromPeer),
					ToInc:     int64(data.DeltaToPeer),
				})
				if err != nil {
					log.Printf("failed to update peer stats: %v", err)
				}
			}
		}
	}()

	return nil
}

func (pm *PeersManager) CreatePeerAutoID(ctx context.Context, peer *model.Peer) (uint64, error) {
	row, err := pm.db.CreatePeerAutoID(ctx, repos.CreatePeerAutoIDParams{
		Type:           peer.Type,
		VirtualIp:      int64(peer.VirtualIP),
		AwgPrivateKey:  peer.AwgPrivateKey,
		AwgPublicKey:   peer.AwgPublicKey,
		ExpirationDate: peer.ExpirationDate,
	})
	if err != nil {
		return 0, fmt.Errorf("create peer: %w", err)
	}
	transport, ex := pm.transports.Get(peer.Type)
	if ex {
		err = transport.PreparePeer(peer)
		if err != nil {
			return 0, fmt.Errorf("failed to prepare peer: %v", err)
		}
	}

	return uint64(row.ID), nil
}
func (pm *PeersManager) CreatePeerExplicit(ctx context.Context, peer *model.Peer) (uint64, error) {
	row, err := pm.db.CreatePeerExplicit(ctx, repos.CreatePeerExplicitParams{
		ID:             int64(peer.ID),
		Type:           peer.Type,
		VirtualIp:      int64(peer.VirtualIP),
		AwgPrivateKey:  peer.AwgPrivateKey,
		AwgPublicKey:   peer.AwgPublicKey,
		ExpirationDate: peer.ExpirationDate,
	})
	if err != nil {
		return 0, fmt.Errorf("create peer: %w", err)
	}
	transport, ex := pm.transports.Get(peer.Type)
	if ex {
		err = transport.PreparePeer(peer)
		if err != nil {
			return 0, fmt.Errorf("failed to prepare peer: %v", err)
		}
	}
	return uint64(row.ID), nil
}

func (pm *PeersManager) GetPeerByID(ctx context.Context, id uint64) (*model.Peer, error) {
	row, err := pm.db.GetPeerByID(ctx, int64(id))
	if err != nil {
		return nil, fmt.Errorf("get peer by ID: %w", err)
	}
	return peerFromRow(row), nil
}

func (pm *PeersManager) DeletePeer(ctx context.Context, peerId uint64) error {
	if err := pm.firewallManager.RemoveAllPeerRules(ctx, peerId); err != nil {
		return fmt.Errorf("delete peer rules from DB: %w", err)
	}

	peer, err := pm.db.GetPeerByID(ctx, int64(peerId))
	if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}
	if err := pm.db.DeletePeer(ctx, int64(peerId)); err != nil {
		return fmt.Errorf("delete peer from DB: %w", err)
	}

	transport, ex := pm.transports.Get(peer.Type)
	if ex {
		transport.KickUser(uint32(peer.VirtualIp))
	}
	return nil
}

// peerFromRow преобразует сгенерированную sqlc-строку в Peer.
func peerFromRow(row repos.Peer) *model.Peer {
	return &model.Peer{
		ID:             uint64(row.ID),
		Type:           row.Type,
		VirtualIP:      uint32(row.VirtualIp),
		LastSeen:       row.LastSeen,
		ExpirationDate: row.ExpirationDate,
		FromPeerTotal:  uint64(row.FromPeerTotal),
		ToPeerTotal:    uint64(row.ToPeerTotal),
		AwgPrivateKey:  row.AwgPrivateKey,
		AwgPublicKey:   row.AwgPublicKey,
	}
}

func (pm *PeersManager) GetPeerByVirtualIP(ctx context.Context, virtualIP uint32) (*model.Peer, error) {
	row, err := pm.db.GetPeerByVirtualIP(ctx, int64(virtualIP))
	if err != nil {
		return nil, fmt.Errorf("get peer by virtual IP: %w", err)
	}
	return peerFromRow(row), nil
}
func (pm *PeersManager) ListPeers(ctx context.Context) ([]*model.Peer, error) {
	rows, err := pm.db.ListPeers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	peers := make([]*model.Peer, 0, len(rows))
	for _, row := range rows {
		peers = append(peers, peerFromRow(row))
	}
	return peers, nil
}
func (pm *PeersManager) GenerateClientKey(ctx context.Context, peerId uint64, addr string, name string) (string, error) {
	peer, err := pm.GetPeerByID(ctx, peerId)
	if err != nil {
		return "", err
	}

	transport, ex := pm.transports.Get(peer.Type)
	if !ex {
		return "", fmt.Errorf("corresponding transport %s not found", peer.Type)
	}

	return transport.GenerateClientKey(peer, addr, name)
}
