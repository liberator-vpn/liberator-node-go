package peersmanager

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/infra/repos"
	"github.com/TexHik620953/liberator-node-go/internal/utils/safemap"
	"github.com/TexHik620953/liberator-node-go/pkg/model"
	"github.com/TexHik620953/liberator-node-go/pkg/services/firewallmanager"
	"github.com/TexHik620953/liberator-node-go/pkg/transport"
)

type PeersManager struct {
	ctx context.Context

	db              *sql.DB
	queries         *repos.Queries
	firewallManager *firewallmanager.Firewallmanager

	transports safemap.Safemap[string, transport.Transport]

	statsDrain chan transport.TransportPeerStats
}

func New(
	ctx context.Context,
	db *sql.DB,
	firewallManager *firewallmanager.Firewallmanager,
) *PeersManager {
	return &PeersManager{
		ctx:             ctx,
		db:              db,
		queries:         repos.New(db),
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
	rows, err := pm.queries.ListPeers(pm.ctx)
	if err != nil {
		return fmt.Errorf("failed to load peers: %w", err)
	}

	for _, row := range rows {
		peer := peerFromRow(row)
		if peer.ExpirationDate != nil {
			if time.Now().After(*peer.ExpirationDate) {
				err = pm.DeletePeer(pm.ctx, peer.ID)
				if err != nil {
					log.Printf("failed to remove expired peer: %v", err)
				}
				continue
			}
		}

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
				err := pm.queries.UpdatePeerStats(pm.ctx, repos.UpdatePeerStatsParams{
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

func (pm *PeersManager) CreatePeerAutoID(ctx context.Context, peer *model.Peer) error {
	// Генерируем ключи для пира
	transport, ex := pm.transports.Get(peer.Type)
	if !ex {
		return fmt.Errorf("transport with type %s not found", peer.Type)
	}

	err := transport.GeneratePeerKeys(peer)
	if err != nil {
		return fmt.Errorf("failed to generate peer keys: %v", err)
	}

	// Начинаем транзакцию с эксклюзивной блокировкой
	tx, err := pm.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Устанавливаем эксклюзивную блокировку (SQLite)
	// Это нужно выполнить до вставки
	_, err = tx.ExecContext(ctx, "BEGIN EXCLUSIVE")
	if err != nil {
		return fmt.Errorf("exclusive lock: %w", err)
	}

	// Создаём экземпляр Queries, привязанный к транзакции
	q := repos.New(tx)

	// Выполняем вставку (подзапрос MAX+1 будет безопасен)
	rq := repos.CreatePeerAutoIDParams{
		Type:           peer.Type,
		AwgPrivateKey:  peer.AwgPrivateKey,
		AwgPublicKey:   peer.AwgPublicKey,
		ExpirationDate: peer.ExpirationDate,
	}
	if peer.TrafficLimitGb != nil {
		rq.TrafficLimitGb = sql.NullFloat64{
			Float64: *peer.TrafficLimitGb,
			Valid:   true,
		}
	}
	if peer.SpeedLimitMbps != nil {
		rq.SpeedLimitMbps = sql.NullFloat64{
			Float64: *peer.SpeedLimitMbps,
			Valid:   true,
		}
	}

	row, err := q.CreatePeerAutoID(ctx, rq)
	if err != nil {
		return fmt.Errorf("create peer: %w", err)
	}

	peer.ID = uint64(row.ID)
	peer.VirtualIP = uint32(row.VirtualIp)

	if err = transport.PreparePeer(peer); err != nil {
		return fmt.Errorf("failed to prepare peer: %v", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (pm *PeersManager) GetPeerByID(ctx context.Context, id uint64) (*model.Peer, error) {
	row, err := pm.queries.GetPeerByID(ctx, int64(id))
	if err != nil {
		return nil, fmt.Errorf("get peer by ID: %w", err)
	}
	return peerFromRow(row), nil
}

func (pm *PeersManager) DeletePeer(ctx context.Context, peerId uint64) error {
	if err := pm.firewallManager.RemoveAllPeerRules(ctx, peerId); err != nil {
		return fmt.Errorf("delete peer rules from DB: %w", err)
	}

	peer, err := pm.queries.GetPeerByID(ctx, int64(peerId))
	if err != nil {
		return fmt.Errorf("failed to get peer: %w", err)
	}
	if err := pm.queries.DeletePeer(ctx, int64(peerId)); err != nil {
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
	p := &model.Peer{
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

	if row.TrafficLimitGb.Valid {
		p.TrafficLimitGb = &row.TrafficLimitGb.Float64
	}
	if row.SpeedLimitMbps.Valid {
		p.SpeedLimitMbps = &row.SpeedLimitMbps.Float64
	}
	return p
}

func (pm *PeersManager) GetPeerByVirtualIP(ctx context.Context, virtualIP uint32) (*model.Peer, error) {
	row, err := pm.queries.GetPeerByVirtualIP(ctx, int64(virtualIP))
	if err != nil {
		return nil, fmt.Errorf("get peer by virtual IP: %w", err)
	}
	return peerFromRow(row), nil
}
func (pm *PeersManager) ListPeers(ctx context.Context) ([]*model.Peer, error) {
	rows, err := pm.queries.ListPeers(ctx)
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

	return transport.GenerateClientConnectionString(peer, addr, name)
}
