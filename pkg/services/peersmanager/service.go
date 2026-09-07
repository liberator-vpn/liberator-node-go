package peersmanager

import (
	"context"
	"fmt"
	"sync"

	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/model"
	"github.com/liberator-vpn/liberator-node-go/pkg/services/firewallmanager"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport"
)

// PeersManager провижинит желаемых клиентов в транспорты. Вся информация о
// клиентах (virtual IP, ключи, лимиты, правила) приходит готовой из config-фида
// (в будущем — из state API); нода ничего не аллоцирует и не хранит в БД.
type PeersManager struct {
	ctx             context.Context
	firewallManager *firewallmanager.Firewallmanager

	mu         sync.RWMutex
	transports map[string]transport.Transport
}

func New(ctx context.Context, firewallManager *firewallmanager.Firewallmanager) *PeersManager {
	return &PeersManager{
		ctx:             ctx,
		firewallManager: firewallManager,
		transports:      make(map[string]transport.Transport),
	}
}

func (pm *PeersManager) RegisterTransport(name string, trp transport.Transport) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.transports[name] = trp
}

// ApplyClients провижинит все клиентов на заданный транспорт.
func (pm *PeersManager) ApplyClients(ctx context.Context, transportName string, clients []appconfig.ClientConfig) error {
	pm.mu.RLock()
	trp, ok := pm.transports[transportName]
	pm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("transport with name %q not found", transportName)
	}

	for _, c := range clients {
		if err := pm.provisionClient(ctx, trp, c); err != nil {
			return fmt.Errorf("provision client %s: %w", netutils.Uint32ToIPString(c.VirtualIP), err)
		}
	}
	return nil
}

func (pm *PeersManager) provisionClient(ctx context.Context, trp transport.Transport, c appconfig.ClientConfig) error {
	peer := &model.Peer{
		VirtualIP:      c.VirtualIP,
		AwgPublicKey:   c.AwgPublicKey,
		ExpirationDate: c.Expiration,
		TrafficLimitGb: c.TrafficLimitGb,
		SpeedLimitMbps: c.SpeedLimitMbps,
	}

	if err := trp.CreatePeer(peer); err != nil {
		return fmt.Errorf("create peer: %w", err)
	}

	for _, r := range c.Rules {
		pm.firewallManager.AddRule(c.VirtualIP, model.PortRule{
			TargetAddress:  r.TargetAddress,
			Protocol:       r.Protocol,
			PortRangeStart: r.PortRangeStart,
			PortRangeEnd:   r.PortRangeEnd,
		})
	}
	return nil
}
