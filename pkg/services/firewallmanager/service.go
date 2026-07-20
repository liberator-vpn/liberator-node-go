package firewallmanager

import (
	"context"
	"fmt"

	"github.com/TexHik620953/liberator-node-go/internal/infra/repos"
	"github.com/TexHik620953/liberator-node-go/pkg/firewall"
)

type Firewallmanager struct {
	firewall firewall.FirewallEngine
	db       *repos.Queries
}

func New(
	firewall firewall.FirewallEngine,
	db repos.DBTX,
) *Firewallmanager {
	return &Firewallmanager{
		firewall: firewall,
		db:       repos.New(db),
	}
}

func (fm *Firewallmanager) Start(ctx context.Context) error {
	dbRules, err := fm.db.LoadAllRules(ctx)
	if err != nil {
		return fmt.Errorf("load rules from DB: %w", err)
	}

	for _, dbRule := range dbRules {
		// Преобразуем в firewall.PortRule
		rule := firewall.PortRule{
			ID:             uint64(dbRule.ID),
			Address:        uint32(dbRule.VirtualIp),
			TargetAddress:  dbRule.TargetIp,
			Protocol:       dbRule.Protocol,
			PortRangeStart: uint16(dbRule.PortRangeStart),
			PortRangeEnd:   dbRule.PortRangeEnd,
		}
		fm.firewall.AddRule(rule)
	}
	return nil
}

func (fm *Firewallmanager) AddRule(ctx context.Context, peerID uint64, rule firewall.PortRule) error {
	// Вставляем в БД (авто ID)
	dbRuleID, err := fm.db.InsertPeerRule(ctx, repos.InsertPeerRuleParams{
		PeerID:         int64(peerID),
		TargetIp:       rule.TargetAddress,
		Protocol:       rule.Protocol,
		PortRangeStart: int64(rule.PortRangeStart),
		PortRangeEnd:   rule.PortRangeEnd,
	})
	if err != nil {
		return fmt.Errorf("insert rule into DB: %w", err)
	}

	// Присваиваем сгенерированный ID и добавляем в firewall
	rule.ID = uint64(dbRuleID)
	fm.firewall.AddRule(rule)
	return nil
}

func (fm *Firewallmanager) RemoveRule(ctx context.Context, ruleID uint64) error {
	if err := fm.db.DeletePeerRule(ctx, int64(ruleID)); err != nil {
		return fmt.Errorf("delete rule from DB: %w", err)
	}
	fm.firewall.RemoveRule(ruleID)
	return nil
}

func (fm *Firewallmanager) RemoveAllPeerRules(ctx context.Context, peerID uint64) error {
	rules, err := fm.db.LoadRulesByPeerID(ctx, int64(peerID))
	if err != nil {
		return fmt.Errorf("load all peer rules from DB: %w", err)
	}
	for _, rule := range rules {
		fm.firewall.RemoveRule(uint64(rule.ID))
	}

	err = fm.db.DeleteAllPeerRules(ctx, int64(peerID))
	if err != nil {
		return fmt.Errorf("delete all peer rules from DB: %w", err)
	}
	return nil
}
