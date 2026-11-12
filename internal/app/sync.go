package app

import (
	"context"
	"log"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/services/peersmanager"
	"github.com/liberator-vpn/liberator-node-go/pkg/userrules"
)

// syncLoop — пассивный контур ноды к API: heartbeat, pull желаемого состояния,
// реконсиляция локальных клиентов и ack активации сессий.
func (app *App) syncLoop(ctx context.Context) {
	cfg := app.cfg.API
	client := apiclient.New(cfg.BaseURL, app.apiSecret)
	if client == nil {
		return
	}

	syncEvery := cfg.SyncInterval
	if syncEvery <= 0 {
		syncEvery = 5 * time.Second
	}
	hbEvery := cfg.HeartbeatInterval
	if hbEvery <= 0 {
		hbEvery = 10 * time.Second
	}

	nodeID := app.apiNodeID
	if nodeID == "" {
		log.Printf("api node identity is missing; sync loop disabled")
		return
	}
	hbTicker := time.NewTicker(hbEvery)
	defer hbTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-hbTicker.C:
			if err := client.Heartbeat(ctx, nodeID, apiclient.Heartbeat{
				ActiveSessions: int32(app.peersManager.ActiveCountAll()),
				AgentVersion:   cfg.AgentVersion,
			}); err != nil {
				log.Printf("api heartbeat failed: %v", err)
			}
		default:
		}

		st, err := client.GetState(ctx, nodeID)
		if err != nil {
			log.Printf("api state pull failed: %v", err)
		} else {
			usageIndex := app.reconcileState(ctx, client, nodeID, st)
			app.pushUsage(ctx, client, nodeID, usageIndex)
			app.pushAlive(ctx, client, nodeID, usageIndex)
			app.applyFirewallPairs(st.FirewallPairs)
			app.reconcileEgress(st.Policies, st.Egress, st.BlockedPrefixes)
			app.reconcileRemotes(ctx, client, nodeID)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(syncEvery):
		}
	}
}

// pushAlive отправляет API отчёт о реально активных сессиях (по last_seen).
// По нему API закрывает «мёртвые» active-сессии и освобождает их peer_ip.
func (app *App) pushAlive(ctx context.Context, client *apiclient.Client, nodeID string, ipToSession map[uint32]string) {
	// клиент считается живым, если активность наблюдалась недавно.
	aliveIPs := app.peersManager.AliveWithin(90 * time.Second)
	items := make([]apiclient.AliveItem, 0, len(aliveIPs))
	for _, ip := range aliveIPs {
		sid, ok := ipToSession[ip]
		if !ok {
			continue
		}
		last, ok := app.peersManager.LastSeen(ip)
		if !ok {
			continue
		}
		items = append(items, apiclient.AliveItem{SessionID: sid, LastSeen: last})
	}
	if len(items) > 0 {
		if err := client.PushAlive(ctx, nodeID, items); err != nil {
			log.Printf("api alive push failed: %v", err)
		}
	}
}

// pushUsage отправляет накопленные дельты трафика по сессиям в API.
// Дельты списываются только после успешного ответа API: при недоступности
// control-plane они остаются в памяти и уходят на следующем цикле. Иначе
// каждый сетевой сбой API означал бы безвозвратную потерю биллинга.
func (app *App) pushUsage(ctx context.Context, client *apiclient.Client, nodeID string, ipToSession map[uint32]string) {
	usages := app.peersManager.UsageSnapshot()
	reports := make([]apiclient.UsageReport, 0, len(usages))
	committed := make([]peersmanager.Usage, 0, len(usages))
	var orphans uint64
	for _, u := range usages {
		sid, ok := ipToSession[u.VirtualIP]
		if !ok || (u.Up == 0 && u.Down == 0) {
			// Сессии уже нет в текущем state (IP переиспользован/клиент ушёл).
			// Начислять не на что, но и копить вечно нельзя — списываем.
			orphans += u.Up + u.Down
			committed = append(committed, u)
			continue
		}
		reports = append(reports, apiclient.UsageReport{
			SessionID: sid, BytesUp: int64(u.Up), BytesDown: int64(u.Down),
		})
		committed = append(committed, u)
	}

	if len(reports) == 0 {
		if orphans > 0 {
			app.peersManager.CommitUsage(committed)
		}
		return
	}
	if err := client.PushUsage(ctx, nodeID, reports); err != nil {
		var pending uint64
		for _, u := range usages {
			pending += u.Up + u.Down
		}
		log.Printf("api usage push failed, %d reports (%d bytes) kept for retry: %v", len(reports), pending, err)
		return
	}
	app.peersManager.CommitUsage(committed)
}

// reconcileState приводит локальный транспорт к желаемому состоянию сессий и
// возвращает карту virtual IP -> session_id (для пуша usage).
func (app *App) reconcileState(ctx context.Context, client *apiclient.Client, nodeID string, st *apiclient.State) map[uint32]string {
	quota := make(map[string]*apiclient.Quota, len(st.Quotas))
	for i := range st.Quotas {
		q := &st.Quotas[i]
		if q.KeyID != "" {
			quota[q.KeyID] = q
		} else {
			quota[q.AccountID] = q
		}
	}

	// Сессии группируются по транспорту: awg идёт в AWG-транспорт,
	// vless/hysteria2 — в xray. Раньше все сессии уезжали в «последний
	// зарегистрированный» транспорт.
	byTransport := make(map[string][]appconfig.ClientConfig)
	ipToSession := make(map[uint32]string)
	var toActivate []string
	for _, s := range st.Sessions {
		if s.Status != "issued" && s.Status != "active" {
			continue
		}
		if s.Status == "issued" {
			toActivate = append(toActivate, s.ID)
		}
		ip := netutils.IPStringToUint32(s.PeerIP)
		if ip == 0 {
			continue
		}
		protocol := s.Protocol
		if protocol == "" {
			protocol = "awg"
		}
		transportName, ok := app.protocolTransport[protocol]
		if !ok {
			log.Printf("state: no transport for protocol %q (session %s)", protocol, s.ID)
			continue
		}
		// AWG не может поднять пира без публичного ключа. Для VLESS UUID
		// и Hysteria2-пароль тоже приходят в client_public_key; если пусто,
		// proxy-транспорт сгенерирует auth сам.
		if protocol == "awg" && s.ClientPublicKey == "" {
			continue
		}
		ipToSession[ip] = s.ID
		c := appconfig.ClientConfig{
			Protocol:     protocol,
			Name:         s.ID,
			Auth:         s.ClientPublicKey,
			VirtualIP:    ip,
			AwgPublicKey: s.ClientPublicKey,
		}
		quotaID := s.AccountID
		if s.KeyID != "" {
			quotaID = s.KeyID
		}
		applyQuotaLimits(&c, quota[quotaID])
		byTransport[transportName] = append(byTransport[transportName], c)
	}
	metrics.SetActiveClients(len(ipToSession))

	for transportName, clients := range byTransport {
		if err := app.peersManager.ReconcileClients(ctx, transportName, clients); err != nil {
			log.Printf("reconcile clients on %s failed: %v", transportName, err)
		}
	}
	// Транспорты без сессий в текущем state тоже надо реконсилировать:
	// иначе исчезнувшие клиенты остаются поднятыми навсегда.
	for name := range app.transports.CloneRaw() {
		if _, done := byTransport[name]; done {
			continue
		}
		if err := app.peersManager.ReconcileClients(ctx, name, nil); err != nil {
			log.Printf("reconcile clients on %s failed: %v", name, err)
		}
	}

	// Убираем из карты usage IP, которых больше нет в state. Записи с ещё
	// неотправленными байтами сохраняются до успешного пуша.
	app.peersManager.PruneUsage(func(ip uint32) bool {
		_, ok := ipToSession[ip]
		return ok
	})
	if len(toActivate) > 0 {
		if _, err := client.ActivateSessions(ctx, nodeID, toActivate); err != nil {
			log.Printf("activate sessions failed: %v", err)
		}
	}
	return ipToSession
}

// applyQuotaLimits переводит квоту аккаунта в лимиты клиента.
// over_limit — это явный запрет трафика: нулевой traffic-limit заставляет
// шейпер дропать все пакеты. Раньше при over_limit лимит не ставился вовсе,
// то есть нода снимала ограничение ровно в момент исчерпания квоты.
func applyQuotaLimits(c *appconfig.ClientConfig, q *apiclient.Quota) {
	if q == nil {
		return
	}
	if q.SpeedLimitBps != nil && *q.SpeedLimitBps > 0 {
		mbps := float64(*q.SpeedLimitBps) / 8 / (1024 * 1024) // bps -> MiB/s
		c.SpeedLimitMbps = &mbps
	}

	zero := 0.0
	if q.OverLimit {
		c.TrafficLimitGb = &zero
		return
	}
	if q.TrafficLimitBytes == nil {
		return
	}
	used := int64(0)
	if q.TrafficUsedBytes != nil {
		used = *q.TrafficUsedBytes
	}
	rem := *q.TrafficLimitBytes - used
	if rem <= 0 {
		c.TrafficLimitGb = &zero
		return
	}
	gb := float64(rem) / (1024 * 1024 * 1024)
	c.TrafficLimitGb = &gb
}

// reconcileEgress приводит правила выхода роутера (userRules) в соответствие
// желаемому /state.egress. Набор собирается целиком и подменяется атомарно:
// иначе между Clear и Set был бы интервал, когда весь egress шёл в локальный NAT.
func (app *App) reconcileEgress(policies []apiclient.PolicyRule, items []apiclient.Egress, deny []apiclient.DenyRule) {
	entries := make([]userrules.Entry, 0, len(policies)+len(items)+len(deny))
	if len(policies) > 0 {
		for _, p := range policies {
			if p.PeerIP == "" || p.Prefix == "" {
				continue
			}
			ip := netutils.IPStringToUint32(p.PeerIP)
			if ip == 0 {
				continue
			}
			entries = append(entries, userrules.Entry{
				ClientIP:      ip,
				PrefixCIDR:    p.Prefix,
				Action:        p.Action,
				Exit:          p.ExitMeshEndpoint,
				Tier:          p.Tier,
				GroupPriority: p.GroupPriority,
				Priority:      p.Priority,
			})
		}
	} else {
		for _, eg := range items {
			if eg.PeerIP == "" || eg.Prefix == "" || eg.ExitMeshEndpoint == "" {
				continue
			}
			ip := netutils.IPStringToUint32(eg.PeerIP)
			if ip == 0 {
				continue
			}
			entries = append(entries, userrules.Entry{
				ClientIP:   ip,
				PrefixCIDR: eg.Prefix,
				Action:     userrules.ActionExit,
				Exit:       eg.ExitMeshEndpoint,
			})
		}
		for _, dr := range deny {
			if dr.PeerIP == "" || dr.Prefix == "" {
				continue
			}
			ip := netutils.IPStringToUint32(dr.PeerIP)
			if ip == 0 {
				continue
			}
			entries = append(entries, userrules.Entry{
				ClientIP:   ip,
				PrefixCIDR: dr.Prefix,
				Action:     userrules.ActionDeny,
			})
		}
	}
	if invalid := app.router.ReplaceEgressRules(entries); invalid > 0 {
		log.Printf("policy: dropped %d invalid rules from desired state", invalid)
	}
}
