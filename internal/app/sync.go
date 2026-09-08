package app

import (
	"context"
	"log"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
)

// syncLoop — пассивный контур ноды к API: регистрация, heartbeat, pull желаемого
// состояния, реконсиляция локальных клиентов и ack активации сессий.
func (app *App) syncLoop(ctx context.Context, secret, transportName string) {
	cfg := app.cfg.API
	client := apiclient.New(cfg.BaseURL, secret)
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

	host := nodeIdentity()
	nodeID := ""
	hbTicker := time.NewTicker(hbEvery)
	defer hbTicker.Stop()

	// Ждём API (с саморегистрацией) без блокировки основного рантайма.
	for {
		if nodeID == "" {
			reg, err := client.Register(ctx, host, cfg.PublicEndpoint, cfg.MeshEndpoint, cfg.RegionCode)
			if err != nil {
				log.Printf("api register failed: %v", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(syncEvery):
				}
				continue
			}
			nodeID = reg.NodeID
			log.Printf("api registered node_id=%s gateway=%s", nodeID, reg.GatewayAddr)
		}

		select {
		case <-ctx.Done():
			return
		case <-hbTicker.C:
			if err := client.Heartbeat(ctx, nodeID, apiclient.Heartbeat{
				ActiveSessions: int32(app.peersManager.ActiveCount(transportName)),
			}); err != nil {
				log.Printf("api heartbeat failed: %v", err)
			}
		default:
		}

		st, err := client.GetState(ctx, nodeID)
		if err != nil {
			log.Printf("api state pull failed: %v", err)
		} else {
			usageIndex := app.reconcileState(ctx, client, nodeID, transportName, st)
			app.pushUsage(ctx, client, nodeID, usageIndex)
			app.applyFirewallPairs(st.FirewallPairs)
			app.reconcileEgress(st.Egress)
			app.reconcileRemotes(ctx, client, nodeID)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(syncEvery):
		}
	}
}

// pushUsage отправляет накопленные дельты трафика по сессиям в API.
func (app *App) pushUsage(ctx context.Context, client *apiclient.Client, nodeID string, ipToSession map[uint32]string) {
	usages := app.peersManager.DrainUsage()
	reports := make([]apiclient.UsageReport, 0, len(usages))
	for _, u := range usages {
		sid, ok := ipToSession[u.VirtualIP]
		if !ok || (u.Up == 0 && u.Down == 0) {
			continue
		}
		reports = append(reports, apiclient.UsageReport{
			SessionID: sid, BytesUp: int64(u.Up), BytesDown: int64(u.Down),
		})
	}
	if len(reports) > 0 {
		if err := client.PushUsage(ctx, nodeID, reports); err != nil {
			log.Printf("api usage push failed: %v", err)
		}
	}
}

// reconcileState приводит локальный транспорт к желаемому состоянию сессий и
// возвращает карту virtual IP -> session_id (для пуша usage).
func (app *App) reconcileState(ctx context.Context, client *apiclient.Client, nodeID, transportName string, st *apiclient.State) map[uint32]string {
	quota := make(map[string]*apiclient.Quota, len(st.Quotas))
	for i := range st.Quotas {
		quota[st.Quotas[i].AccountID] = &st.Quotas[i]
	}

	clients := make([]appconfig.ClientConfig, 0, len(st.Sessions))
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
		if s.ClientPublicKey == "" {
			continue
		}
		ipToSession[ip] = s.ID
		c := appconfig.ClientConfig{
			VirtualIP:    ip,
			AwgPublicKey: s.ClientPublicKey,
		}
		if q := quota[s.AccountID]; q != nil {
			if q.SpeedLimitBps != nil && *q.SpeedLimitBps > 0 {
				mbps := float64(*q.SpeedLimitBps) / 8 / (1024 * 1024) // bps -> MiB/s
				c.SpeedLimitMbps = &mbps
			}
			if q.TrafficLimitBytes != nil && !q.OverLimit {
				used := int64(0)
				if q.TrafficUsedBytes != nil {
					used = *q.TrafficUsedBytes
				}
				if rem := *q.TrafficLimitBytes - used; rem > 0 {
					gb := float64(rem) / (1024 * 1024 * 1024)
					c.TrafficLimitGb = &gb
				}
			}
		}
		clients = append(clients, c)
	}
	metrics.SetActiveClients(len(clients))

	if err := app.peersManager.ReconcileClients(ctx, transportName, clients); err != nil {
		log.Printf("reconcile clients failed: %v", err)
	}
	if len(toActivate) > 0 {
		if _, err := client.ActivateSessions(ctx, nodeID, toActivate); err != nil {
			log.Printf("activate sessions failed: %v", err)
		}
	}
	return ipToSession
}

// reconcileEgress приводит таблицу правил выхода (router.UserRules) в соответствие
// желаемому /state.egress.
func (app *App) reconcileEgress(items []apiclient.Egress) {
	rules := app.router.UserRules()
	rules.Clear()
	for _, eg := range items {
		if eg.PeerIP == "" || eg.Prefix == "" || eg.ExitMeshEndpoint == "" {
			continue
		}
		ip := netutils.IPStringToUint32(eg.PeerIP)
		if ip == 0 {
			continue
		}
		_ = rules.Set(ip, eg.Prefix, eg.ExitMeshEndpoint)
	}
}
