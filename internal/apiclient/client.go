// Package apiclient — HTTP-клиент ноды к контроль-плоскости (liberator-api).
// Нода пассивна: регистрируется, шлёт heartbeat, тянет желаемое состояние и
// подтверждает активацию сессий. Аутентификация — общий secret (Bearer).
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	base   string
	secret string
	hc     *http.Client
}

func New(base, secret string) *Client {
	if secret == "" || base == "" {
		return nil
	}
	return &Client{base: base, secret: secret, hc: &http.Client{Timeout: 15 * time.Second}}
}

// Register — вызов POST /v1/ctrl/nodes/register (upsert по hostname).
type Register struct {
	NodeID      string `json:"node_id"`
	Secret      string `json:"secret"`
	Created     bool   `json:"created"`
	GatewayAddr string `json:"gateway_addr"`
	GlobalCIDR  string `json:"global_cidr"`
}

type Protocol struct {
	Protocol string `json:"protocol"`
	Capacity int32  `json:"capacity"`
}

type registerReq struct {
	Hostname        string     `json:"hostname"`
	PublicEndpoint  string     `json:"public_endpoint"`
	MeshEndpoint    string     `json:"mesh_endpoint"`
	RegionCode      string     `json:"region_code"`
	ProtocolVersion string     `json:"protocol_version"`
	Protocols       []Protocol `json:"protocols"`
}

func (c *Client) Register(ctx context.Context, hostname, publicEndpoint, meshEndpoint, region string) (*Register, error) {
	var out Register
	err := c.do(ctx, http.MethodPost, "/v1/ctrl/nodes/register", "", registerReq{
		Hostname: hostname, PublicEndpoint: publicEndpoint, MeshEndpoint: meshEndpoint,
		RegionCode: region, ProtocolVersion: "1", Protocols: []Protocol{{Protocol: "awg", Capacity: 100}},
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat — POST /v1/ctrl/nodes/heartbeat.
type Heartbeat struct {
	ActiveSessions  int32   `json:"active_sessions"`
	CPU             float64 `json:"cpu"`
	LoadPercent     float64 `json:"load_percent"`
	ProtocolVersion string  `json:"protocol_version"`
}

func (c *Client) Heartbeat(ctx context.Context, nodeID string, hb Heartbeat) error {
	return c.do(ctx, http.MethodPost, "/v1/ctrl/nodes/heartbeat", nodeID, hb, nil)
}

// State — желаемое состояние ноды (GET /v1/ctrl/nodes/state).
type Session struct {
	ID              string `json:"id"`
	NodeID          string `json:"node_id"`
	AccountID       string `json:"account_id"`
	Protocol        string `json:"protocol"`
	PeerIP          string `json:"peer_ip"`
	ClientPublicKey string `json:"client_public_key"`
	Status          string `json:"status"`
}

type Quota struct {
	AccountID         string `json:"account_id"`
	Kind              string `json:"kind"`
	TrafficLimitBytes *int64 `json:"traffic_limit_bytes"`
	TrafficUsedBytes  *int64 `json:"traffic_used_bytes"`
	SpeedLimitBps     *int64 `json:"speed_limit_bps"`
	OverLimit         bool   `json:"over_limit"`
}

type State struct {
	NodeID        string            `json:"node_id"`
	GatewayAddr   string            `json:"gateway_addr"`
	RegionCode    string            `json:"region_code"`
	Sessions      []Session         `json:"sessions"`
	Quotas        []Quota           `json:"quotas"`
	RouteRules    []json.RawMessage `json:"route_rules"`
	FirewallRules []json.RawMessage `json:"firewall_rules"`
	FirewallPairs []FirewallPair    `json:"firewall_pairs"`
	Egress        []Egress          `json:"egress"`
}

// Egress — policy-правило выхода для клиента: префикс назначения -> нода-выход.
type Egress struct {
	PeerIP           string `json:"peer_ip"`
	Prefix           string `json:"prefix"`
	ExitMeshEndpoint string `json:"exit_mesh_endpoint"`
}

// FirewallPair — разрешённый поток recipient<-sender (enforcement на источнике).
type FirewallPair struct {
	RecipientIP string `json:"recipient_ip"`
	SenderIP    string `json:"sender_ip"`
}

func (c *Client) GetState(ctx context.Context, nodeID string) (*State, error) {
	var out State
	if err := c.do(ctx, http.MethodGet, "/v1/ctrl/nodes/state", nodeID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ClientEntry — запись глобальной директории активных клиентов всех нод.
type ClientEntry struct {
	SessionID       string     `json:"session_id"`
	AccountID       string     `json:"account_id"`
	PeerIP          string     `json:"peer_ip"`
	ClientPublicKey string     `json:"client_public_key"`
	Protocol        string     `json:"protocol"`
	Status          string     `json:"status"`
	Node            ClientNode `json:"node"`
}

type ClientNode struct {
	ID             string `json:"node_id"`
	Hostname       string `json:"hostname"`
	PublicEndpoint string `json:"public_endpoint"`
	MeshEndpoint   string `json:"mesh_endpoint"`
	GatewayAddr    string `json:"gateway_addr"`
}

type ClientsResult struct {
	Clients []ClientEntry `json:"clients"`
}

func (c *Client) GetClients(ctx context.Context, nodeID string) (*ClientsResult, error) {
	var out ClientsResult
	if err := c.do(ctx, http.MethodGet, "/v1/ctrl/clients", nodeID, nil, &out); err != nil {
		return nil, err
	}
	if out.Clients == nil {
		out.Clients = []ClientEntry{}
	}
	return &out, nil
}

// AliveItem — подтверждение активности сессии (для закрытия мёртвых active).
type AliveItem struct {
	SessionID string    `json:"session_id"`
	LastSeen  time.Time `json:"last_seen"`
}

// PushAlive — POST /v1/ctrl/sessions/alive.
func (c *Client) PushAlive(ctx context.Context, nodeID string, items []AliveItem) error {
	if len(items) == 0 {
		return nil
	}
	return c.do(ctx, http.MethodPost, "/v1/ctrl/sessions/alive", nodeID,
		map[string][]AliveItem{"items": items}, nil)
}

// ActivateSessions — POST /v1/ctrl/nodes/sessions/activate (issued -> active).
func (c *Client) ActivateSessions(ctx context.Context, nodeID string, ids []string) (int, error) {
	var out struct {
		Activated int `json:"activated"`
	}
	if len(ids) == 0 {
		return 0, nil
	}
	err := c.do(ctx, http.MethodPost, "/v1/ctrl/nodes/sessions/activate", nodeID,
		map[string][]string{"session_ids": ids}, &out)
	return out.Activated, err
}

// UsageReport — дельта трафика по одной сессии.
type UsageReport struct {
	SessionID string `json:"session_id"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
}

// PushUsage — POST /v1/ctrl/nodes/usage.
func (c *Client) PushUsage(ctx context.Context, nodeID string, reports []UsageReport) error {
	return c.do(ctx, http.MethodPost, "/v1/ctrl/nodes/usage", nodeID,
		map[string][]UsageReport{"reports": reports}, nil)
}

func (c *Client) do(ctx context.Context, method, path, nodeID string, body, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	if nodeID != "" {
		req.Header.Set("X-Node-Id", nodeID)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("api %s %s -> %s", method, path, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
