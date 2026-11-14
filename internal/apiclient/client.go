// Package apiclient — HTTP-клиент ноды к control-plane (liberator-api).
// Нода пассивна: enroll по одноразовому токену, heartbeat, state, usage, ack.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	base   string
	secret string
	hc     *http.Client
}

// APIError — HTTP-ошибка control-plane с кодом ответа. Нужна, чтобы
// отличать протухшую identity (401/403) от сетевой недоступности API.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api %s %s -> %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
}

func New(base, secret string) *Client {
	if base == "" {
		return nil
	}
	return &Client{base: base, secret: secret, hc: &http.Client{Timeout: 15 * time.Second}}
}

type Protocol struct {
	Protocol string `json:"protocol"`
	Capacity int32  `json:"capacity"`
}

type EnrollRequest struct {
	Token          string         `json:"token"`
	Name           string         `json:"name"`
	Hostname       string         `json:"hostname"`
	PublicEndpoint string         `json:"public_endpoint"`
	MeshEndpoint   string         `json:"mesh_endpoint"`
	RegionCode     string         `json:"region_code"`
	Zone           string         `json:"zone,omitempty"`
	Provider       string         `json:"provider,omitempty"`
	AgentVersion   string         `json:"agent_version,omitempty"`
	Labels         map[string]any `json:"labels,omitempty"`
	Capabilities   map[string]any `json:"capabilities,omitempty"`
	Protocols      []Protocol     `json:"protocols"`
}

type EnrollResult struct {
	NodeID      string `json:"node_id"`
	Secret      string `json:"secret"`
	GatewayAddr string `json:"gateway_addr"`
	GlobalCIDR  string `json:"global_cidr"`
}

type WhoamiResult struct {
	NodeID      string `json:"node_id"`
	GatewayAddr string `json:"gateway_addr"`
}

func (c *Client) Whoami(ctx context.Context, nodeID string) (*WhoamiResult, error) {
	var out WhoamiResult
	if err := c.do(ctx, http.MethodGet, "/v1/node/whoami", nodeID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResult, error) {
	var out EnrollResult
	if err := c.do(ctx, http.MethodPost, "/v1/node/enroll", "", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type MeshPeer struct {
	PeerID     string  `json:"peer_id"`
	RemoteAddr string  `json:"remote_addr"`
	RTTMillis  float64 `json:"rtt_ms"`
	Initiator  bool    `json:"initiator"`
	SentBytes  uint64  `json:"sent_bytes"`
	RecvBytes  uint64  `json:"recv_bytes"`
}

type Heartbeat struct {
	ActiveSessions int32          `json:"active_sessions"`
	CPU            float64        `json:"cpu"`
	LoadPercent    float64        `json:"load_percent"`
	BytesUp        int64          `json:"bytes_up"`
	BytesDown      int64          `json:"bytes_down"`
	AgentVersion   string         `json:"agent_version,omitempty"`
	Capabilities   map[string]any `json:"capabilities,omitempty"`
	MeshID         string         `json:"mesh_id,omitempty"`
	MeshPeers      []MeshPeer     `json:"mesh_peers,omitempty"`
}

type DirectoryNode struct {
	NodeID         string `json:"node_id"`
	Hostname       string `json:"hostname"`
	PublicEndpoint string `json:"public_endpoint"`
	MeshEndpoint   string `json:"mesh_endpoint"`
	RegionCode     string `json:"region_code"`
	Status         string `json:"status"`
	GatewayAddr    string `json:"gateway_addr"`
}

type Directory struct {
	Nodes []DirectoryNode `json:"nodes"`
}

func (c *Client) GetDirectory(ctx context.Context, nodeID string) (*Directory, error) {
	var out Directory
	if err := c.do(ctx, http.MethodGet, "/v1/node/directory", nodeID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Heartbeat(ctx context.Context, nodeID string, hb Heartbeat) error {
	return c.do(ctx, http.MethodPost, "/v1/node/heartbeat", nodeID, hb, nil)
}

type Session struct {
	ID              string `json:"id"`
	AccountID       string `json:"account_id"`
	DeviceID        string `json:"device_id"`
	KeyID           string `json:"key_id,omitempty"`
	Protocol        string `json:"protocol"`
	PeerIP          string `json:"peer_ip"`
	ClientPublicKey string `json:"client_public_key"`
	Status          string `json:"status"`
	BytesUp         int64  `json:"bytes_up"`
	BytesDown       int64  `json:"bytes_down"`
}

type Quota struct {
	AccountID         string `json:"account_id"`
	KeyID             string `json:"key_id,omitempty"`
	Kind              string `json:"kind"`
	TrafficLimitBytes *int64 `json:"traffic_limit_bytes"`
	TrafficUsedBytes  *int64 `json:"traffic_used_bytes"`
	SpeedLimitBps     *int64 `json:"speed_limit_bps"`
	OverLimit         bool   `json:"over_limit"`
}

type RouteRule struct {
	ID             string          `json:"id"`
	UserID         string          `json:"user_id"`
	DeviceID       string          `json:"device_id,omitempty"`
	Match          json.RawMessage `json:"match"`
	Action         string          `json:"action"`
	ExitNodeID     string          `json:"exit_node_id,omitempty"`
	ExitRegionCode string          `json:"exit_region_code,omitempty"`
	Priority       int32           `json:"priority"`
}

type State struct {
	NodeID          string          `json:"node_id"`
	RegionCode      string          `json:"region_code"`
	Hostname        string          `json:"hostname"`
	PublicEndpoint  string          `json:"public_endpoint"`
	GatewayAddr     string          `json:"gateway_addr"`
	Status          string          `json:"status"`
	ConfigVersion   int64           `json:"config_version"`
	Config          json.RawMessage `json:"config,omitempty"`
	Protocols       []Protocol      `json:"protocols"`
	Sessions        []Session       `json:"sessions"`
	Quotas          []Quota         `json:"quotas"`
	RouteRules      []RouteRule     `json:"route_rules"`
	FirewallPairs   []FirewallPair  `json:"firewall_pairs"`
	Egress          []Egress        `json:"egress"`
	BlockedPrefixes []DenyRule      `json:"blocked_prefixes"`
	Policies        []PolicyRule    `json:"policies"`
}

type Egress struct {
	PeerIP           string `json:"peer_ip"`
	Prefix           string `json:"prefix"`
	ExitMeshEndpoint string `json:"exit_mesh_endpoint"`
}

type FirewallPair struct {
	RecipientIP string `json:"recipient_ip"`
	SenderIP    string `json:"sender_ip"`
}

type DenyRule struct {
	PeerIP string `json:"peer_ip"`
	Prefix string `json:"prefix"`
}

type PolicyRule struct {
	PeerIP           string `json:"peer_ip"`
	Prefix           string `json:"prefix,omitempty"`
	Domain           string `json:"domain,omitempty"`
	Action           string `json:"action"`
	ExitMeshEndpoint string `json:"exit_mesh_endpoint,omitempty"`
	Tier             int    `json:"tier"`
	Priority         int32  `json:"priority"`
	GroupPriority    int32  `json:"group_priority,omitempty"`
}

func (c *Client) GetState(ctx context.Context, nodeID string) (*State, error) {
	var out State
	if err := c.do(ctx, http.MethodGet, "/v1/node/state", nodeID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

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
	if err := c.do(ctx, http.MethodGet, "/v1/node/clients", nodeID, nil, &out); err != nil {
		return nil, err
	}
	if out.Clients == nil {
		out.Clients = []ClientEntry{}
	}
	return &out, nil
}

type AliveItem struct {
	SessionID string    `json:"session_id"`
	LastSeen  time.Time `json:"last_seen"`
}

func (c *Client) PushAlive(ctx context.Context, nodeID string, items []AliveItem) error {
	if len(items) == 0 {
		return nil
	}
	return c.do(ctx, http.MethodPost, "/v1/node/sessions/alive", nodeID,
		map[string][]AliveItem{"items": items}, nil)
}

func (c *Client) ActivateSessions(ctx context.Context, nodeID string, ids []string) (int, error) {
	var out struct {
		Activated int `json:"activated"`
	}
	if len(ids) == 0 {
		return 0, nil
	}
	err := c.do(ctx, http.MethodPost, "/v1/node/sessions/activate", nodeID,
		map[string][]string{"session_ids": ids}, &out)
	return out.Activated, err
}

type UsageReport struct {
	SessionID string `json:"session_id"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
}

func (c *Client) PushUsage(ctx context.Context, nodeID string, reports []UsageReport) error {
	if len(reports) == 0 {
		return nil
	}
	return c.do(ctx, http.MethodPost, "/v1/node/usage", nodeID,
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
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Message: msg}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
