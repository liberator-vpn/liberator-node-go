package apiclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Identity — постоянная идентичность ноды, выданная API при enrollment.
type Identity struct {
	NodeID      string `json:"node_id"`
	Secret      string `json:"secret"`
	GatewayAddr string `json:"gateway_addr"`
	GlobalCIDR  string `json:"global_cidr"`
}

// LoadIdentity читает identity-файл. Если файла нет — (nil, nil).
func LoadIdentity(path string) (*Identity, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parse node identity %s: %w", path, err)
	}
	if id.NodeID == "" || id.Secret == "" {
		return nil, fmt.Errorf("node identity %s is incomplete (node_id/secret)", path)
	}
	return &id, nil
}

// SaveIdentity атомарно пишет identity-файл с правами 0600.
func SaveIdentity(path string, id *Identity) error {
	if path == "" {
		return errors.New("empty identity path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
