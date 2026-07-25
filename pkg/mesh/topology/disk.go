package topology

import (
	"encoding/json"
	"fmt"
	"os"
)

type jsonFilePersister struct {
	filename string
}

func NewJsonFilePersister(filename string) FilePersister {
	return &jsonFilePersister{filename: filename}
}

func (j *jsonFilePersister) Save(peers map[string]*PeerInfo) error {
	if j.filename == "" {
		return nil
	}

	data, err := json.MarshalIndent(peers, "", "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal topology data: %w", err)
	}

	tmpFile := j.filename + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpFile, j.filename); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit topology file: %w", err)
	}

	return nil
}

func (j *jsonFilePersister) Load() (map[string]*PeerInfo, error) {
	if j.filename == "" {
		return make(map[string]*PeerInfo), nil
	}

	data, err := os.ReadFile(j.filename)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*PeerInfo), nil
		}
		return nil, fmt.Errorf("failed to read topology file: %w", err)
	}

	var peers map[string]*PeerInfo
	if err := json.Unmarshal(data, &peers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal topology file: %w", err)
	}

	for id, p := range peers {
		if id == "" || p == nil || p.ID == "" {
			delete(peers, id)
		}
	}

	return peers, nil
}
