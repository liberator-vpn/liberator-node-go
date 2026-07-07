package discovery

import (
	"encoding/json"
	"fmt"
	"liberator-node-go/internal/infra/ipapi"
	"liberator-node-go/internal/utils/safemap"
	"net"
	"os"
	"time"
)

type PeerInfo struct {
	Id       string
	LastSeen time.Time
	IpInfo   *ipapi.IpInfo

	Addresses safemap.Safemap[string, bool]
}

type PeerStore struct {
	store safemap.Safemap[string, *PeerInfo]
}

func NewPeerStore() *PeerStore {
	return &PeerStore{
		store: safemap.New[string, *PeerInfo](),
	}
}

func (ps *PeerStore) List() []*PeerInfo {
	r := make([]*PeerInfo, 0)

	ps.store.Foreach(func(s string, pi *PeerInfo) {
		r = append(r, pi)
	})

	return r
}
func (svc *PeerStore) Count() int {
	return svc.store.Count()
}
func (ps *PeerStore) Exists(key string) bool {
	return ps.store.Exists(key)
}

func (ps *PeerStore) Get(key string) (*PeerInfo, bool) {
	return ps.store.Get(key)
}

func (ps *PeerStore) Set(info *PeerInfo) {
	ps.store.Set(info.Id, info)
}

func (ps *PeerStore) InsertMerge(update *PeerInfo) {
	pi, ex := ps.Get(update.Id)
	if !ex {
		ps.Set(update)
		return
	}

	// Merge addresses map
	update.Addresses.Foreach(func(a string, _ bool) {
		if len(a) == 0 {
			return
		}
		if _, err := net.ResolveUDPAddr("udp", a); err != nil {
			return
		}
		pi.Addresses.Set(a, true)
	})

	if update.LastSeen.After(pi.LastSeen) {
		pi.LastSeen = update.LastSeen
	}

	if update.IpInfo != nil {
		pi.IpInfo = update.IpInfo
	}
}

func (ps *PeerStore) Save(filename string) error {
	raw := ps.store.CloneRaw()
	data, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("write file error: %w", err)
	}
	return nil
}

func (ps *PeerStore) Load(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	var temp map[string]*PeerInfo
	err = json.Unmarshal(data, &temp)
	if err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}

	ps.store = safemap.From(temp)
	return nil
}
