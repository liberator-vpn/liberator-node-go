package topology

import (
	"testing"
	"time"
)

// Нода перевыпустила сертификат: новый ID на том же адресе должен вытеснить старый,
// иначе протухшая запись живет в сторе вечно и разносится gossip'ом.
func TestInsertMergeDropsStaleIDOnSameAddress(t *testing.T) {
	s := newInMemoryState()
	now := time.Now()

	s.InsertMerge(PeerInfo{ID: "old", Address: "1.1.1.1:9000", LastSeen: now.Add(-time.Hour)})
	s.InsertMerge(PeerInfo{ID: "new", Address: "1.1.1.1:9000", LastSeen: now})

	if _, ok := s.Get("old"); ok {
		t.Fatal("stale id on the same address must be dropped")
	}
	if _, ok := s.Get("new"); !ok {
		t.Fatal("fresh id must survive")
	}
}

func TestInsertMergeKeepsFresherIDAndEmptyAddresses(t *testing.T) {
	s := newInMemoryState()
	now := time.Now()

	s.InsertMerge(PeerInfo{ID: "fresh", Address: "1.1.1.1:9000", LastSeen: now})
	s.InsertMerge(PeerInfo{ID: "stale", Address: "1.1.1.1:9000", LastSeen: now.Add(-time.Hour)})
	if _, ok := s.Get("fresh"); !ok {
		t.Fatal("older record must not evict a fresher one")
	}
	// Иначе сосед со старым peers.json бесконечно переопыляет нас мусором по gossip.
	if _, ok := s.Get("stale"); ok {
		t.Fatal("older record for an owned address must not be stored")
	}

	// Пустой адрес (пир только принял нас входящим) не должен схлопывать пиров между собой.
	s.InsertMerge(PeerInfo{ID: "a", LastSeen: now})
	s.InsertMerge(PeerInfo{ID: "b", LastSeen: now})
	if _, ok := s.Get("a"); !ok {
		t.Fatal("peers without address must not evict each other")
	}
}
