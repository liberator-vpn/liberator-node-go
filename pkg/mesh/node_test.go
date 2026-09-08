package mesh

import "testing"

func TestDiscoveredPeersSkipsLoopbackSelf(t *testing.T) {
	n := &MeshNode{static: []string{"127.0.0.1:9000", "192.0.2.1:9000"}}
	peers := n.discoveredPeers()
	for _, p := range peers {
		if p == "127.0.0.1:9000" {
			t.Fatalf("self loopback not filtered: %v", peers)
		}
	}
	if len(peers) == 0 {
		t.Fatalf("expected at least a non-self peer, got none")
	}
}

func TestDiscoveredPeersEmpty(t *testing.T) {
	n := &MeshNode{}
	if got := n.discoveredPeers(); len(got) != 0 {
		t.Fatalf("expected no peers, got %v", got)
	}
}
