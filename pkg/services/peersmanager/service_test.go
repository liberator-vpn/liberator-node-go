package peersmanager

import (
	"context"
	"testing"
)

// CommitUsage должен вычитать ровно отправленный срез и не терять дельты,
// накопленные за время HTTP-запроса (иначе биллинг теряет байты).
func TestCommitUsageKeepsConcurrentDeltas(t *testing.T) {
	pm := New(context.Background())
	pm.usage = map[uint32]*usageAgg{
		1: {up: 100, down: 50},
	}

	snap := pm.UsageSnapshot()
	pm.usage[1].up += 10
	pm.usage[1].down += 5
	pm.CommitUsage(snap)

	got := pm.usage[1]
	if got.up != 10 || got.down != 5 {
		t.Fatalf("after commit up=%d down=%d, want 10/5", got.up, got.down)
	}
}

func TestPruneUsageKeepsPendingBytes(t *testing.T) {
	pm := New(context.Background())
	pm.usage = map[uint32]*usageAgg{
		1: {up: 0, down: 0},
		2: {up: 10, down: 0},
	}
	pm.PruneUsage(func(uint32) bool { return false })

	if _, ok := pm.usage[1]; ok {
		t.Fatal("empty entry for removed client must be pruned")
	}
	if _, ok := pm.usage[2]; !ok {
		t.Fatal("entry with pending bytes must survive pruning")
	}
}
