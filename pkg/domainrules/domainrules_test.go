package domainrules

import "testing"

func TestReplaceAllAndLookup(t *testing.T) {
	tbl := New()
	tbl.ReplaceAll([]Entry{
		{ClientIP: 100, Domain: "example.com.", Action: "exit", Exit: "de-1", Tier: 0, Priority: 1},
		{ClientIP: 100, Domain: "direct.com", Action: "direct", Tier: 1, Priority: 2},
		{ClientIP: 200, Domain: "example.com", Action: "deny", Tier: 0},
	})
	r, ok := tbl.Lookup(100, "EXAMPLE.COM")
	if !ok || r.Action != "exit" || r.Exit != "de-1" {
		t.Fatalf("lookup = %+v, %v", r, ok)
	}
	if r, ok := tbl.Lookup(100, "direct.com"); !ok || r.Action != "direct" {
		t.Fatalf("direct lookup = %+v, %v", r, ok)
	}
	if r, ok := tbl.Lookup(200, "example.com"); !ok || r.Action != "deny" {
		t.Fatalf("deny lookup = %+v, %v", r, ok)
	}
	if _, ok := tbl.Lookup(300, "example.com"); ok {
		t.Fatal("unknown client must not match")
	}
}
