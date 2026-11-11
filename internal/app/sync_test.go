package app

import (
	"testing"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
)

func i64Ptr(v int64) *int64 { return &v }

func TestApplyQuotaLimitsOverLimitDeniesTraffic(t *testing.T) {
	c := appconfig.ClientConfig{}
	applyQuotaLimits(&c, &apiclient.Quota{
		OverLimit:         true,
		TrafficLimitBytes: i64Ptr(10 << 30),
		TrafficUsedBytes:  i64Ptr(1 << 30),
	})
	if c.TrafficLimitGb == nil || *c.TrafficLimitGb != 0 {
		t.Fatalf("over_limit must install zero traffic limit, got %v", c.TrafficLimitGb)
	}
}

func TestApplyQuotaLimitsRemainingTraffic(t *testing.T) {
	c := appconfig.ClientConfig{}
	applyQuotaLimits(&c, &apiclient.Quota{
		TrafficLimitBytes: i64Ptr(10 << 30),
		TrafficUsedBytes:  i64Ptr(4 << 30),
	})
	if c.TrafficLimitGb == nil {
		t.Fatal("traffic limit must be set")
	}
	if got, want := *c.TrafficLimitGb, float64(6); got != want {
		t.Fatalf("remaining = %v GiB, want %v", got, want)
	}
}

func TestApplyQuotaLimitsSpeed(t *testing.T) {
	c := appconfig.ClientConfig{}
	applyQuotaLimits(&c, &apiclient.Quota{SpeedLimitBps: i64Ptr(8 * 1024 * 1024)})
	if c.SpeedLimitMbps == nil {
		t.Fatal("speed limit must be set")
	}
	if got, want := *c.SpeedLimitMbps, float64(1); got != want {
		t.Fatalf("speed = %v MiB/s, want %v", got, want)
	}
}
