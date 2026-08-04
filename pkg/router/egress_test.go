package router

import (
	"testing"

	"github.com/TexHik620953/liberator-node-go/internal/utils/netutils"
)

func TestIsForbiddenEgress(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "169.254.169.254", "10.1.2.3",
		"192.168.1.1", "172.16.0.1", "172.31.255.255",
		"0.0.0.0", "224.0.0.1", "255.255.255.255",
	}
	allowed := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "11.0.0.1",
	}
	for _, ip := range blocked {
		if !isForbiddenEgress(netutils.IPStringToUint32(ip)) {
			t.Errorf("%s must be forbidden egress", ip)
		}
	}
	for _, ip := range allowed {
		if isForbiddenEgress(netutils.IPStringToUint32(ip)) {
			t.Errorf("%s must be allowed egress", ip)
		}
	}
}
