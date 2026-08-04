package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func GetDefaultGatewayInterface() (string, error) {
	// 1. Fetch all IPv4 routes from the Linux kernel [3.1]
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to list kernel routes: %w", err)
	}

	// 2. Scan the routes to find the default gateway (Dst == nil or 0.0.0.0/0) [3.1]
	for _, route := range routes {
		// A default route has no destination network specified (it matches everything) [3.1]
		if route.Dst == nil || route.Dst.IP.IsUnspecified() {
			// Ensure the route has a valid outbound interface index (LinkIndex) [3.1]
			if route.LinkIndex <= 0 {
				continue
			}

			// 3. Resolve the interface index to its actual OS string name [3.1]
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return "", fmt.Errorf("failed to resolve link index %d: %w", route.LinkIndex, err)
			}

			// Returns strings like "eth0", "ens3", "enp11s0" [3.1]
			return link.Attrs().Name, nil
		}
	}

	return "", fmt.Errorf("default outbound gateway route (0.0.0.0/0) not found")
}

func main() {
	n, err := GetDefaultGatewayInterface()
	fmt.Println(n, err)
}
