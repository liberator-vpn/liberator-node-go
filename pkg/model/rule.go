package model

type PortRule struct {
	ID             uint64
	TargetAddress  *uint32
	Protocol       string // tcp/udp/both-
	PortRangeStart uint16
	PortRangeEnd   *uint16
}
