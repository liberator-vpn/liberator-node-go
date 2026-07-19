package netutils

import (
	"encoding/binary"
	"fmt"
	"net"
)

func IPToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}

	// Извлекаем именно 4-байтовое представление IPv4.
	// Это важно, так как net.ParseIP часто возвращает 16-байтовый слайс (IPv4-mapped IPv6).
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0 // Не IPv4 адрес (например, чистый IPv6)
	}

	// Читаем байты в сетевом порядке (Big Endian)
	return binary.BigEndian.Uint32(ipv4)
}
func Uint32ToIPString(nn uint32) string {
	// Allocate a 4-byte array
	ipBytes := make(net.IP, 4)

	// Write the uint32 into the byte slice in Big Endian order
	binary.BigEndian.PutUint32(ipBytes, nn)

	// Convert net.IP to string format (e.g., "192.168.1.1")
	return ipBytes.String()
}

func IPStringToUint32(ipStr string) uint32 {
	// Parse the string into a net.IP object
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}

	// Safely extract the 4-byte IPv4 representation
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}

	// Read the bytes as a Big Endian uint32
	return binary.BigEndian.Uint32(ipv4)
}

type NativeIPNet struct {
	Base uint32 // The network address (e.g., 192.168.1.0)
	Mask uint32 // The subnet mask (e.g., 255.255.255.0)
}

// Contains performs a zero-allocation bitwise check to see if an IP belongs to this subnet.
func (n NativeIPNet) Contains(ip uint32) bool {
	return (ip & n.Mask) == n.Base
}

func NewNativeIPNet(cidrStr string) (uint32, NativeIPNet, error) {
	addr, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return 0, NativeIPNet{}, fmt.Errorf("invalid CIDR: %w", err)
	}

	// 1. Extract the 4-byte IPv4 representation of the network base address
	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return 0, NativeIPNet{}, fmt.Errorf("only IPv4 is supported")
	}
	baseInt := binary.BigEndian.Uint32(ipv4)

	// 2. Extract the 4-byte mask representation
	maskBytes := ipNet.Mask
	if len(maskBytes) == 16 {
		// If it's stored as a 16-byte IPv6 mask, grab the last 4 bytes for IPv4
		maskBytes = maskBytes[12:]
	}
	maskInt := binary.BigEndian.Uint32(maskBytes)

	return IPToUint32(addr), NativeIPNet{
		Base: baseInt,
		Mask: maskInt,
	}, nil
}
