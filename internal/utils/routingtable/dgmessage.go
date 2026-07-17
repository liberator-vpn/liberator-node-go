package routingtable

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DatagramMessage struct {
	Data     []byte
	HoleInfo HoleInfo
}

func NewDatagramMessage(data []byte) (*DatagramMessage, error) {
	version := data[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("only ipv4 is supported")
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})

	ipv4LayerSt := packet.Layer(layers.LayerTypeIPv4)
	if ipv4LayerSt == nil {
		return nil, fmt.Errorf("ipv4 layer not found")
	}
	ipv4Layer := ipv4LayerSt.(*layers.IPv4)
	/*
		// Fixing address
		if !ipv4Layer.SrcIP.Equal(source.GetVirtualIP()) {
			ipv4Layer.SrcIP = source.GetVirtualIP()
			buffer := gopacket.NewSerializeBuffer()

			allLayers := packet.Layers()
			for _, layer := range allLayers {
				switch l := layer.(type) {
				case *layers.TCP:
					l.SetNetworkLayerForChecksum(ipv4Layer)
				case *layers.UDP:
					l.SetNetworkLayerForChecksum(ipv4Layer)
				}
			}
			serializableLayers := make([]gopacket.SerializableLayer, 0, len(allLayers))
			for _, layer := range allLayers {
				if s, ok := layer.(gopacket.SerializableLayer); ok {
					serializableLayers = append(serializableLayers, s)
				} else {
					return
				}
			}
			err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}, serializableLayers...)
			if err != nil {
				return
			}
			data = buffer.Bytes()
		}
	*/

	var protocol string
	var srcPort, dstPort uint16

	if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		tcpL := l.(*layers.TCP)
		protocol = "tcp"
		srcPort = uint16(tcpL.SrcPort)
		dstPort = uint16(tcpL.DstPort)
	} else if l := packet.Layer(layers.LayerTypeUDP); l != nil {
		udpL := l.(*layers.UDP)
		protocol = "udp"
		srcPort = uint16(udpL.SrcPort)
		dstPort = uint16(udpL.DstPort)
	} else if l := packet.Layer(layers.LayerTypeICMPv4); l != nil {
		protocol = "icmp"
		srcPort = 0
		dstPort = 0
	}

	return &DatagramMessage{
		Data: data,
		HoleInfo: HoleInfo{
			SrcIP: ipv4Layer.SrcIP,
			DstIP: ipv4Layer.DstIP,

			SrcPort: srcPort,
			DstPort: dstPort,

			Protocol: protocol,
		},
	}, nil
}
