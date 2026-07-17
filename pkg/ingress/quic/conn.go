package ingressquic

import (
	"net"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
)

type IngressConnection struct {
	id     string    // Random id
	nodeID string    // Current mesh node id
	userID uuid.UUID // Current connection id

	virtualIp net.IP

	conn *quic.Conn
}

func wrapConnetion(conn *quic.Conn, nodeID string) *IngressConnection {
	ic := &IngressConnection{
		id:     uuid.NewString(),
		nodeID: nodeID,
		conn:   conn,

		virtualIp: nil,
	}

	return ic
}

// ---- RoutingObject ----

func (ic *IngressConnection) SendDatagram(data []byte) error {
	return ic.conn.SendDatagram(data)
}
func (ic *IngressConnection) GetNodeID() string {
	return ic.nodeID
}
func (ic *IngressConnection) GetUserID() uuid.UUID {
	return ic.userID
}
func (ic *IngressConnection) GetVirtualIP() net.IP {
	return ic.virtualIp
}

// ---- Setters (from ingress only) ----

func (ic *IngressConnection) SetUserID(userID uuid.UUID) {
	if ic.userID == uuid.Nil {
		ic.userID = userID
	}
}
func (ic *IngressConnection) SetVirtualIP(ip net.IP) {
	if ic.virtualIp == nil {
		ic.virtualIp = ip
	}
}

// ---- Others ----

func (ic *IngressConnection) Close() {
	_ = ic.conn.CloseWithError(0, "kicked")
}
