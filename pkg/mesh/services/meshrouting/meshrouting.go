package meshrouting

import (
	"context"
	"liberator-node-go/internal/utils/peerstore"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/pkg/mesh/services/meshrouting/proto"
	"log"
	"net"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type DatagramMeshRouter interface {
	NewVirtualConnection(nodeID, userID, virtualIP string) (routingtable.RoutingObject, error)
	NodeID() string
}

type MeshRoutingService struct {
	ctx          context.Context
	routingTable routingtable.RoutingTable
	peerStore    *peerstore.PeerStore

	dgRouter DatagramMeshRouter
	proto.MeshRoutingServiceServer
}

func New(grpcServer *grpc.Server, peerStore *peerstore.PeerStore, routingTable routingtable.RoutingTable, dgRouter DatagramMeshRouter) (*MeshRoutingService, error) {
	mr := &MeshRoutingService{
		routingTable: routingTable,
		peerStore:    peerStore,
		dgRouter:     dgRouter,
	}
	proto.RegisterMeshRoutingServiceServer(grpcServer, mr)
	routingTable.AddEventHandler(mr.onRoutingTableEvent)
	return mr, nil
}

func (mr *MeshRoutingService) onRoutingTableEvent(added, deleted routingtable.RoutingObject) {
	// Notify only about our clients
	upd := &proto.UserConnectionUpdate{}
	if added != nil {
		if added.GetNodeID() != mr.dgRouter.NodeID() {
			return
		}
		upd.Type = proto.UpdateType_ADD
		upd.Add = &proto.UserConnection{
			UserId:    added.GetUserID().String(),
			VirtualIp: added.GetVirtualIP().String(),
			NodeId:    added.GetNodeID(),
		}

		for _, rule := range mr.routingTable.DumpRules(added.GetUserID()) {
			r := &proto.PortRule{
				Protocol:       rule.Protocol,
				PortRangeStart: uint32(rule.PortRangeStart),
			}
			if rule.TargetUser != nil {
				targetUser := rule.TargetUser.String()
				r.TargetUser = &targetUser
			}
			if rule.PortRangeEnd != nil {
				val := uint32(*rule.PortRangeEnd)
				r.PortRangeEnd = &val
			}
			upd.Add.Rules = append(upd.Add.Rules, r)
		}
	}
	if deleted != nil {
		if deleted.GetNodeID() != mr.dgRouter.NodeID() {
			return
		}
		upd.Type = proto.UpdateType_REMOVE
		upd.RemoveVirtualIp = deleted.GetVirtualIP().String()
	}

	if mr.ctx == nil {
		return
	}
	for _, peer := range mr.peerStore.ListConnected() {
		_, err := proto.NewMeshRoutingServiceClient(peer.Connection.GrpcClient()).PushConnectionUpdate(mr.ctx, upd)
		if err != nil {
			log.Printf("failed to push connection update: %v", err)
		}
	}
}

func (mr *MeshRoutingService) Run(ctx context.Context) {
	mr.ctx = ctx
	// Every 30 seconds pull full routing table dump for sync
	ticker := time.NewTicker(time.Second * 30)
	go func() {
		for range ticker.C {
			for _, peer := range mr.peerStore.ListConnected() {
				resp, err := proto.NewMeshRoutingServiceClient(peer.Connection.GrpcClient()).PullFullTable(ctx, &emptypb.Empty{})
				if err != nil {
					log.Printf("failed to pull full table: %v", err)
					continue
				}
				mr.merge(resp.Connections)
			}
		}
	}()

	<-ctx.Done()
	ticker.Stop()
}

func (mr *MeshRoutingService) merge(rq []*proto.UserConnection) {
	// Add missing
	for _, info := range rq {
		_, byIpEx := mr.routingTable.GetByVirtualIp(net.ParseIP(info.VirtualIp))
		if byIpEx {
			continue
		}
		mr.add(info)
	}
}
func (mr *MeshRoutingService) add(rq *proto.UserConnection) {
	virualConnection, err := mr.dgRouter.NewVirtualConnection(rq.NodeId, rq.UserId, rq.VirtualIp)
	if err != nil {
		log.Printf("failed to create virtual connection: %v", err)
		return
	}
	if err := mr.routingTable.Add(virualConnection); err != nil {
		log.Printf("failed to add virtual connection: %v", err)
	}

	// Apply rules
	for _, rule := range rq.Rules {
		r := routingtable.PortRule{
			User:           virualConnection.GetUserID(),
			Protocol:       rule.Protocol,
			PortRangeStart: uint16(rule.PortRangeStart),
		}
		if rule.TargetUser != nil {
			targetUser, err := uuid.Parse(*rule.TargetUser)
			if err != nil {
				log.Printf("failed to add rule: uuid invalid")
			}
			r.TargetUser = &targetUser
		}
		if rule.PortRangeEnd != nil {
			val := uint16(*rule.PortRangeEnd)
			r.PortRangeEnd = &val
		}
		mr.routingTable.AddRule(r)
	}
}
func (mr *MeshRoutingService) delete(virtualIp string) {
	record, ex := mr.routingTable.GetByVirtualIp(net.ParseIP(virtualIp))
	if ex {
		mr.routingTable.Delete(record)
	}
	log.Printf("record %s removed", virtualIp)
}

// HANDLERS
func (mr *MeshRoutingService) PushConnectionUpdate(ctx context.Context, rq *proto.UserConnectionUpdate) (*emptypb.Empty, error) {
	// We have update, apply it to routing table
	switch rq.Type {
	case proto.UpdateType_ADD:
		if rq.Add == nil {
			return &emptypb.Empty{}, nil
		}
		mr.add(rq.Add)
	case proto.UpdateType_REMOVE:
		mr.delete(rq.RemoveVirtualIp)
	}
	return &emptypb.Empty{}, nil
}
func (mr *MeshRoutingService) PullFullTable(ctx context.Context, _ *emptypb.Empty) (*proto.UsersConnectionsList, error) {
	// Dump routing table and send it
	dump := mr.routingTable.Dump()
	r := &proto.UsersConnectionsList{Connections: make([]*proto.UserConnection, len(dump))}
	for i, v := range dump {
		cv := &proto.UserConnection{
			UserId:    v.UserID,
			VirtualIp: v.VirtualIP,
			NodeId:    v.NodeID,
		}
		for _, rule := range v.Rules {
			r := &proto.PortRule{
				Protocol:       rule.Protocol,
				PortRangeStart: uint32(rule.PortRangeStart),
			}
			if rule.TargetUser != nil {
				targetUser := rule.TargetUser.String()
				r.TargetUser = &targetUser
			}
			if rule.PortRangeEnd != nil {
				val := uint32(*rule.PortRangeEnd)
				r.PortRangeEnd = &val
			}
			cv.Rules = append(cv.Rules, r)
		}
		r.Connections[i] = cv
	}
	return r, nil
}
