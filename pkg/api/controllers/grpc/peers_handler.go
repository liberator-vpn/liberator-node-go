package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/TexHik620953/liberator-node-go/pkg/api/grpc" // Наш общий сгенерированный grpc пакет
	"github.com/TexHik620953/liberator-node-go/pkg/model"
	"github.com/TexHik620953/liberator-node-go/pkg/services/peersmanager"
)

type PeersHandler struct {
	pb.UnimplementedPeerServiceServer
	manager *peersmanager.PeersManager
}

// RegisterPeerService регистрирует хэндлер пиров на gRPC сервере
func RegisterPeerService(server *grpc.Server, manager *peersmanager.PeersManager) {
	handler := &PeersHandler{manager: manager}
	pb.RegisterPeerServiceServer(server, handler)
}

func (h *PeersHandler) CreatePeerAutoID(ctx context.Context, req *pb.CreatePeerAutoIDRequest) (*pb.CreatePeerResponse, error) {
	domainPeer := &model.Peer{
		Type:           req.Type,
		TrafficLimitGb: req.TrafficLimitGb,
		SpeedLimitMbps: req.SpeedLimitMbps,
	}

	// Обрабатываем nullable/optional дату окончания действия
	if req.ExpirationDate != nil {
		expTime := req.ExpirationDate.AsTime()
		domainPeer.ExpirationDate = &expTime
	}

	err := h.manager.CreatePeerAutoID(ctx, domainPeer)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create peer: %v", err)
	}

	return &pb.CreatePeerResponse{
		Id:            domainPeer.ID,
		VirtualIp:     domainPeer.VirtualIP,
		AwgPrivateKey: domainPeer.AwgPrivateKey,
		AwgPublicKey:  domainPeer.AwgPrivateKey,
	}, nil
}
func (h *PeersHandler) GetPeer(ctx context.Context, req *pb.GetPeerRequest) (*pb.Peer, error) {
	if req.Id == 0 {
		return nil, status.Error(codes.InvalidArgument, "id cannot be 0")
	}

	peer, err := h.manager.GetPeerByID(ctx, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "peer not found: %v", err)
	}

	return convertToPbPeer(peer), nil
}

func (h *PeersHandler) ListPeers(ctx context.Context, _ *emptypb.Empty) (*pb.ListPeersResponse, error) {
	peers, err := h.manager.ListPeers(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list peers: %v", err)
	}

	pbPeers := make([]*pb.Peer, 0, len(peers))
	for _, peer := range peers {
		pbPeers = append(pbPeers, convertToPbPeer(peer))
	}

	return &pb.ListPeersResponse{Peers: pbPeers}, nil
}

func (h *PeersHandler) DeletePeer(ctx context.Context, req *pb.DeletePeerRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, status.Error(codes.InvalidArgument, "id cannot be 0")
	}

	err := h.manager.DeletePeer(ctx, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete peer: %v", err)
	}

	return &emptypb.Empty{}, nil
}
func (h *PeersHandler) ProlongPeer(ctx context.Context, req *pb.ProlongPeerRequest) (*emptypb.Empty, error) {
	err := h.manager.ProlongPeer(ctx, req.Id, req.NewExpirationDate.AsTime())
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (h *PeersHandler) GenerateClientKey(ctx context.Context, req *pb.GenerateClientKeyRequest) (*pb.GenerateClientKeyResponse, error) {
	key, err := h.manager.GenerateClientKey(ctx, req.PeerId, req.Addr, req.Name)
	if err != nil {
		return nil, err
	}
	return &pb.GenerateClientKeyResponse{
		Key: key,
	}, nil
}

// Вспомогательная функция для маппинга внутренней структуры в структуру Protobuf
func convertToPbPeer(p *model.Peer) *pb.Peer {
	pbPeer := &pb.Peer{
		Id:             p.ID,
		Type:           p.Type,
		VirtualIp:      p.VirtualIP,
		LastSeen:       timestamppb.New(p.LastSeen),
		FromPeerTotal:  p.FromPeerTotal,
		ToPeerTotal:    p.ToPeerTotal,
		AwgPrivateKey:  p.AwgPrivateKey,
		AwgPublicKey:   p.AwgPublicKey,
		TrafficLimitGb: p.TrafficLimitGb,
		SpeedLimitMbps: p.SpeedLimitMbps,
	}

	if p.ExpirationDate != nil {
		pbPeer.ExpirationDate = timestamppb.New(*p.ExpirationDate)
	}

	return pbPeer
}
