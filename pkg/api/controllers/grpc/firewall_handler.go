package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/TexHik620953/liberator-node-go/pkg/api/grpc" // Наш сгенерированный gRPC пакет
	"github.com/TexHik620953/liberator-node-go/pkg/model"
	"github.com/TexHik620953/liberator-node-go/pkg/services/firewallmanager"
)

type FirewallHandler struct {
	pb.UnimplementedFirewallServiceServer
	manager *firewallmanager.Firewallmanager
}

func RegisterFirewallService(server *grpc.Server, manager *firewallmanager.Firewallmanager) {
	handler := &FirewallHandler{manager: manager}
	pb.RegisterFirewallServiceServer(server, handler)
}

func (h *FirewallHandler) AddRule(ctx context.Context, req *pb.PortRule) (*pb.AddRuleResponse, error) {
	// Благодаря `optional` в .proto, поля TargetAddress и PortRangeEnd
	// в структуре req.Rule автоматически стали указателями (*uint32)!
	// Если клиент их не передал, они придут как nil, что идеально для нашей БД.
	domainRule := model.PortRule{
		TargetAddress:  req.TargetAddress, // Прямой маппинг *uint32 -> *uint32
		Protocol:       req.Protocol,
		PortRangeStart: uint16(req.PortRangeStart),
	}

	// Приведение типов для PortRangeEnd из *uint32 в *uint16, если он передан
	if req.PortRangeEnd != nil {
		endPort := uint16(*req.PortRangeEnd)
		domainRule.PortRangeEnd = &endPort
	}

	// Вызов Control Plane бизнес-логики
	err := h.manager.AddRule(ctx, req.PeerId, &domainRule)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add rule: %v", err)
	}

	// Возвращаем сгенерированный ID правила (manager записал его в domainRule.ID)
	return &pb.AddRuleResponse{RuleId: domainRule.ID}, nil
}

func (h *FirewallHandler) ListPeerRules(ctx context.Context, req *pb.ListPeerRulesRequest) (*pb.ListRulesResponse, error) {
	r, err := h.manager.ListPeerRules(ctx, req.PeerId)
	if err != nil {
		return nil, err
	}
	resp := &pb.ListRulesResponse{
		Rules: make([]*pb.PortRule, len(r)),
	}
	for i, v := range r {
		resp.Rules[i] = &pb.PortRule{
			PeerId:         req.PeerId,
			TargetAddress:  v.TargetAddress,
			Protocol:       v.Protocol,
			PortRangeStart: uint32(v.PortRangeStart),
		}
		if v.PortRangeEnd != nil {
			var portRangeEnd uint32
			portRangeEnd = uint32(*v.PortRangeEnd)
			resp.Rules[i].PortRangeEnd = &portRangeEnd
		}
	}
	return resp, nil
}

func (h *FirewallHandler) RemoveRule(ctx context.Context, req *pb.RemoveRuleRequest) (*emptypb.Empty, error) {
	if req.RuleId == 0 {
		return nil, status.Error(codes.InvalidArgument, "rule_id cannot be 0")
	}

	err := h.manager.RemoveRule(ctx, req.RuleId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove rule: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (h *FirewallHandler) RemoveAllPeerRules(ctx context.Context, req *pb.RemoveAllPeerRulesRequest) (*emptypb.Empty, error) {
	if req.PeerId == 0 {
		return nil, status.Error(codes.InvalidArgument, "peer_id cannot be 0")
	}

	err := h.manager.RemoveAllPeerRules(ctx, req.PeerId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove all peer rules: %v", err)
	}

	return &emptypb.Empty{}, nil
}
