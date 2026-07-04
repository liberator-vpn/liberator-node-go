package bridge

import (
	"context"
	"crypto/tls"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/utils/liberatorjwt"
	"liberator-node-go/pkg/egress"
	"liberator-node-go/pkg/ingress"
	"liberator-node-go/pkg/mesh"
)

type Bridge struct {
	ing  *ingress.Ingress
	egr  *egress.Egress
	mesh *mesh.MeshNode
}

func New(ctx context.Context, cfg appconfig.BridgeConfig, jwtIss *liberatorjwt.LiberatorJWT, cert *tls.Certificate) (*Bridge, error) {
	br := &Bridge{}

	var err error
	br.egr, err = egress.New(ctx, cfg.Egress.IfaceInName, cfg.CIDR, cfg.Egress.IfaceOutName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create egress: %w", err)
	}

	// TODO: Load certificate from file
	//cfg.Ingress.Cert, cfg.Ingress.Key

	br.ing, err = ingress.New(ctx, cfg.Ingress.ListenAddr, jwtIss, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create ingress: %w", err)
	}

	return br, nil
}

func (b *Bridge) Run() {
	ing2bridge := make(chan []byte, 10)
	bridge2ing := make(chan []byte, 10)
	go b.egr.Run(ing2bridge, bridge2ing)
	b.ing.Run(bridge2ing, ing2bridge)

}
