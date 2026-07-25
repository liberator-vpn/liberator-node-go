package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/internal/utils/cert"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh"

	mrand "math/rand"
)

var rootPrivate []byte
var rootCert *x509.Certificate
var startPort int = 10000

func nextPort() int {
	startPort++
	return startPort
}

func createNode(ctx context.Context, port int, bootstrapNodes []string) *mesh.MeshNode {
	_, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	nodeCert, err := cert.IssueNodeCertificate(nodePrivate, "aboba", rootCert, rootPrivate)
	if err != nil {
		panic(err)
	}

	nodeCertTLS := tls.Certificate{
		Certificate: [][]byte{nodeCert.Raw},
		PrivateKey:  nodePrivate,
		Leaf:        nil,
	}
	node, err := mesh.New(ctx, appconfig.MeshConfig{
		ListenAddr:        fmt.Sprintf(":%d", port),
		BootstrapAddrs:    bootstrapNodes,
		PeersStore:        "",
		RTTUpdateInterval: 10 * time.Second,
	}, rootCert, nodeCertTLS, nil)
	if err != nil {
		panic(err)
	}
	return node
}

func main() {
	ctx := context.Background()
	var err error

	_, rootPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	rootCert, err = cert.GenerateRootCA(rootPrivate)
	if err != nil {
		panic(err)
	}

	nodes := make([]*mesh.MeshNode, 0)

	port1 := nextPort()
	baseNode1 := createNode(ctx, port1, []string{})
	nodes = append(nodes, baseNode1)

	port2 := nextPort()
	baseNode2 := createNode(ctx, port2, []string{fmt.Sprintf("localhost:%d", port1)})
	nodes = append(nodes, baseNode2)

	for range 10 {
		// select random node as bootstrap
		bootstrapNode := nodes[mrand.Int31n(int32(len(nodes)))]

		// create node
		node := createNode(ctx, nextPort(), []string{fmt.Sprintf("localhost%s", bootstrapNode.ListenAddr())})
		nodes = append(nodes, node)
	}
	for _, n := range nodes {
		go n.Run()
	}

	for {
		for _, n := range nodes {
			v := n.ListConnections()
			fmt.Printf("%d ", len(v))
		}
		fmt.Println("\n")
		<-time.After(time.Millisecond * 100)
	}

	select {}
}
