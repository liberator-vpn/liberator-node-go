package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/internal/utils/cert"
	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"github.com/TexHik620953/liberator-node-go/pkg/router"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

var rootPrivate []byte
var rootCert *x509.Certificate
var startPort int = 10000

// Матрица файрвола: хранит разрешенные физические линки между портами
var (
	networkMatrixMu sync.RWMutex
	networkMatrix   = make(map[string]map[string]bool)
)

func nextPort() int {
	startPort++
	return startPort
}

// CanConnect вызывается транспортным слоем QUIC для проверки физической доступности линка
func CanConnect(fromAddr, toAddr string) bool {
	networkMatrixMu.RLock()
	defer networkMatrixMu.RUnlock()

	// Извлекаем порты из строк адресов (например, ":10001" или "127.0.0.1:10001")
	fromPort := getPort(fromAddr)
	toPort := getPort(toAddr)

	if fromPort == "" || toPort == "" {
		return false
	}

	// Проверяем двунаправленное разрешение в матрице
	if allowed, ok := networkMatrix[fromPort]; ok && allowed[toPort] {
		return true
	}
	return false
}

func allowLink(portA, portB int) {
	networkMatrixMu.Lock()
	defer networkMatrixMu.Unlock()

	pA := fmt.Sprintf("%d", portA)
	pB := fmt.Sprintf("%d", portB)

	if networkMatrix[pA] == nil {
		networkMatrix[pA] = make(map[string]bool)
		networkMatrix[pA] = make(map[string]bool)
	}
	if networkMatrix[pB] == nil {
		networkMatrix[pB] = make(map[string]bool)
	}

	networkMatrix[pA][pB] = true
	networkMatrix[pB][pA] = true
}

func getPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		// На случай если пришла строка просто со значением порта ":10001"
		if strings.Contains(addr, ":") {
			return strings.Split(addr, ":")[1]
		}
		return ""
	}
	return port
}

type NodeMeta struct {
	Node *mesh.MeshNode
	Port int
	Role string
}

type filteredTransport struct {
	transport.NetworkTransport
}

func (t *filteredTransport) Dial(ctx context.Context, addr string) (transport.PeerConnection, error) {
	if !CanConnect(t.Addr().String(), addr) {
		return nil, errors.New("connection blocked by test topology")
	}
	return t.NetworkTransport.Dial(ctx, addr)
}

type meshTestRouter struct{}

func (meshTestRouter) SubscribeEvents(context.Context) (<-chan router.RouterEvent, context.CancelFunc) {
	return make(chan router.RouterEvent), func() {}
}

func (meshTestRouter) DumpRoutingTable() []routingtable.RoutingTableRecordDump {
	return nil
}

func (meshTestRouter) AddRemoteRoutingObject(routingtable.RoutingObject) error {
	return nil
}

func (meshTestRouter) DeleteRemoteRoutingObject(uint32) error {
	return nil
}

func (meshTestRouter) GetRemoteRoutingObject(uint32) (routingtable.RoutingObject, bool) {
	return nil, false
}

func (meshTestRouter) NewMessageCopyFrom([]byte) (*dgmessage.DatagramMessage, error) {
	return nil, errors.New("data plane is disabled in mesh test")
}

func (meshTestRouter) HandleMeshPacket(*dgmessage.DatagramMessage) {}

func createNode(ctx context.Context, port int, bootstrapNodes []string) *mesh.MeshNode {
	_, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	nodeCert, err := cert.IssueNodeCertificate(nodePrivate, "aboba", rootCert, rootPrivate)
	if err != nil {
		panic(err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	nodeCertTLS := tls.Certificate{
		Certificate: [][]byte{nodeCert.Raw},
		PrivateKey:  nodePrivate,
		Leaf:        nil,
	}
	cfg := appconfig.MeshConfig{
		ListenAddr:        fmt.Sprintf(":%d", port),
		BootstrapAddrs:    bootstrapNodes,
		PeersStore:        "",
		RTTUpdateInterval: 10 * time.Second,
	}
	baseTransport, err := transport.NewQuicTransport(cfg.ListenAddr, nodeCertTLS, rootPool)
	if err != nil {
		panic(err)
	}
	node, err := mesh.NewWithTransport(
		ctx,
		cfg,
		nodeCertTLS,
		meshTestRouter{},
		&filteredTransport{NetworkTransport: baseTransport},
	)
	if err != nil {
		_ = baseTransport.Close()
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

	nodeRegistry := make([]NodeMeta, 0)

	// =========================================================================
	// СТРОИМ ГЛУБОКУЮ РАЗВЕТВЛЕННУЮ ТОПОЛОГИЮ (TREE-MESH С СЕГМЕНТАМИ)
	// =========================================================================

	// LAYER 0: Главный Корневой Узел (Центральный коммутатор сети)
	rootPort := nextPort()
	rootNode := createNode(ctx, rootPort, []string{})
	nodeRegistry = append(nodeRegistry, NodeMeta{Node: rootNode, Port: rootPort, Role: "ROOT"})

	// LAYER 1: Два магистральных провайдера (Ветка А и Ветка Б)
	// Они соединены только с ROOT, но не видят друг друга напрямую!
	portBranchA := nextPort()
	nodeBranchA := createNode(ctx, portBranchA, []string{fmt.Sprintf("localhost:%d", rootPort)})
	allowLink(portBranchA, rootPort)
	nodeRegistry = append(nodeRegistry, NodeMeta{Node: nodeBranchA, Port: portBranchA, Role: "BACKBONE_A"})

	portBranchB := nextPort()
	nodeBranchB := createNode(ctx, portBranchB, []string{fmt.Sprintf("localhost:%d", rootPort)})
	allowLink(portBranchB, rootPort)
	nodeRegistry = append(nodeRegistry, NodeMeta{Node: nodeBranchB, Port: portBranchB, Role: "BACKBONE_B"})

	// LAYER 2: Региональные Хабы (По 2 под-узла на каждую магистраль)
	for i := 0; i < 4; i++ {
		// Хабы для Ветки А (Bootstrap-адрес ведет на BACKBONE_A)
		hubPortA := nextPort()
		hubNodeA := createNode(ctx, hubPortA, []string{fmt.Sprintf("localhost:%d", portBranchA)})
		allowLink(hubPortA, portBranchA)
		nodeRegistry = append(nodeRegistry, NodeMeta{Node: hubNodeA, Port: hubPortA, Role: fmt.Sprintf("HUB_A_%d", i)})

		// Хабы для Ветки Б (Bootstrap-адрес ведет на BACKBONE_B)
		hubPortB := nextPort()
		hubNodeB := createNode(ctx, hubPortB, []string{fmt.Sprintf("localhost:%d", portBranchB)})
		allowLink(hubPortB, portBranchB)
		nodeRegistry = append(nodeRegistry, NodeMeta{Node: hubNodeB, Port: hubPortB, Role: fmt.Sprintf("HUB_B_%d", i)})

		// LAYER 3: Конечные Листья (Глубокие клиенты, по 2 штуки под каждый хаб)
		// Уровень вложенности (Multi-hop) становится равен 3 хопам до корня!
		for j := 0; j < 4; j++ {
			leafPortA := nextPort()
			leafNodeA := createNode(ctx, leafPortA, []string{fmt.Sprintf("localhost:%d", hubPortA)})
			allowLink(leafPortA, hubPortA)
			nodeRegistry = append(nodeRegistry, NodeMeta{Node: leafNodeA, Port: leafPortA, Role: fmt.Sprintf("LEAF_A_%d_%d", i, j)})

			leafPortB := nextPort()
			leafNodeB := createNode(ctx, leafPortB, []string{fmt.Sprintf("localhost:%d", hubPortB)})
			allowLink(leafPortB, hubPortB)
			nodeRegistry = append(nodeRegistry, NodeMeta{Node: leafNodeB, Port: leafPortB, Role: fmt.Sprintf("LEAF_B_%d_%d", i, j)})
		}
	}

	// Запускаем все ноды параллельно
	for _, meta := range nodeRegistry {
		go meta.Node.Run()
	}

	fmt.Println("=== ТЕСТ ГЛУБОКОЙ РАЗВЕТВЛЕННОЙ СЕТИ ЗАПУЩЕН ===")
	fmt.Printf("Всего создано нод: %d\n", len(nodeRegistry))
	fmt.Printf("Ожидаемый результат: Peers должен сойтись к %d у всех (сеть знает про всех),\n", len(nodeRegistry))
	fmt.Println("но Connections у листьев будет равен строго 1 (физический линк только к своему хабу).")
	fmt.Println()

	// Цикл мониторинга
	for {
		time.Sleep(2 * time.Second)
		fmt.Println("--- Срез состояния сети ---")
		for _, meta := range nodeRegistry {
			fmt.Printf("%-14s [Ports: Active=%d / Total Known Peers=%d]\n",
				fmt.Sprintf("%s(:%d):", meta.Role, meta.Port),
				meta.Node.CountConnections(),
				meta.Node.CountPeers(),
			)
		}
		fmt.Println()
	}
}
