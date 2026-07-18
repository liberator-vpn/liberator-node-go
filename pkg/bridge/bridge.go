package bridge

import (
	"context"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/utils/awgconfig"
	"liberator-node-go/internal/utils/dgmessage"
	"liberator-node-go/internal/utils/ipalloc"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/egress"
	"liberator-node-go/pkg/ingress"
	"liberator-node-go/pkg/ingress/awg"
	"liberator-node-go/pkg/mesh"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

type fromType = int

const (
	fromIngress fromType = 0
	fromTun     fromType = 1
	fromMesh    fromType = 2
)

type datagramMessageInfo struct {
	Msg  *dgmessage.DatagramMessage
	From fromType
}

type Bridge struct {
	ctx context.Context

	packetsPool  dgmessage.DGMessagePool
	ipAlloc      *ipalloc.IPAllocator
	routingTable routingtable.RoutingTable

	egr       *egress.Egress
	ingresses safemap.Safemap[string, ingress.Ingress]
	meshNode  *mesh.MeshNode

	gatewayAddr   net.IP
	network       *net.IPNet
	globalNetwork *net.IPNet

	toEgr, fromEgr chan *dgmessage.DatagramMessage
	fromMesh       chan *dgmessage.DatagramMessage
	fromIng        chan *dgmessage.DatagramMessage

	workerChans []chan datagramMessageInfo
}

func New(
	ctx context.Context,
	cfg appconfig.BridgeConfig,
	packetsPool dgmessage.DGMessagePool,
	meshNode *mesh.MeshNode,
	routingTable routingtable.RoutingTable,
	numWorkers int,
) (*Bridge, error) {
	br := &Bridge{
		ctx:          ctx,
		ingresses:    safemap.New[string, ingress.Ingress](),
		packetsPool:  packetsPool,
		routingTable: routingTable,
		meshNode:     meshNode,
		toEgr:        make(chan *dgmessage.DatagramMessage, 1024),
		fromEgr:      make(chan *dgmessage.DatagramMessage, 1024),
		fromMesh:     meshNode.DatagramChan(),
		fromIng:      make(chan *dgmessage.DatagramMessage, 1024),
		workerChans:  make([]chan datagramMessageInfo, numWorkers),
	}

	for i := 0; i < numWorkers; i++ {
		br.workerChans[i] = make(chan datagramMessageInfo, 1024)
	}

	var err error
	br.egr, err = egress.New(ctx, cfg.Egress, br.packetsPool, cfg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to create egress: %w", err)
	}

	_, br.globalNetwork, err = net.ParseCIDR(cfg.GlobalCIRD)
	if err != nil {
		return nil, fmt.Errorf("invalid global CIDR: %v", err)
	}

	// Build ip allocator and reserve gateway address
	br.ipAlloc, err = ipalloc.New(cfg.CIDR)
	if err != nil {
		return nil, err
	}
	br.gatewayAddr, br.network, err = net.ParseCIDR(cfg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	err = br.ipAlloc.Reserve(br.gatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to reserve ip for gateway: %v", err)
	}

	// Build ingresses
	for name, iconf := range cfg.Ingresses {
		if br.ingresses.Exists(name) {
			return nil, fmt.Errorf("duplicated ingress name: %s", name)
		}
		typ, ex := iconf["type"]
		if !ex {
			return nil, fmt.Errorf("type for ingress %s is not provided", name)
		}

		var ing ingress.Ingress
		switch typ {
		case "awg":
			icfg, err := awg.ParseConfig(iconf)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ingress %s config: %v", name, err)
			}

			awging, err := awg.New(
				ctx,
				icfg,
				br.packetsPool,
				br.routingTable,
				br.ipAlloc,
				br.fromIng, // Передаем общий канал входящих пакетов
				meshNode.NodeID(),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create ingress %s: %w", name, err)
			}
			ing = awging

			serverPubKey, err := getServerPubKey(icfg.PrivateKey)
			if err != nil {
				log.Fatalf("Failed to calc server pub key: %v", err)
			}
			fmt.Printf("Сервер Public Key (HEX): %s\n", serverPubKey)

			clientPrivKey := "58627383123294ebb76f5831ddcf3d40ed31104a9ef1c1accaf007efb4318b73"
			clientPubKey := "afa89c215becc53d4bc90562b7e1c8667298ec39ff3cff47857052c55a45b402"
			// Генерируем ключи клиента СРАЗУ В HEX
			//clientPrivKey, clientPubKey, err := generateKeyPair()
			//if err != nil {
			//	log.Fatalf("Failed to generate client keys: %v", err)
			//}

			userID := uuid.New()
			clientIp, err := awging.PreparePeer(userID, clientPubKey)
			if err != nil {
				log.Fatalf("Failed to prepare peer: %v", err)
			}

			clientTestConfig, iniString, err := awgconfig.GenerateURI(&awgconfig.ClientParams{
				ServerAddr:    "192.168.68.121",
				ServerPort:    2200,
				ServerPubKey:  serverPubKey,
				ClientPrivKey: clientPrivKey,
				ClientIP:      clientIp.String() + "/32",
				DNSServer:     "10.0.0.1",

				// Передаем ОБЯЗАТЕЛЬНО строками!
				H1:   icfg.H1,
				H2:   icfg.H2,
				H3:   icfg.H3,
				H4:   icfg.H4,
				Jc:   strconv.Itoa(icfg.Jc),
				Jmin: strconv.Itoa(icfg.JMin),
				Jmax: strconv.Itoa(icfg.JMax),
				S1:   strconv.Itoa(icfg.S1),
				S2:   strconv.Itoa(icfg.S2),
			})
			if err != nil {
				log.Fatalf("Failed to gen config: %v", err)
			}

			fmt.Println(clientTestConfig)
			fmt.Println(iniString)

		default:
			return nil, fmt.Errorf("unknown ingress type: %s", typ)
		}
		br.ingresses.Set(name, ing)
	}

	return br, nil
}

func (br *Bridge) handleTUNPacket(data *dgmessage.DatagramMessage) {
	err := br.routingTable.SendDatagram(data.HoleInfo.DstIP, data.Data)
	if err != nil {
		log.Printf("failed to send datagram from tun %d: %v", len(data.Data), err)
	}
	data.Free()
}
func (br *Bridge) handleMeshPacket(data *dgmessage.DatagramMessage) {
	if data.HoleInfo.Protocol != "" {
		br.routingTable.Holepunch(data.HoleInfo, time.Minute)
	}

	err := br.routingTable.SendDatagram(data.HoleInfo.DstIP, data.Data)
	if err != nil {
		log.Printf("failed to send datagram from mesh %d: %v", len(data.Data), err)
	}
	data.Free()
}
func (br *Bridge) handleIngressPacket(data *dgmessage.DatagramMessage) {
	if data.HoleInfo.DstIP.Equal(br.gatewayAddr) || !br.globalNetwork.Contains(data.HoleInfo.DstIP) {
		br.toEgr <- data // TUN
		return
	}
	hi := dgmessage.HoleInfo{
		SrcIP:    data.HoleInfo.SrcIP,
		DstIP:    data.HoleInfo.DstIP,
		SrcPort:  data.HoleInfo.SrcPort,
		DstPort:  data.HoleInfo.DstPort,
		Protocol: data.HoleInfo.Protocol,
	}
	if !br.routingTable.RuleCheck(hi) {
		return
	}

	br.routingTable.Holepunch(hi, time.Minute)
	if br.network.Contains(data.HoleInfo.DstIP) {
		br.toEgr <- data // TUN
	} else {

		err := br.routingTable.SendDatagram(data.HoleInfo.DstIP, data.Data)
		if err != nil {
			log.Printf("failed to send datagram to mesh: %v", err)
		}
		data.Free()
	}
}

func (br *Bridge) Run() {
	var wg sync.WaitGroup
	// Run ingresses
	br.ingresses.Foreach(func(s string, i ingress.Ingress) {
		wg.Go(func() {
			i.Run()
		})
	})
	// Run egresses
	wg.Go(func() {
		br.egr.Run(br.toEgr, br.fromEgr)
	})

	// Run parallel workers
	for i := 0; i < len(br.workerChans); i++ {
		workerID := i
		wg.Go(func() {
			for {
				select {
				case <-br.ctx.Done():
					return
				case data := <-br.workerChans[workerID]:
					switch data.From {
					case fromTun:
						br.handleTUNPacket(data.Msg)
					case fromMesh:
						br.handleMeshPacket(data.Msg)
					case fromIngress:
						br.handleIngressPacket(data.Msg)
					}
				}
			}
		})
	}

	// Messages router
	wg.Go(func() {
		for {
			select {
			case <-br.ctx.Done():
				return
			case data := <-br.fromEgr:
				// Пакет пришел из TUN, шардируем по DstIP (куда летит)
				br.getWorker(data.HoleInfo.DstIP) <- datagramMessageInfo{
					Msg:  data,
					From: fromTun,
				}
			case data := <-br.fromMesh:
				// Пакет из Mesh, шардируем по SrcIP (кто прислал)
				br.getWorker(data.HoleInfo.SrcIP) <- datagramMessageInfo{
					Msg:  data,
					From: fromMesh,
				}
			case data := <-br.fromIng:
				// Пакет от клиента (Ингресс). Шардируем строго по SrcIP клиента
				br.getWorker(data.HoleInfo.SrcIP) <- datagramMessageInfo{
					Msg:  data,
					From: fromIngress,
				}
			}
		}
	})
	wg.Wait()
}

func (br *Bridge) getWorker(ip net.IP) chan datagramMessageInfo {
	// Берём последние 4 байта (работает и для IPv4, и для IPv4-mapped IPv6)
	v4 := ip[len(ip)-4:]
	// Суммируем байты и берем остаток от деления на количество воркеров
	hash := uint32(v4[0]) + uint32(v4[1]) + uint32(v4[2]) + uint32(v4[3])
	return br.workerChans[hash%uint32(len(br.workerChans))]
}
