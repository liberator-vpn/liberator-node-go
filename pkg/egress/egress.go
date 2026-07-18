package egress

import (
	"context"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/utils/dgmessage"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

// Egress управляет TUN-интерфейсом и маршрутизацией.
type Egress struct {
	ctx         context.Context
	cfg         appconfig.EgressConfig
	packetsPool dgmessage.DGMessagePool

	ifce  tun.Device
	ipNet *net.IPNet
	ipt   *iptables.IPTables
}

const tun_iface_offset = 10
const ringSize = 3

// New создаёт и настраивает TUN-интерфейс.
func New(ctx context.Context, cfg appconfig.EgressConfig, packetsPool dgmessage.DGMessagePool, ipCIDR string) (*Egress, error) {
	eg := &Egress{
		ctx:         ctx,
		cfg:         cfg,
		packetsPool: packetsPool,
	}

	// 1. Создаём TUN-интерфейс
	var err error
	eg.ifce, err = tun.CreateTUN(cfg.IfaceInName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUn: %w", err)
	}

	// 2. Парсим IP и маску
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		eg.Close()
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	eg.ipNet = &net.IPNet{IP: ip, Mask: ipNet.Mask}

	// 3. Настраиваем интерфейс через netlink
	link, err := netlink.LinkByName(cfg.IfaceInName)
	if err != nil {
		eg.Close()
		return nil, fmt.Errorf("failed to get iface with name %s: %w", cfg.IfaceInName, err)
	}

	// Добавляем IP-адрес
	addr := &netlink.Addr{IPNet: eg.ipNet}
	if err := netlink.AddrAdd(link, addr); err != nil {
		eg.Close()
		return nil, fmt.Errorf("failed to add IP: %w", err)
	}

	// Задаем MTU
	if cfg.MTU > 0 {
		if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
			eg.Close()
			return nil, fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Поднимаем интерфейс
	if err := netlink.LinkSetUp(link); err != nil {
		eg.Close()
		return nil, fmt.Errorf("failed to up iface: %w", err)
	}

	// 4. Включаем IP-форвардинг
	// sysctl -w net.ipv4.ip_forward=1

	// 5. Настраиваем NAT через go-iptables
	eg.ipt, err = iptables.New()
	if err != nil {
		eg.Close()
		return nil, fmt.Errorf("failed to initialize iptables: %w", err)
	}

	if err := eg.setupNAT(); err != nil {
		eg.Close()
		return nil, err
	}

	return eg, nil
}
func (eg *Egress) setupNAT() error {
	// Если внешний интерфейс не задан, определяем его автоматически
	if eg.cfg.IfaceOutName == "" {
		ext, err := getDefaultInterface()
		if err != nil {
			return fmt.Errorf("failed to get default iface: %w", err)
		}
		eg.cfg.IfaceOutName = ext
	}

	tunNet := eg.ipNet.String()

	// Маскарадинг (NAT)
	if err := eg.ipt.Append("nat", "POSTROUTING", "-s", tunNet, "-o", eg.cfg.IfaceOutName, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	// Разрешаем форвардинг для TUN-интерфейса
	for _, rule := range [][]string{
		{"-i", eg.cfg.IfaceInName, "-j", "ACCEPT"},
		{"-o", eg.cfg.IfaceInName, "-j", "ACCEPT"},
	} {
		if err := eg.ipt.Append("filter", "FORWARD", rule...); err != nil {
			return fmt.Errorf("failed to setup iface FORWARD: %w", err)
		}
	}
	return nil
}

// getDefaultInterface возвращает имя интерфейса по умолчанию (через netlink).
func getDefaultInterface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, r := range routes {
		// Маршрут по умолчанию — Dst == nil или 0.0.0.0/0
		if r.Dst == nil || (r.Dst.IP != nil && r.Dst.IP.IsUnspecified()) {
			if r.LinkIndex > 0 {
				link, err := netlink.LinkByIndex(r.LinkIndex)
				if err != nil {
					return "", err
				}
				return link.Attrs().Name, nil
			}
		}
	}
	return "", fmt.Errorf("failed to get default iface")
}

// Close удаляет интерфейс и очищает правила iptables.
func (eg *Egress) Close() error {
	var errs []string

	eg.ifce.Close()

	// Удаляем правила iptables
	if eg.ipt != nil && eg.ipNet != nil && eg.cfg.IfaceOutName != "" {
		tunNet := eg.ipNet.String()

		// Удаляем NAT
		if err := eg.ipt.Delete("nat", "POSTROUTING", "-s", tunNet, "-o", eg.cfg.IfaceOutName, "-j", "MASQUERADE"); err != nil {
			errs = append(errs, fmt.Sprintf("failed to remove NAT: %v", err))
		}

		// Удаляем FORWARD правила
		for _, rule := range [][]string{
			{"-i", eg.cfg.IfaceInName, "-j", "ACCEPT"},
			{"-o", eg.cfg.IfaceInName, "-j", "ACCEPT"},
		} {
			if err := eg.ipt.Delete("filter", "FORWARD", rule...); err != nil {
				errs = append(errs, fmt.Sprintf("failed to remove FORWARD: %v", err))
			}
		}
	}

	// Удаляем интерфейс
	if eg.ifce != nil {
		if link, err := netlink.LinkByName(eg.cfg.IfaceInName); err == nil {
			if err := netlink.LinkDel(link); err != nil {
				errs = append(errs, fmt.Sprintf("failed to remove iface: %v", err))
			}
		} else {
			errs = append(errs, fmt.Sprintf("failed to find iface: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close: %s", strings.Join(errs, "; "))
	}
	return nil
}
func (eg *Egress) Run(toEgr, fromEgr chan *dgmessage.DatagramMessage) {
	var wg sync.WaitGroup

	batchSize := eg.ifce.BatchSize()

	wg.Go(func() {
		eg.readLoop(fromEgr, batchSize)
	})

	wg.Go(func() {
		eg.writeLoop(toEgr, batchSize)
	})
	wg.Wait()
}

// readLoop – батчевое чтение из TUN
func (eg *Egress) readLoop(fromEgr chan *dgmessage.DatagramMessage, batchSize int) {
	maxPacketLen := math.MaxUint16 + tun_iface_offset

	locks := make([]sync.Mutex, ringSize)
	ringSizes := make([][]int, ringSize)
	for i := 0; i < ringSize; i++ {
		ringSizes[i] = make([]int, batchSize)
	}

	flatBuffer := make([]byte, ringSize*batchSize*maxPacketLen)
	readProjections := make([][][]byte, ringSize)
	for r := 0; r < ringSize; r++ {
		readProjections[r] = make([][]byte, batchSize)
		for i := 0; i < batchSize; i++ {
			// Нарезаем плоский буфер на правильные сегменты по формуле смещения
			start := (r * batchSize * maxPacketLen) + (i * maxPacketLen)
			end := start + maxPacketLen
			readProjections[r][i] = flatBuffer[start:end]
		}
	}

	bufferIndex := 0

	for {
		select {
		case <-eg.ctx.Done():
			return
		default:
		}

		locks[bufferIndex].Lock()

		n, err := eg.ifce.Read(readProjections[bufferIndex], ringSizes[bufferIndex], tun_iface_offset)
		if err != nil {
			locks[bufferIndex].Unlock()
			log.Printf("failed to read from iface: %v", err)
			time.Sleep(time.Millisecond * 2)
			continue
		}
		if n == 0 {
			locks[bufferIndex].Unlock()
			continue
		}

		go func(idx int, count int, sizes []int) {
			defer locks[idx].Unlock()
			for i := 0; i < n; i++ {
				if sizes[i] <= 0 {
					continue
				}

				flatStart := (idx * batchSize * maxPacketLen) + (i * maxPacketLen) + tun_iface_offset
				flatEnd := flatStart + sizes[i] + tun_iface_offset

				msg, err := eg.packetsPool.NewMessageCopyFrom(flatBuffer[flatStart:flatEnd])
				if err != nil {
					log.Printf("invalid egress datagram message: %v", err)
					continue
				}

				select {
				case fromEgr <- msg:
				case <-eg.ctx.Done():
					msg.Free()
					return
				}
			}
		}(bufferIndex, n, ringSizes[bufferIndex])
	}
}

// writeLoop – батчевая запись в TUN с линеаризованной памятью
func (eg *Egress) writeLoop(toEgr chan *dgmessage.DatagramMessage, batchSize int) {
	maxPacketLen := math.MaxUint16 + tun_iface_offset

	flatBuffer := make([]byte, batchSize*maxPacketLen)

	writeProjections := make([][]byte, batchSize)
	for i := 0; i < batchSize; i++ {
		start := i * maxPacketLen
		end := start + maxPacketLen
		writeProjections[i] = flatBuffer[start:end]
	}

	msgs := make([]*dgmessage.DatagramMessage, batchSize)
	idx := 0

	defer func() {
		for i := 0; i < idx; i++ {
			if msgs[i] != nil {
				msgs[i].Free()
			}
		}
	}()

	for {
		select {
		case <-eg.ctx.Done():
			return
		case msg := <-toEgr:
			if msg.Data == nil || len(*msg.Data) == 0 || len(*msg.Data) > eg.cfg.MTU {
				msg.Free()
				continue
			}

			flatStart := (idx * maxPacketLen) + tun_iface_offset
			copy(flatBuffer[flatStart:], *msg.Data)

			msgs[idx] = msg
			idx++
		}

		// Пытаемся добрать пачку до batchSize из канала без блокировки
		for idx < batchSize {
			select {
			case msg := <-toEgr:
				if msg.Data == nil || len(*msg.Data) == 0 || len(*msg.Data) > eg.cfg.MTU {
					msg.Free()
					continue
				}

				flatStart := (idx * maxPacketLen) + tun_iface_offset
				copy(flatBuffer[flatStart:], *msg.Data)

				msgs[idx] = msg
				idx++
			default:
				goto send
			}
		}

	send:
		if idx > 0 {
			for i := 0; i < idx; i++ {
				start := i * maxPacketLen
				end := start + tun_iface_offset + len(*msgs[i].Data)
				writeProjections[i] = flatBuffer[start:end]
			}

			_, err := eg.ifce.Write(writeProjections[:idx], tun_iface_offset)
			if err != nil {
				log.Printf("failed to write batch to iface: %v", err)
			}

			for i := 0; i < idx; i++ {
				msgs[i].Free()
				msgs[i] = nil
			}

			idx = 0
		}
	}
}
