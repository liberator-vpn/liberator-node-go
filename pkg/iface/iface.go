package iface

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

type Router interface {
	HandleTunPacket(packet *dgmessage.DatagramMessage)
	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	ToTUNChannel() chan *dgmessage.DatagramMessage
}

// TUNIface управляет TUN-интерфейсом и маршрутизацией.
type TUNIface struct {
	ctx context.Context
	cfg appconfig.TUNConfig

	router Router

	ifce  tun.Device
	ipNet *net.IPNet
	ipt   *iptables.IPTables
}

const tun_iface_offset = 10
const ringSize = 3

// NewTUN создаёт и настраивает TUN-интерфейс.
func NewTUN(
	ctx context.Context,
	cfg appconfig.TUNConfig,

	router Router,
	ipCIDR string,
) (*TUNIface, error) {
	eg := &TUNIface{
		ctx:    ctx,
		cfg:    cfg,
		router: router,
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
	/*
		// Вычисляем сетевой адрес (обнуляем хостовую часть)
		networkIP := eg.ipNet.IP.Mask(eg.ipNet.Mask)
		network := &net.IPNet{
			IP:   networkIP,
			Mask: eg.ipNet.Mask,
		}

		route := &netlink.Route{
			Family:    netlink.FAMILY_V4, // явно указываем IPv4
			Dst:       network,           // теперь 10.8.0.0/16
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
		}
		if err := netlink.RouteAdd(route); err != nil {
			// Проверяем, является ли ошибка "file exists"
			if strings.Contains(err.Error(), "file exists") {
				log.Printf("Route already exists, skipping: %v", err)
				// Можно также попробовать заменить или просто проигнорировать
			} else {
				eg.Close()
				return nil, fmt.Errorf("failed to add route: %w", err)
			}
		}
	*/
	/*
		// 4. Включаем IP-форвардинг
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
			eg.Close()
			return nil, fmt.Errorf("failed to enable ipv4 forward: %w", err)
		}

		// 4.1. ДОБАВЛЕНО: Глобально включаем BBR для всех TCP соединений сервера
		// Для работы BBR ядро Linux также требует дисциплину очередей fq (она у вас уже активна)
		if err := os.WriteFile("/proc/sys/net/ipv4/tcp_congestion_control", []byte("bbr"), 0644); err != nil {
			// Если ядро старое и не поддерживает BBR, логируем предупреждение, но не падаем
			log.Printf("[Warning] Failed to set TCP congestion control to BBR: %v. Falling back to system default.", err)
		}

		// 5. ДОБАВЛЕНО: Отключаем Reverse Path Filtering для интерфейса liberator
		rpFilterPath := filepath.Join("/proc/sys/net/ipv4/conf", cfg.IfaceInName, "rp_filter")
		if err := os.WriteFile(rpFilterPath, []byte("0"), 0644); err != nil {
			// Некоторые ядра требуют отключения и на глобальном уровне
			_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0"), 0644)
		}
	*/

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

// sudo iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/16 -o amn0 -j MASQUERADE
func (eg *TUNIface) setupNAT() error {
	if eg.cfg.IfaceOutName == "" {
		ext, err := getDefaultInterface()
		if err != nil {
			return fmt.Errorf("failed to get default iface: %w", err)
		}
		eg.cfg.IfaceOutName = ext
	}

	network := &net.IPNet{
		IP:   eg.ipNet.IP.Mask(eg.ipNet.Mask),
		Mask: eg.ipNet.Mask,
	}
	tunNet := network.String()

	// А) ДОБАВЛЕНО: MSS Clamping (Зажатие MSS под PMTU)
	// Это заставит компьютеры на Windows/Linux отправлять TCP сегменты,
	// которые гарантированно пролезут через L3 Point-to-Point линк
	err := eg.ipt.Append("mangle", "FORWARD",
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
	)
	if err != nil {
		return fmt.Errorf("failed to setup MSS Clamping: %w", err)
	}

	// Б) Маскарадинг (NAT) трафика из подсети туннеля наружу в amn0
	if err := eg.ipt.Append("nat", "POSTROUTING", "-s", tunNet, "-o", eg.cfg.IfaceOutName, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	// В) КРОСС-ФОРВАРДИНГ: Разрешаем прохождение пакетов МЕЖДУ интерфейсами
	// Разрешаем трафик из TUN во внешний мир
	if err := eg.ipt.Append("filter", "FORWARD", "-i", eg.cfg.IfaceInName, "-o", eg.cfg.IfaceOutName, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to setup FORWARD IN->OUT: %w", err)
	}

	// Разрешаем трафик из внешнего мира обратно в TUN (только для уже установленных соединений)
	err = eg.ipt.Append("filter", "FORWARD",
		"-i", eg.cfg.IfaceOutName,
		"-o", eg.cfg.IfaceInName,
		"-m", "conntrack",
		"--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
	)
	if err != nil {
		return fmt.Errorf("failed to setup FORWARD OUT->IN: %w", err)
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
func (eg *TUNIface) Close() error {
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
func (eg *TUNIface) Run() {
	var wg sync.WaitGroup

	batchSize := eg.ifce.BatchSize()

	wg.Go(func() {
		eg.readLoop(batchSize)
	})

	toIfaceChan := eg.router.ToTUNChannel()
	wg.Go(func() {
		eg.writeLoop(toIfaceChan, batchSize)
	})
	wg.Wait()
	eg.Close()
}

// readLoop – батчевое чтение из TUN
func (eg *TUNIface) readLoop(batchSize int) {
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

				msg, err := eg.router.NewMessageCopyFrom(flatBuffer[flatStart:flatEnd])
				if err != nil {
					log.Printf("invalid egress datagram message: %v", err)
					continue
				}

				eg.router.HandleTunPacket(msg)
			}
		}(bufferIndex, n, ringSizes[bufferIndex])
	}
}

// writeLoop – батчевая запись в TUN с линеаризованной памятью
func (eg *TUNIface) writeLoop(toEgr chan *dgmessage.DatagramMessage, batchSize int) {
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
			if len(msg.Data) == 0 || len(msg.Data) > eg.cfg.MTU {
				msg.Free()
				continue
			}

			flatStart := (idx * maxPacketLen) + tun_iface_offset
			copy(flatBuffer[flatStart:], msg.Data)

			msgs[idx] = msg
			idx++
		}

		// Пытаемся добрать пачку до batchSize из канала без блокировки
		if idx < 4 {
			runtime.Gosched()
		}
		for idx < batchSize {
			select {
			case msg := <-toEgr:
				if len(msg.Data) == 0 || len(msg.Data) > eg.cfg.MTU {
					msg.Free()
					continue
				}

				flatStart := (idx * maxPacketLen) + tun_iface_offset
				copy(flatBuffer[flatStart:], msg.Data)

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
				end := start + tun_iface_offset + len(msgs[i].Data)
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
