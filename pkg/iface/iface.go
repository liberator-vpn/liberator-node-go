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

	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

// defaultGatewayInterface возвращает имя интерфейса с default-маршрутом IPv4.
func defaultGatewayInterface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to list kernel routes: %w", err)
	}
	for _, route := range routes {
		if (route.Dst == nil || route.Dst.IP.IsUnspecified()) && route.LinkIndex > 0 {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return "", fmt.Errorf("failed to resolve link index %d: %w", route.LinkIndex, err)
			}
			return link.Attrs().Name, nil
		}
	}
	return "", fmt.Errorf("default outbound gateway route (0.0.0.0/0) not found")
}

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

	closeOnce sync.Once
	closeErr  error
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
	var err error
	// Получаем дефолтный выходной интерфейс
	if cfg.IfaceOutName == "" {
		cfg.IfaceOutName, err = defaultGatewayInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to get default out interface: %v", err)
		}
		log.Printf("[TUN] Autodetected primary outbound network interface: %s", cfg.IfaceOutName)
	}

	// 1. Создаём TUN-интерфейс. Если после аварийного завершения остался
	// старый линк с тем же именем, CreateTUN упадёт с EEXIST — удаляем его
	// и ждём, пока netlink реально уберёт линк.
	if link, err := netlink.LinkByName(cfg.IfaceInName); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			return nil, fmt.Errorf("failed to remove stale iface %s: %w", cfg.IfaceInName, err)
		}
		for i := 0; i < 100; i++ {
			if _, err := netlink.LinkByName(cfg.IfaceInName); err != nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
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

	// Настраиваем NAT через go-iptables
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

// tunNetwork возвращает сеть TUN с замаскированным адресом. Один и тот же
// источник используется и для Append, и для Delete: go-iptables ищет правило
// по точному совпадению аргументов.
func (eg *TUNIface) tunNetwork() *net.IPNet {
	return &net.IPNet{
		IP:   eg.ipNet.IP.Mask(eg.ipNet.Mask),
		Mask: eg.ipNet.Mask,
	}
}

func (eg *TUNIface) setupNAT() error {
	if eg.cfg.IfaceOutName == "" {
		ext, err := defaultGatewayInterface()
		if err != nil {
			return fmt.Errorf("failed to get default iface: %w", err)
		}
		eg.cfg.IfaceOutName = ext
	}

	tunNet := eg.tunNetwork().String()

	// AppendUnique, а не Append: после падения процесса/рестарта старые
	// правила могут остаться, и Append копил бы дубликаты.
	//
	// А) MSS Clamping: заставляет TCP-клиентов подстраивать MSS под PMTU.
	if err := eg.ipt.AppendUnique("mangle", "FORWARD",
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
	); err != nil {
		return fmt.Errorf("failed to setup MSS Clamping: %w", err)
	}

	// Б) Маскарадинг (NAT) трафика из подсети туннеля наружу.
	if err := eg.ipt.AppendUnique("nat", "POSTROUTING", "-s", tunNet, "-o", eg.cfg.IfaceOutName, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	// В) Разрешаем трафик из TUN во внешний мир.
	if err := eg.ipt.AppendUnique("filter", "FORWARD", "-i", eg.cfg.IfaceInName, "-o", eg.cfg.IfaceOutName, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to setup FORWARD IN->OUT: %w", err)
	}

	// Разрешаем обратный трафик только для уже установленных соединений.
	if err := eg.ipt.AppendUnique("filter", "FORWARD",
		"-i", eg.cfg.IfaceOutName,
		"-o", eg.cfg.IfaceInName,
		"-m", "conntrack",
		"--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
	); err != nil {
		return fmt.Errorf("failed to setup FORWARD OUT->IN: %w", err)
	}

	return nil
}

// Close удаляет интерфейс и очищает правила iptables. Идемпотентен: вызывается и из Run,
// и из шатдауна приложения, и из аварийных веток NewTUN.
func (eg *TUNIface) Close() error {
	eg.closeOnce.Do(func() { eg.closeErr = eg.close() })
	return eg.closeErr
}

func (eg *TUNIface) close() error {
	var errs []string

	if eg.ifce != nil {
		if err := eg.ifce.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("failed to close tun device: %v", err))
		}
	}

	// Удаляем ровно те правила, которые добавил setupNAT. Раньше здесь были
	// другие аргументы (`-i <tun> -j ACCEPT`), поэтому Delete ничего не
	// находил и правила жили до перезагрузки хоста.
	if eg.ipt != nil && eg.ipNet != nil && eg.cfg.IfaceOutName != "" {
		tunNet := eg.tunNetwork().String()

		for _, rule := range []struct {
			table, chain string
			args         []string
		}{
			{"mangle", "FORWARD", []string{
				"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu",
			}},
			{"nat", "POSTROUTING", []string{"-s", tunNet, "-o", eg.cfg.IfaceOutName, "-j", "MASQUERADE"}},
			{"filter", "FORWARD", []string{"-i", eg.cfg.IfaceInName, "-o", eg.cfg.IfaceOutName, "-j", "ACCEPT"}},
			{"filter", "FORWARD", []string{
				"-i", eg.cfg.IfaceOutName, "-o", eg.cfg.IfaceInName,
				"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT",
			}},
		} {
			if err := eg.ipt.DeleteIfExists(rule.table, rule.chain, rule.args...); err != nil {
				errs = append(errs, fmt.Sprintf("failed to remove %s/%s rule: %v", rule.table, rule.chain, err))
			}
		}
	}

	// Удаляем интерфейс. Если устройство уже удалило его само — это не ошибка.
	if eg.ifce != nil {
		if link, err := netlink.LinkByName(eg.cfg.IfaceInName); err == nil {
			if err := netlink.LinkDel(link); err != nil {
				errs = append(errs, fmt.Sprintf("failed to remove iface: %v", err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close: %s", strings.Join(errs, "; "))
	}
	return nil
}
func (eg *TUNIface) Run() {
	var wg sync.WaitGroup

	// readLoop висит в блокирующем read() и про ctx не знает: разбудить его может
	// только закрытие устройства (fd неблокирующий, read вернет os.ErrClosed).
	stopWatch := context.AfterFunc(eg.ctx, func() { _ = eg.ifce.Close() })
	defer stopWatch()

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
			// После Close read возвращает os.ErrClosed: не крутим busy-loop
			// со sleep и не спамим лог до выхода по ctx.
			select {
			case <-eg.ctx.Done():
				return
			default:
			}
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
			for i := 0; i < count; i++ {
				if sizes[i] <= 0 {
					continue
				}

				// sizes[i] это длина самого пакета, лежащего уже после offset.
				flatStart := (idx * batchSize * maxPacketLen) + (i * maxPacketLen) + tun_iface_offset
				flatEnd := flatStart + sizes[i]

				msg, err := eg.router.NewMessageCopyFrom(flatBuffer[flatStart:flatEnd])
				if err != nil {
					continue
				}
				metrics.ObserveTraffic(metrics.DirIn, metrics.PeerInternet, metrics.NoProtocol, sizes[i])

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
			out := 0
			for i := 0; i < idx; i++ {
				start := i * maxPacketLen
				end := start + tun_iface_offset + len(msgs[i].Data)
				writeProjections[i] = flatBuffer[start:end]
				out += len(msgs[i].Data)
			}
			metrics.ObserveTraffic(metrics.DirOut, metrics.PeerInternet, metrics.NoProtocol, out)

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
