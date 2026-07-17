package egress

import (
	"context"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/utils/routingtable"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// Egress управляет TUN-интерфейсом и маршрутизацией.
type Egress struct {
	ctx         context.Context
	cfg         appconfig.EgressConfig
	packetsPool routingtable.DGMessagePool

	ifce  *water.Interface
	ipNet *net.IPNet
	ipt   *iptables.IPTables
}

// New создаёт и настраивает TUN-интерфейс.
func New(ctx context.Context, cfg appconfig.EgressConfig, packetsPool routingtable.DGMessagePool, ipCIDR string) (*Egress, error) {
	eg := &Egress{
		ctx:         ctx,
		cfg:         cfg,
		packetsPool: packetsPool,
	}

	// 1. Создаём TUN-интерфейс
	var err error
	eg.ifce, err = water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: cfg.IfaceInName,
		},
	})
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
	if eg.cfg.IfaceInName == "" {
		ext, err := getDefaultInterface()
		if err != nil {
			return fmt.Errorf("failed to get default iface: %w", err)
		}
		eg.cfg.IfaceInName = ext
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

func (eg *Egress) Run(toEgr, fromEgr chan *routingtable.DatagramMessage) {
	var wg sync.WaitGroup

	wg.Go(func() {
		buf := make([]byte, eg.cfg.MTU)
		for {
			select {
			case <-eg.ctx.Done():
				return
			default:
			}

			n, err := eg.ifce.Read(buf)
			if err != nil {
				log.Printf("failed to read from iface: %v", err)
				continue
			}
			if n == 0 {
				continue
			}

			msg, err := eg.packetsPool.NewMessageCopyFrom(buf[:n])
			if err != nil {
				log.Printf("invalid egress datagram message: %v", err)
				continue
			}
			fromEgr <- msg
		}
	})

	wg.Go(func() {
		for {
			select {
			case <-eg.ctx.Done():
				return
			case msg := <-toEgr:
				n, err := eg.ifce.Write(*msg.Data)
				if err != nil {
					msg.Free()
					log.Printf("failed to write to iface: %v", err)
					continue
				}
				if n != len(*msg.Data) {
					log.Printf("iface write size missmatch iface: %v", err)
				}
				msg.Free()
			}
		}
	})

	wg.Wait()
}
