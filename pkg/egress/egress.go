package egress

import (
	"context"
	"fmt"
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
	ctx      context.Context
	ifce     *water.Interface
	ifName   string
	ipNet    *net.IPNet
	ipt      *iptables.IPTables
	extIface string // внешний интерфейс для NAT
	mtu      int
}

// New создаёт и настраивает TUN-интерфейс.
func New(ctx context.Context, ifaceName, ipCIDR, externalIface string, mtu int) (*Egress, error) {
	eg := &Egress{
		ctx:      ctx,
		ifName:   ifaceName,
		extIface: externalIface,
		mtu:      mtu,
	}

	// 1. Создаём TUN-интерфейс
	var err error
	eg.ifce, err = water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: ifaceName,
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
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		eg.Close()
		return nil, fmt.Errorf("failed to get iface with name %s: %w", ifaceName, err)
	}

	// Добавляем IP-адрес
	addr := &netlink.Addr{IPNet: eg.ipNet}
	if err := netlink.AddrAdd(link, addr); err != nil {
		eg.Close()
		return nil, fmt.Errorf("failed to add IP: %w", err)
	}

	// Задаем MTU
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
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
	if eg.extIface == "" {
		ext, err := getDefaultInterface()
		if err != nil {
			return fmt.Errorf("failed to get default iface: %w", err)
		}
		eg.extIface = ext
	}

	tunNet := eg.ipNet.String()

	// Маскарадинг (NAT)
	if err := eg.ipt.Append("nat", "POSTROUTING", "-s", tunNet, "-o", eg.extIface, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	// Разрешаем форвардинг для TUN-интерфейса
	for _, rule := range [][]string{
		{"-i", eg.ifName, "-j", "ACCEPT"},
		{"-o", eg.ifName, "-j", "ACCEPT"},
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
	if eg.ipt != nil && eg.ipNet != nil && eg.extIface != "" {
		tunNet := eg.ipNet.String()

		// Удаляем NAT
		if err := eg.ipt.Delete("nat", "POSTROUTING", "-s", tunNet, "-o", eg.extIface, "-j", "MASQUERADE"); err != nil {
			errs = append(errs, fmt.Sprintf("failed to remove NAT: %v", err))
		}

		// Удаляем FORWARD правила
		for _, rule := range [][]string{
			{"-i", eg.ifName, "-j", "ACCEPT"},
			{"-o", eg.ifName, "-j", "ACCEPT"},
		} {
			if err := eg.ipt.Delete("filter", "FORWARD", rule...); err != nil {
				errs = append(errs, fmt.Sprintf("failed to remove FORWARD: %v", err))
			}
		}
	}

	// Удаляем интерфейс
	if eg.ifce != nil {
		if link, err := netlink.LinkByName(eg.ifName); err == nil {
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

func (eg *Egress) Write(p []byte) (int, error) {
	return eg.ifce.Write(p)
}

func (eg *Egress) Read(p []byte) (int, error) {
	return eg.ifce.Read(p)
}

func (eg *Egress) Run() (chan<- []byte, <-chan []byte) {
	in := make(chan []byte, 10)
	out := make(chan []byte, 10)

	var wg sync.WaitGroup

	wg.Go(func() {
		buf := make([]byte, eg.mtu)
		for {
			select {
			case <-eg.ctx.Done():
				return
			default:
			}

			n, err := eg.Read(buf)
			if err != nil {
				log.Printf("failed to read from iface: %v", err)
				continue
			}
			if n == 0 {
				continue
			}

			data := make([]byte, n)
			copy(data, buf[:n])
			out <- data
		}
	})

	wg.Go(func() {
		for {
			select {
			case <-eg.ctx.Done():
				return
			case data := <-in:
				n, err := eg.Write(data)
				if err != nil {
					log.Printf("failed to write to iface: %v", err)
					continue
				}
				if n != len(data) {
					log.Printf("iface write size missmatch iface: %v", err)
				}
			}
		}
	})

	go func() {
		wg.Wait()
		close(in)
		close(out)
	}()
	return in, out
}
