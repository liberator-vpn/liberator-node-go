package egress

import (
	"fmt"
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// Egress управляет TUN-интерфейсом и маршрутизацией.
type Egress struct {
	ifce     *water.Interface
	ifName   string
	ipNet    *net.IPNet
	ipt      *iptables.IPTables
	extIface string // внешний интерфейс для NAT
}

// New создаёт и настраивает TUN-интерфейс.
func New(ifaceName, ipCIDR, externalIface string, mtu int) (*Egress, error) {
	eg := &Egress{
		ifName:   ifaceName,
		extIface: externalIface,
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
		return nil, fmt.Errorf("создание TUN: %w", err)
	}

	// 2. Парсим IP и маску
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		eg.Close()
		return nil, fmt.Errorf("неверный CIDR: %w", err)
	}
	eg.ipNet = &net.IPNet{IP: ip, Mask: ipNet.Mask}

	// 3. Настраиваем интерфейс через netlink
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		eg.Close()
		return nil, fmt.Errorf("получение интерфейса: %w", err)
	}

	// Добавляем IP-адрес
	addr := &netlink.Addr{IPNet: eg.ipNet}
	if err := netlink.AddrAdd(link, addr); err != nil {
		eg.Close()
		return nil, fmt.Errorf("добавление IP: %w", err)
	}

	// Задаем MTU
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			eg.Close()
			return nil, fmt.Errorf("установка MTU: %w", err)
		}
	}

	// Поднимаем интерфейс
	if err := netlink.LinkSetUp(link); err != nil {
		eg.Close()
		return nil, fmt.Errorf("поднятие интерфейса: %w", err)
	}

	// 4. Включаем IP-форвардинг
	// sysctl -w net.ipv4.ip_forward=1

	// 5. Настраиваем NAT через go-iptables
	eg.ipt, err = iptables.New()
	if err != nil {
		eg.Close()
		return nil, fmt.Errorf("инициализация iptables: %w", err)
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
			return fmt.Errorf("определение внешнего интерфейса: %w", err)
		}
		eg.extIface = ext
	}

	tunNet := eg.ipNet.String()

	// Маскарадинг (NAT)
	if err := eg.ipt.Append("nat", "POSTROUTING", "-s", tunNet, "-o", eg.extIface, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("добавление NAT: %w", err)
	}

	// Разрешаем форвардинг для TUN-интерфейса
	for _, rule := range [][]string{
		{"-i", eg.ifName, "-j", "ACCEPT"},
		{"-o", eg.ifName, "-j", "ACCEPT"},
	} {
		if err := eg.ipt.Append("filter", "FORWARD", rule...); err != nil {
			return fmt.Errorf("добавление FORWARD: %w", err)
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
	return "", fmt.Errorf("не найден интерфейс по умолчанию")
}

// Close удаляет интерфейс и очищает правила iptables.
func (eg *Egress) Close() error {
	var errs []string

	// Удаляем правила iptables
	if eg.ipt != nil && eg.ipNet != nil && eg.extIface != "" {
		tunNet := eg.ipNet.String()

		// Удаляем NAT
		if err := eg.ipt.Delete("nat", "POSTROUTING", "-s", tunNet, "-o", eg.extIface, "-j", "MASQUERADE"); err != nil {
			errs = append(errs, fmt.Sprintf("удаление NAT: %v", err))
		}

		// Удаляем FORWARD правила
		for _, rule := range [][]string{
			{"-i", eg.ifName, "-j", "ACCEPT"},
			{"-o", eg.ifName, "-j", "ACCEPT"},
		} {
			if err := eg.ipt.Delete("filter", "FORWARD", rule...); err != nil {
				errs = append(errs, fmt.Sprintf("удаление FORWARD: %v", err))
			}
		}
	}

	// Удаляем интерфейс
	if eg.ifce != nil {
		if link, err := netlink.LinkByName(eg.ifName); err == nil {
			if err := netlink.LinkDel(link); err != nil {
				errs = append(errs, fmt.Sprintf("удаление интерфейса: %v", err))
			}
		} else {
			errs = append(errs, fmt.Sprintf("интерфейс не найден: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("ошибки при закрытии: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (eg *Egress) Write(p []byte) (int, error) {
	return eg.ifce.Write(p)
}

func (eg *Egress) Read(p []byte) (int, error) {
	return eg.ifce.Read(p)
}
