package ipalloc

import (
	"errors"
	"net"
	"sync"
)

// IPAllocator управляет пулом IP-адресов в заданной подсети.
// Потокобезопасен.
type IPAllocator struct {
	mu    sync.Mutex
	start uint32   // первый доступный адрес (после шлюза)
	end   uint32   // последний доступный адрес (перед широковещательным)
	next  uint32   // следующий адрес для выдачи (инкрементируется)
	freed []uint32 // освобождённые адреса (переиспользуются в первую очередь)
}

// NewIPAllocator создаёт аллокатор для подсети в формате CIDR (например, "10.0.0.0/16").
// Резервирует адрес сети, широковещательный и шлюз (первый адрес подсети).
// Возвращает ошибку, если подсеть не IPv4 или в ней нет свободных адресов.
func New(cidr string) (*IPAllocator, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Проверяем, что это IPv4
	if len(ipnet.IP) != 4 {
		return nil, errors.New("only IPv4 is supported")
	}

	_, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, errors.New("only IPv4 is supported")
	}

	// Вычисляем сетевой и широковещательный адреса как uint32
	network := ipToU32(ipnet.IP.Mask(ipnet.Mask))
	broadcast := network | ^ipToU32(net.IP(ipnet.Mask))

	// Шлюз – первый адрес после сети
	gateway := network + 1

	start := gateway + 1 // первый адрес для клиентов
	end := broadcast - 1 // последний адрес для клиентов

	if start > end {
		return nil, errors.New("no available addresses in subnet")
	}

	return &IPAllocator{
		start: start,
		end:   end,
		next:  start,
		freed: []uint32{},
	}, nil
}

// ipToU32 преобразует IPv4-адрес в uint32 (сетевой порядок байт).
func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// u32ToIP преобразует uint32 в net.IP.
func u32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// Get возвращает свободный IP-адрес или ошибку, если пул исчерпан.
func (a *IPAllocator) Get() (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var addr uint32
	if len(a.freed) > 0 {
		// Берём последний освобождённый адрес (LIFO)
		addr = a.freed[len(a.freed)-1]
		a.freed = a.freed[:len(a.freed)-1]
	} else {
		if a.next > a.end {
			return nil, errors.New("no free IP addresses")
		}
		addr = a.next
		a.next++
	}

	return u32ToIP(addr), nil
}

// Free освобождает ранее выданный IP-адрес, делая его доступным для повторного использования.
// Возвращает ошибку, если адрес вне допустимого диапазона или уже свободен.
func (a *IPAllocator) Free(ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	addr := ipToU32(ip)
	if addr < a.start || addr > a.end {
		return errors.New("address out of range")
	}

	// Проверяем, не освобождён ли уже (защита от дубликатов)
	for _, f := range a.freed {
		if f == addr {
			return errors.New("address already free")
		}
	}

	a.freed = append(a.freed, addr)
	return nil
}
