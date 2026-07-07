package ipalloc

import (
	"errors"
	"net"
	"sync"
)

// IPAllocator управляет пулом IP-адресов в заданной подсети.
// Потокобезопасен.
type IPAllocator struct {
	mu       sync.Mutex
	start    uint32   // первый доступный адрес (сетевой + 1)
	end      uint32   // последний доступный адрес (широковещательный - 1)
	next     uint32   // следующий адрес для выдачи (инкрементируется)
	freed    []uint32 // освобождённые адреса (переиспользуются в первую очередь)
	reserved []uint32 // зарезервированные адреса (не выдаются)
}

// NewIPAllocator создаёт аллокатор для подсети в формате CIDR (например, "10.0.0.0/16").
// Резервирует адрес сети и широковещательный, но не резервирует шлюз автоматически.
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

	start := network + 1 // первый адрес после сети (включая .1)
	end := broadcast - 1 // последний адрес перед широковещательным

	if start > end {
		return nil, errors.New("no available addresses in subnet")
	}

	return &IPAllocator{
		start:    start,
		end:      end,
		next:     start,
		freed:    []uint32{},
		reserved: []uint32{},
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

// isReserved проверяет, зарезервирован ли адрес.
func (a *IPAllocator) isReserved(addr uint32) bool {
	for _, r := range a.reserved {
		if r == addr {
			return true
		}
	}
	return false
}

// removeFromFreed удаляет адрес из списка освобождённых, если он там есть.
func (a *IPAllocator) removeFromFreed(addr uint32) {
	for i, f := range a.freed {
		if f == addr {
			a.freed = append(a.freed[:i], a.freed[i+1:]...)
			return
		}
	}
}

// Reserve резервирует IP-адрес, чтобы он никогда не выдавался аллокатором.
// Возвращает ошибку, если адрес вне диапазона, уже зарезервирован или уже выдан.
func (a *IPAllocator) Reserve(ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	addr := ipToU32(ip)
	if addr < a.start || addr > a.end {
		return errors.New("address out of range")
	}

	// Проверяем, не зарезервирован ли уже
	if a.isReserved(addr) {
		return errors.New("address already reserved")
	}

	// Если адрес был освобождён (в freed), удаляем его оттуда
	a.removeFromFreed(addr)

	// Если адрес уже выдан (addr < next и не в freed), то запрещаем резервирование
	// (выданные адреса нельзя зарезервировать, пока не освободят)
	if addr < a.next {
		// проверяем, не в freed ли он (но мы уже удалили, если был)
		// Если он не в freed и меньше next, значит он выдан
		// нужно проверить, нет ли его в freed (уже удалили), тогда он точно выдан
		// Но мы не храним список выданных, поэтому полагаемся на правило:
		// если addr < next и не был в freed, то он выдан.
		// Однако мы только что удалили его из freed, поэтому если он там был, то теперь его нет,
		// и addr < next - значит выдан. Но мы не хотим резервировать выданные.
		// Поэтому проверяем, не был ли он в freed до удаления? Мы не знаем.
		// Проще: проверить, есть ли он в freed после удаления - если нет и addr < next => выдан.
		// Но мы удалили, так что если он был в freed, то его там нет, и мы ошибочно решим, что он выдан.
		// Поэтому нужно запомнить, был ли он в freed. Сделаем флаг.
		foundInFreed := false
		for _, f := range a.freed {
			if f == addr {
				foundInFreed = true
				break
			}
		}
		if foundInFreed {
			// он был в freed, мы его удалили, значит он не выдан
			// ничего не делаем
		} else {
			// его нет в freed и addr < next => выдан
			return errors.New("address already allocated, cannot reserve")
		}
	}
	// Если addr >= next, то он ещё не выдавался (и не в freed), можно резервировать.

	a.reserved = append(a.reserved, addr)
	return nil
}

// Get возвращает свободный IP-адрес или ошибку, если пул исчерпан.
func (a *IPAllocator) Get() (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var addr uint32
	// Сначала пытаемся использовать освобождённые
	for len(a.freed) > 0 {
		// Берём последний
		addr = a.freed[len(a.freed)-1]
		a.freed = a.freed[:len(a.freed)-1]
		// Если адрес зарезервирован, пропускаем (но такого быть не должно)
		if !a.isReserved(addr) {
			return u32ToIP(addr), nil
		}
		// если зарезервирован, просто продолжаем искать в freed
	}

	// Если freed пуст или все адреса в freed зарезервированы, выдаём новый
	for a.next <= a.end {
		if !a.isReserved(a.next) {
			addr = a.next
			a.next++
			return u32ToIP(addr), nil
		}
		a.next++
	}

	return nil, errors.New("no free IP addresses")
}

// Free освобождает ранее выданный IP-адрес, делая его доступным для повторного использования.
// Возвращает ошибку, если адрес вне допустимого диапазона, уже свободен или зарезервирован.
func (a *IPAllocator) Free(ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	addr := ipToU32(ip)
	if addr < a.start || addr > a.end {
		return errors.New("address out of range")
	}

	// Проверяем, не зарезервирован ли
	if a.isReserved(addr) {
		return errors.New("address is reserved, cannot free")
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
