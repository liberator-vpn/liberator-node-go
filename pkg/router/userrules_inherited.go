package router

// Методы управления правилами интернет-выхода (данные живут в userRules —
// отдельном типе, см. pkg/userrules). Вынесены в этот файл по аналогии с
// firewall_inherited.go / routingtable_inherited.go.

// ClearEgressRules сбрасывает все правила выхода (реконсилится за цикл).
func (r *Router) ClearEgressRules() {
	r.userRules.Clear()
}

// SetEgressRule добавляет клиенту правило выхода для префикса (CIDR).
func (r *Router) SetEgressRule(clientIP uint32, prefixCIDR, exit string) error {
	return r.userRules.Set(clientIP, prefixCIDR, exit)
}
