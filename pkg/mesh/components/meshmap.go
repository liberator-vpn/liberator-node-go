package components

import (
	"sync"
	"time"
)

// RttRecord хранит данные об одном измерении задержки между двумя нодами
type RttRecord struct {
	// RTT в миллисекундах (можно использовать time.Duration)
	Rtt time.Duration
	// Время последнего успешного измерения (для определения устаревания)
	LastUpdate time.Time
	// Флаг: соединение прямое (true) или вычисленное через Флойда (false)
	IsDirect bool
	// Количество успешных измерений подряд (для стабильности)
	SuccessCount int
}

// RttMap хранит полную матрицу задержек между всеми нодами
type RttMap struct {
	// Хранилище: ключ "nodeA:nodeB" (всегда лексикографически отсортированный)
	store map[string]RttRecord
	mut   sync.RWMutex // RWMutex позволяет конкурентные чтения

	// Список всех известных нод (для быстрого перебора)
	nodes map[string]struct{}

	// Матрица смежности (кто с кем соединён напрямую)
	adjacency map[string]map[string]bool
}

// newRttMap создаёт новую карту задержек
func newRttMap() *RttMap {
	return &RttMap{
		store:     map[string]RttRecord{},
		nodes:     map[string]struct{}{},
		adjacency: map[string]map[string]bool{},
	}
}

// makeKey создаёт ключ для пары нод (всегда в одном порядке)
func makeKey(nodeA, nodeB string) string {
	if nodeA > nodeB {
		nodeA, nodeB = nodeB, nodeA
	}
	return nodeA + "|" + nodeB
}

// SetRtt сохраняет измеренное RTT между двумя нодами
func (r *RttMap) SetRtt(nodeA, nodeB string, rtt time.Duration) {
	if nodeA == nodeB {
		return // RTT до самого себя всегда 0
	}

	r.mut.Lock()
	defer r.mut.Unlock()

	// Добавляем ноды в список
	r.nodes[nodeA] = struct{}{}
	r.nodes[nodeB] = struct{}{}

	// Обновляем матрицу смежности
	if r.adjacency[nodeA] == nil {
		r.adjacency[nodeA] = make(map[string]bool)
	}
	if r.adjacency[nodeB] == nil {
		r.adjacency[nodeB] = make(map[string]bool)
	}
	r.adjacency[nodeA][nodeB] = true
	r.adjacency[nodeB][nodeA] = true

	// Сохраняем запись
	key := makeKey(nodeA, nodeB)
	record := r.store[key]
	record.Rtt = rtt
	record.LastUpdate = time.Now()
	record.IsDirect = true
	record.SuccessCount++
	r.store[key] = record
}

// GetRtt возвращает RTT между двумя нодами (включая вычисленные через Флойда)
func (r *RttMap) GetRtt(nodeA, nodeB string) (time.Duration, bool) {
	if nodeA == nodeB {
		return 0, true
	}

	r.mut.RLock()
	defer r.mut.RUnlock()

	key := makeKey(nodeA, nodeB)
	record, exists := r.store[key]
	if !exists {
		return 0, false
	}

	// Проверяем, не устарела ли запись (например, старше 30 секунд)
	if time.Since(record.LastUpdate) > 30*time.Second {
		return 0, false
	}

	return record.Rtt, true
}

// GetDirectNeighbors возвращает список нод, с которыми есть прямое соединение
func (r *RttMap) GetDirectNeighbors(node string) []string {
	r.mut.RLock()
	defer r.mut.RUnlock()

	neighbors := []string{}
	for neighbor, connected := range r.adjacency[node] {
		if connected {
			neighbors = append(neighbors, neighbor)
		}
	}
	return neighbors
}

// GetAllNodes возвращает список всех известных нод
func (r *RttMap) GetAllNodes() []string {
	r.mut.RLock()
	defer r.mut.RUnlock()

	nodes := make([]string, 0, len(r.nodes))
	for node := range r.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetFullMatrix возвращает копию всей матрицы (для отправки координатору)
func (r *RttMap) GetFullMatrix() map[string]time.Duration {
	r.mut.RLock()
	defer r.mut.RUnlock()

	matrix := make(map[string]time.Duration, len(r.store))
	for key, record := range r.store {
		// Отдаём только актуальные записи
		if time.Since(record.LastUpdate) <= 30*time.Second {
			matrix[key] = record.Rtt
		}
	}
	return matrix
}

// SetIndirectRtt сохраняет вычисленное (через Флойда) RTT
func (r *RttMap) SetIndirectRtt(nodeA, nodeB string, rtt time.Duration) {
	if nodeA == nodeB {
		return
	}

	r.mut.Lock()
	defer r.mut.Unlock()

	key := makeKey(nodeA, nodeB)
	record := r.store[key]

	// Обновляем только если нет прямого соединения или оно устарело
	if record.IsDirect && time.Since(record.LastUpdate) <= 30*time.Second {
		return // Не перезаписываем прямое измерение вычисленным
	}

	record.Rtt = rtt
	record.LastUpdate = time.Now()
	record.IsDirect = false
	record.SuccessCount = 0 // Сбрасываем счётчик для непрямых путей
	r.store[key] = record
}

// RemoveNode удаляет ноду из всех структур (при уходе из сети)
func (r *RttMap) RemoveNode(node string) {
	r.mut.Lock()
	defer r.mut.Unlock()

	// Удаляем из списка нод
	delete(r.nodes, node)

	// Удаляем все записи, связанные с этой нодой
	for key := range r.store {
		// Проверяем, содержит ли ключ эту ноду
		if containsNode(key, node) {
			delete(r.store, key)
		}
	}

	// Удаляем из матрицы смежности
	for neighbor := range r.adjacency[node] {
		delete(r.adjacency[neighbor], node)
	}
	delete(r.adjacency, node)
}

// containsNode проверяет, содержит ли ключ указанную ноду
func containsNode(key, node string) bool {
	// Ключ вида "nodeA|nodeB"
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			left := key[:i]
			right := key[i+1:]
			return left == node || right == node
		}
	}
	return false
}

// GetMatrixWithIndirect вычисляет и возвращает полную матрицу со всеми путями
// (реализация Флойда-Уоршелла)
func (r *RttMap) GetMatrixWithIndirect() map[string]time.Duration {
	r.mut.RLock()

	// Копируем все прямые измерения
	matrix := make(map[string]time.Duration)
	for key, record := range r.store {
		if time.Since(record.LastUpdate) <= 30*time.Second {
			matrix[key] = record.Rtt
		}
	}

	// Получаем список всех нод
	nodes := make([]string, 0, len(r.nodes))
	for node := range r.nodes {
		nodes = append(nodes, node)
	}
	r.mut.RUnlock()

	// Алгоритм Флойда-Уоршелла
	n := len(nodes)
	if n == 0 {
		return matrix
	}

	// Создаём индекс для быстрого доступа
	nodeIndex := make(map[string]int)
	for i, node := range nodes {
		nodeIndex[node] = i
	}

	// Инициализируем матрицу расстояний
	dist := make([][]time.Duration, n)
	for i := range dist {
		dist[i] = make([]time.Duration, n)
		for j := range dist[i] {
			if i == j {
				dist[i][j] = 0
			} else {
				dist[i][j] = time.Duration(1<<63 - 1) // INF
			}
		}
	}

	// Заполняем известными значениями
	for key, rtt := range matrix {
		var a, b string
		for i := 0; i < len(key); i++ {
			if key[i] == '|' {
				a = key[:i]
				b = key[i+1:]
				break
			}
		}
		if a != "" && b != "" {
			i, ok1 := nodeIndex[a]
			j, ok2 := nodeIndex[b]
			if ok1 && ok2 {
				dist[i][j] = rtt
				dist[j][i] = rtt
			}
		}
	}

	// Флойд-Уоршелл
	for k := 0; k < n; k++ {
		for i := 0; i < n; i++ {
			for j := 0; j < n; j++ {
				if dist[i][k]+dist[k][j] < dist[i][j] {
					dist[i][j] = dist[i][k] + dist[k][j]
				}
			}
		}
	}

	// Заполняем отсутствующие значения вычисленными
	result := make(map[string]time.Duration)
	for key, rtt := range matrix {
		result[key] = rtt // Сохраняем прямые измерения
	}

	// Добавляем вычисленные пути для пар, у которых нет прямого измерения
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			key := makeKey(nodes[i], nodes[j])
			if _, exists := matrix[key]; !exists && dist[i][j] < time.Duration(1<<63-1) {
				result[key] = dist[i][j]
			}
		}
	}

	return result
}
