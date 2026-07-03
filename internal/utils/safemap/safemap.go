package safemap

import (
	"maps"
	"sync"
)

// Thread safe map
type Safemap[K comparable, V any] interface {
	Get(key K) (V, bool)
	Set(key K, val V)
	Exists(key K) bool
	Foreach(it func(K, V))
	ForeachCond(it func(K, V) bool)
	Delete(key K)
	Count() int
	Clone() Safemap[K, V]
	CloneRaw() map[K]V
}

type safemapImpl[K comparable, V any] struct {
	data  map[K]V
	mutex sync.RWMutex
}

func From[K comparable, V any](m map[K]V) Safemap[K, V] {
	r := &safemapImpl[K, V]{
		data:  make(map[K]V),
		mutex: sync.RWMutex{},
	}
	r.data = maps.Clone(m)
	return r
}

// Thread safe map
func New[K comparable, V any]() Safemap[K, V] {
	return &safemapImpl[K, V]{
		data:  make(map[K]V),
		mutex: sync.RWMutex{},
	}
}

func (h *safemapImpl[K, V]) Get(key K) (V, bool) {
	h.mutex.RLock()
	v, ex := h.data[key]
	h.mutex.RUnlock()
	return v, ex
}

func (h *safemapImpl[K, V]) Set(key K, val V) {
	h.mutex.Lock()
	h.data[key] = val
	h.mutex.Unlock()
}

func (h *safemapImpl[K, V]) Exists(key K) bool {
	h.mutex.Lock()
	_, ex := h.data[key]
	h.mutex.Unlock()
	return ex
}

func (h *safemapImpl[K, V]) ForeachCond(it func(K, V) bool) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	for k, v := range h.data {
		if !it(k, v) {
			break
		}
	}
}
func (h *safemapImpl[K, V]) Foreach(it func(K, V)) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	for k, v := range h.data {
		it(k, v)
	}
}
func (h *safemapImpl[K, V]) Delete(key K) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	delete(h.data, key)
}

func (h *safemapImpl[K, V]) Count() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return len(h.data)
}

func (h *safemapImpl[K, V]) Clone() Safemap[K, V] {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	r := &safemapImpl[K, V]{
		data: maps.Clone(h.data),
	}
	return r
}

func (h *safemapImpl[K, V]) CloneRaw() map[K]V {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	return maps.Clone(h.data)
}
