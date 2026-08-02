package http

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/TexHik620953/liberator-node-go/pkg/model"
)

type Router interface {
	GetStats() model.RouterStats
}

type RouterHandler struct {
	router Router
}

func RegisterRouterService(mux *http.ServeMux, router Router) {
	sh := &RouterHandler{
		router: router,
	}

	mux.HandleFunc("/router/stats", sh.handleStats)
}

func (sh *RouterHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	stats := sh.router.GetStats()

	if err := json.NewEncoder(w).Encode(stats); err != nil {
		log.Printf("router handleStats failed to encode json: %v", err)
	}
}
