package http

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/TexHik620953/liberator-node-go/pkg/model"
)

type MeshNode interface {
	GetConnectivity() []model.ConnectivityState
}

type MeshHandler struct {
	node MeshNode
}

func RegisterMeshNodeService(mux *http.ServeMux, node MeshNode) {
	sh := &MeshHandler{
		node: node,
	}

	mux.HandleFunc("/mesh/connectivity", sh.handleConnectivity)
}

func (sh *MeshHandler) handleConnectivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	connectivity := sh.node.GetConnectivity()

	if err := json.NewEncoder(w).Encode(connectivity); err != nil {
		log.Printf("mesh handleConnectivity failed to encode json: %v", err)
	}
}
