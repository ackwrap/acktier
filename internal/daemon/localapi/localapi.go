package localapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/acktier/acktier/internal/daemon/engine"
)

const DefaultAddr = "127.0.0.1:41920"

// Server exposes local daemon management endpoints to the `acktier` CLI and desktop GUI.
type Server struct {
	eng *engine.Engine
}

func NewServer(eng *engine.Engine) *Server {
	return &Server{eng: eng}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /local/v1/status", s.handleStatus)
	mux.HandleFunc("GET /local/v1/mesh", s.handleMesh)
	mux.HandleFunc("GET /local/v1/netcheck", s.handleNetCheck)
	mux.HandleFunc("GET /local/v1/dns", s.handleDNSLookup)
	mux.HandleFunc("POST /local/v1/exit-node", s.handleSetExitNode)
	mux.HandleFunc("POST /local/v1/network-change", s.handleNetworkChange)
	mux.HandleFunc("POST /local/v1/up", s.handleUp)
	mux.HandleFunc("POST /local/v1/down", s.handleDown)
	mux.HandleFunc("POST /local/v1/ping", s.handlePing)
	return mux
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.eng.Status())
}

func (s *Server) handleMesh(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.eng.MeshStatus())
}

func (s *Server) handleDNSLookup(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	v4, v6, fqdn, ok := s.eng.LookupDNS(name)
	if !ok {
		writeError(w, http.StatusNotFound, "host not found in MagicDNS")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"fqdn": fqdn,
		"ipv4": v4,
		"ipv6": v6,
	})
}

func (s *Server) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExitNode string `json:"exitNode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.eng.SetExitNode(req.ExitNode); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"exitNode": req.ExitNode})
}

func (s *Server) handleNetworkChange(w http.ResponseWriter, r *http.Request) {
	s.eng.NotifyNetworkChange()
	writeJSON(w, http.StatusOK, map[string]bool{"roamingTriggered": true})
}

func (s *Server) handleNetCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.eng.NetCheck(ctx))
}

func (s *Server) handleUp(w http.ResponseWriter, r *http.Request) {
	var req engine.UpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	nm, err := s.eng.Up(ctx, req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nm)
}

func (s *Server) handleDown(w http.ResponseWriter, r *http.Request) {
	s.eng.Down()
	writeJSON(w, http.StatusOK, map[string]any{"state": "Stopped"})
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target    string `json:"target"`
		TimeoutMs int    `json:"timeoutMs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}
	timeout := 3 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	res, err := s.eng.PingPeer(ctx, req.Target)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
