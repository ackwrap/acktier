package localapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acktier/acktier/internal/daemon/engine"
	"github.com/acktier/acktier/internal/secfile"
)

const (
	DefaultAddr     = "127.0.0.1:41920"
	maxLocalAPIBody = 64 * 1024
)

func generateFallbackToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "lapi_" + hex.EncodeToString(b)
}

// TokenFilePathForAddr computes the deterministic owner-only LocalAPI token file path for a given listen addr or URL.
func TokenFilePathForAddr(addrOrURL string) string {
	raw := strings.TrimSpace(addrOrURL)
	if raw == "" {
		raw = DefaultAddr
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		port = "41920"
		host = "127.0.0.1"
	}
	if host == "" || strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	safeHost := strings.NewReplacer(":", "_", ".", "_", "[", "", "]", "").Replace(host)
	baseDir, err := os.UserConfigDir()
	if err != nil || baseDir == "" {
		baseDir = os.TempDir()
	}
	return filepath.Join(baseDir, "acktier", fmt.Sprintf("localapi-%s-%s.token", safeHost, port))
}

// WriteTokenFile persists the LocalAPI bearer token with strict owner-only OS permissions (0600 / Protected Windows DACL).
func WriteTokenFile(listenAddr, token string) (string, error) {
	p := TokenFilePathForAddr(listenAddr)
	if err := secfile.WritePrivate(p, []byte(strings.TrimSpace(token)+"\n")); err != nil {
		return "", err
	}
	return p, nil
}

// ReadTokenFile loads the LocalAPI bearer token for targetAddrOrURL if accessible to the current OS user.
func ReadTokenFile(targetAddrOrURL string) string {
	if envTok := strings.TrimSpace(os.Getenv("ACKTIER_LOCAL_TOKEN")); envTok != "" {
		return envTok
	}
	p := TokenFilePathForAddr(targetAddrOrURL)
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// Server exposes authenticated local daemon management endpoints to the `acktier` CLI and desktop GUI.
type Server struct {
	eng   *engine.Engine
	token string
}

func NewServer(eng *engine.Engine, authToken string) *Server {
	tok := strings.TrimSpace(authToken)
	if tok == "" {
		tok = eng.LocalAPIToken()
	}
	if tok == "" {
		tok = generateFallbackToken()
	}
	return &Server{
		eng:   eng,
		token: tok,
	}
}

func (s *Server) Token() string {
	return s.token
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /local/v1/status", s.requireLocalAuth(s.handleStatus))
	mux.HandleFunc("GET /local/v1/mesh", s.requireLocalAuth(s.handleMesh))
	mux.HandleFunc("GET /local/v1/netcheck", s.requireLocalAuth(s.handleNetCheck))
	mux.HandleFunc("GET /local/v1/dns", s.requireLocalAuth(s.handleDNSLookup))
	mux.HandleFunc("POST /local/v1/exit-node", s.requireLocalAuth(s.handleSetExitNode))
	mux.HandleFunc("POST /local/v1/network-change", s.requireLocalAuth(s.handleNetworkChange))
	mux.HandleFunc("POST /local/v1/up", s.requireLocalAuth(s.handleUp))
	mux.HandleFunc("POST /local/v1/down", s.requireLocalAuth(s.handleDown))
	mux.HandleFunc("POST /local/v1/ping", s.requireLocalAuth(s.handlePing))
	return mux
}

func (s *Server) requireLocalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Block browser cross-origin / CSRF / DNS-rebinding requests unconditionally.
		if r.Header.Get("Origin") != "" {
			writeError(w, http.StatusForbidden, "cross-origin browser requests are forbidden on LocalAPI")
			return
		}
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && !strings.EqualFold(sfs, "none") {
			writeError(w, http.StatusForbidden, "browser fetch requests are forbidden on LocalAPI")
			return
		}

		provided := strings.TrimSpace(r.Header.Get("X-AckTier-Local-Token"))
		if provided == "" {
			hdr := r.Header.Get("Authorization")
			if len(hdr) >= 7 && strings.EqualFold(hdr[:7], "Bearer ") {
				provided = strings.TrimSpace(hdr[7:])
			}
		}
		if provided == "" || len(provided) != len(s.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid LocalAPI bearer token")
			return
		}
		next(w, r)
	}
}

func decodeLocalJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxLocalAPIBody)
	return json.NewDecoder(r.Body).Decode(dst)
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
	if err := decodeLocalJSON(w, r, &req); err != nil {
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
	if err := decodeLocalJSON(w, r, &req); err != nil {
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
	if err := decodeLocalJSON(w, r, &req); err != nil || req.Target == "" {
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
