package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/acktier/acktier/internal/secfile"
	"github.com/acktier/acktier/pkg/types"
)

// NormalizeServerOrigin canonicalizes a Control Server URL into "scheme://host[:port]"
// so NodeTokens are strictly isolated per control-plane origin and never leaked across servers.
func NormalizeServerOrigin(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.ToLower(strings.TrimRight(rawURL, "/"))
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return scheme + "://[" + host + "]"
	}
	return scheme + "://" + host
}

func generateLocalAPIToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "lapi_" + hex.EncodeToString(b)
}

// ConfigState persists daemon identity keys and per-origin control server credentials on disk.
type ConfigState struct {
	MachineKey       types.PrivateKey  `json:"machineKey"`
	NodeKey          types.PrivateKey  `json:"nodeKey"`
	LocalAPIToken    string            `json:"localApiToken,omitempty"`
	ServerURL        string            `json:"serverUrl,omitempty"`
	NodeTokens       map[string]string `json:"nodeTokens,omitempty"` // Normalized origin -> NodeToken
	LegacyNodeToken  string            `json:"nodeToken,omitempty"`  // Migrated into NodeTokens[Origin(ServerURL)] and cleared
	Hostname         string            `json:"hostname,omitempty"`
	AdvertisedRoutes []netip.Prefix    `json:"advertisedRoutes,omitempty"`
	ExitNode         string            `json:"exitNode,omitempty"`
	RelayMode        types.RelayMode   `json:"relayMode,omitempty"` // "auto" (default) | "on" | "off"
	MaxRelayMbps     float64           `json:"maxRelayMbps,omitempty"`
	CanRelay         bool              `json:"canRelay,omitempty"`
	WantRunning      bool              `json:"wantRunning,omitempty"`
}

type Manager struct {
	mu    sync.RWMutex
	path  string
	state ConfigState
}

func LoadOrCreate(path string) (*Manager, error) {
	m := &Manager{path: path}
	if path != "" {
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, &m.state); err != nil {
				return nil, err
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	dirty := false
	if m.state.NodeTokens == nil {
		m.state.NodeTokens = make(map[string]string)
	}
	if m.state.LegacyNodeToken != "" {
		if origin := NormalizeServerOrigin(m.state.ServerURL); origin != "" {
			m.state.NodeTokens[origin] = m.state.LegacyNodeToken
		}
		m.state.LegacyNodeToken = ""
		dirty = true
	}
	if m.state.MachineKey.IsZero() {
		mk, err := types.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		m.state.MachineKey = mk
		dirty = true
	}
	if m.state.NodeKey.IsZero() {
		nk, err := types.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		m.state.NodeKey = nk
		dirty = true
	}
	if m.state.LocalAPIToken == "" {
		m.state.LocalAPIToken = generateLocalAPIToken()
		dirty = true
	}
	if m.state.Hostname == "" {
		h, _ := os.Hostname()
		if h == "" {
			h = "acktier-node"
		}
		m.state.Hostname = h
		dirty = true
	}
	if dirty {
		if err := m.saveLocked(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Manager) Get() ConfigState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := m.state
	cp.AdvertisedRoutes = append([]netip.Prefix(nil), m.state.AdvertisedRoutes...)
	if len(m.state.NodeTokens) > 0 {
		cp.NodeTokens = make(map[string]string, len(m.state.NodeTokens))
		for k, v := range m.state.NodeTokens {
			cp.NodeTokens[k] = v
		}
	}
	return cp
}

// TokenForServer retrieves the saved NodeToken strictly scoped to serverURL's normalized origin.
func (m *Manager) TokenForServer(serverURL string) string {
	origin := NormalizeServerOrigin(serverURL)
	if origin == "" {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.NodeTokens[origin]
}

func (m *Manager) Update(fn func(s *ConfigState)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.NodeTokens == nil {
		m.state.NodeTokens = make(map[string]string)
	}
	fn(&m.state)
	m.state.LegacyNodeToken = ""
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return secfile.WritePrivate(m.path, raw)
}
