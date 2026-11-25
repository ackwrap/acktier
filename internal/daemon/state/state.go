package state

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/acktier/acktier/pkg/types"
)

// ConfigState persists daemon identity keys and control server credentials on disk.
type ConfigState struct {
	MachineKey       types.PrivateKey `json:"machineKey"`
	NodeKey          types.PrivateKey `json:"nodeKey"`
	ServerURL        string           `json:"serverUrl,omitempty"`
	NodeToken        string           `json:"nodeToken,omitempty"`
	Hostname         string           `json:"hostname,omitempty"`
	AdvertisedRoutes []netip.Prefix   `json:"advertisedRoutes,omitempty"`
	ExitNode         string           `json:"exitNode,omitempty"`
	RelayMode        types.RelayMode  `json:"relayMode,omitempty"` // "auto" (default) | "on" | "off"
	MaxRelayMbps     float64          `json:"maxRelayMbps,omitempty"`
	CanRelay         bool             `json:"canRelay,omitempty"`
	WantRunning      bool             `json:"wantRunning,omitempty"`
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
	return cp
}

func (m *Manager) Update(fn func(s *ConfigState)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(&m.state)
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}
