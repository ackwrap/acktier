package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/acktier/acktier/internal/secfile"
	"github.com/acktier/acktier/pkg/types"
)

var (
	ErrNotFound       = errors.New("store: record not found")
	ErrInvalidAuthKey = errors.New("store: invalid, expired, or exhausted auth key")
	ErrNameConflict   = errors.New("store: node DNS name already assigned to another node")
)

var reservedDNSLabels = map[string]bool{
	"localhost": true,
	"wpad":      true,
	"isatap":    true,
	"acktier":   true,
	"magicdns":  true,
}

// StoredNode wraps PeerNode with server-side authentication secret token.
type StoredNode struct {
	Node      types.PeerNode `json:"node"`
	NodeToken string         `json:"nodeToken"`
}

type snapshot struct {
	NextNodeID  types.NodeID                `json:"nextNodeId"`
	Nodes       map[types.NodeID]StoredNode `json:"nodes"`
	PreAuthKeys map[string]types.PreAuthKey `json:"preAuthKeys"`
	ACLPolicy   types.ACLPolicy             `json:"aclPolicy"`
	FilterRules []types.FilterRule          `json:"filterRules,omitempty"`
	DNS         types.DNSConfig             `json:"dns"`
}

// FileStore provides concurrency-safe persistent storage backed by owner-only atomic JSON snapshots.
type FileStore struct {
	mu   sync.RWMutex
	path string
	data snapshot
}

func NewFileStore(path string) (*FileStore, error) {
	s := &FileStore{
		path: path,
		data: snapshot{
			NextNodeID:  1,
			Nodes:       make(map[types.NodeID]StoredNode),
			PreAuthKeys: make(map[string]types.PreAuthKey),
			DNS: types.DNSConfig{
				EnableMagicDNS: true,
				MagicDNSSuffix: "ack.internal",
			},
		},
	}
	if path == "" {
		return s, nil
	}
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("parse store file %s: %w", path, err)
		}
		if s.data.Nodes == nil {
			s.data.Nodes = make(map[types.NodeID]StoredNode)
		}
		if s.data.PreAuthKeys == nil {
			s.data.PreAuthKeys = make(map[string]types.PreAuthKey)
		}
		if s.data.NextNodeID < 1 {
			s.data.NextNodeID = 1
		}
		s.ensureUniqueNodeNamesLocked()
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// SanitizeDNSLabel converts an arbitrary hostname into a valid RFC 1123 lowercase DNS label.
func SanitizeDNSLabel(hostname string, fallbackID types.NodeID) string {
	name := strings.ToLower(strings.TrimSpace(hostname))
	var b strings.Builder
	prevDash := false
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			b.WriteRune(ch)
			prevDash = false
		} else if (ch == '-' || ch == '_' || ch == ' ' || ch == '.') && !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
		if b.Len() >= 50 {
			break
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" || reservedDNSLabels[res] {
		return fmt.Sprintf("node-%d", fallbackID)
	}
	return res
}

func (s *FileStore) ensureUniqueNodeNamesLocked() {
	ids := make([]types.NodeID, 0, len(s.data.Nodes))
	for id := range s.data.Nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	used := make(map[string]types.NodeID, len(ids))
	for _, id := range ids {
		sn := s.data.Nodes[id]
		base := SanitizeDNSLabel(sn.Node.Name, id)
		candidate := base
		for suffix := 2; ; suffix++ {
			if owner, taken := used[candidate]; !taken || owner == id {
				break
			}
			candidate = fmt.Sprintf("%s-%d", base, suffix)
		}
		sn.Node.Name = candidate
		used[candidate] = id
		s.data.Nodes[id] = sn
	}
}

func (s *FileStore) isNameTakenLocked(name string, excludeID types.NodeID) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if reservedDNSLabels[name] {
		return true
	}
	for id, sn := range s.data.Nodes {
		if id != excludeID && strings.EqualFold(sn.Node.Name, name) {
			return true
		}
	}
	return false
}

// AllocateUniqueName assigns a globally unique server-managed DNS name for nodeID.
func (s *FileStore) AllocateUniqueName(desiredHostname string, nodeID types.NodeID) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	base := SanitizeDNSLabel(desiredHostname, nodeID)
	candidate := base
	for suffix := 2; ; suffix++ {
		if !s.isNameTakenLocked(candidate, nodeID) {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
}

func (s *FileStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return secfile.WritePrivate(s.path, raw)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateNodeToken creates a fresh 192-bit random bearer token for a registered node.
func GenerateNodeToken() string {
	return "ntok_" + randomHex(24)
}

func (s *FileStore) NextID() types.NodeID {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.data.NextNodeID
	s.data.NextNodeID++
	_ = s.saveLocked()
	return id
}

func (s *FileStore) UpsertNode(sn StoredNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sn.NodeToken == "" {
		sn.NodeToken = GenerateNodeToken()
	}
	base := SanitizeDNSLabel(sn.Node.Name, sn.Node.ID)
	if s.isNameTakenLocked(base, sn.Node.ID) {
		for suffix := 2; ; suffix++ {
			cand := fmt.Sprintf("%s-%d", base, suffix)
			if !s.isNameTakenLocked(cand, sn.Node.ID) {
				base = cand
				break
			}
		}
	}
	sn.Node.Name = base
	s.data.Nodes[sn.Node.ID] = sn
	return s.saveLocked()
}

// RenameNode allows an administrator to explicitly assign a unique DNS name to an existing node.
func (s *FileStore) RenameNode(id types.NodeID, newName string) (StoredNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn, ok := s.data.Nodes[id]
	if !ok {
		return StoredNode{}, ErrNotFound
	}
	clean := SanitizeDNSLabel(newName, id)
	if s.isNameTakenLocked(clean, id) {
		return StoredNode{}, ErrNameConflict
	}
	sn.Node.Name = clean
	s.data.Nodes[id] = sn
	return sn, s.saveLocked()
}

func (s *FileStore) FindByMachineKey(mk types.PublicKey) (StoredNode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sn := range s.data.Nodes {
		if sn.Node.MachineKey == mk {
			return sn, true
		}
	}
	return StoredNode{}, false
}

func (s *FileStore) FindByNodeKey(nk types.PublicKey) (StoredNode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sn := range s.data.Nodes {
		if sn.Node.NodeKey == nk {
			return sn, true
		}
	}
	return StoredNode{}, false
}

func (s *FileStore) GetNode(id types.NodeID) (StoredNode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sn, ok := s.data.Nodes[id]
	return sn, ok
}

func (s *FileStore) ListNodes() []StoredNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]StoredNode, 0, len(s.data.Nodes))
	for _, sn := range s.data.Nodes {
		out = append(out, sn)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Node.ID < out[j].Node.ID
	})
	return out
}

func (s *FileStore) DeleteNode(id types.NodeID) (StoredNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn, ok := s.data.Nodes[id]
	if !ok {
		return StoredNode{}, ErrNotFound
	}
	delete(s.data.Nodes, id)
	return sn, s.saveLocked()
}

func (s *FileStore) CreatePreAuthKey(label string, reusable, ephemeral bool, tags []string, ttl time.Duration) (types.PreAuthKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	pak := types.PreAuthKey{
		ID:        "key_" + randomHex(6),
		Key:       "ackkey-" + randomHex(20),
		Label:     label,
		Reusable:  reusable,
		Ephemeral: ephemeral,
		Tags:      tags,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	s.data.PreAuthKeys[pak.ID] = pak
	return pak, s.saveLocked()
}

func (s *FileStore) ConsumePreAuthKey(rawKey string) (types.PreAuthKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rawKey == "" {
		return types.PreAuthKey{}, ErrInvalidAuthKey
	}
	now := time.Now().UTC()
	for id, pak := range s.data.PreAuthKeys {
		if pak.Key != rawKey {
			continue
		}
		if pak.Revoked || now.After(pak.ExpiresAt) {
			return types.PreAuthKey{}, ErrInvalidAuthKey
		}
		if !pak.Reusable && pak.UsedCount > 0 {
			return types.PreAuthKey{}, ErrInvalidAuthKey
		}
		pak.UsedCount++
		s.data.PreAuthKeys[id] = pak
		_ = s.saveLocked()
		return pak, nil
	}
	return types.PreAuthKey{}, ErrInvalidAuthKey
}

func (s *FileStore) ListPreAuthKeys() []types.PreAuthKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.PreAuthKey, 0, len(s.data.PreAuthKeys))
	for _, k := range s.data.PreAuthKeys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *FileStore) RevokePreAuthKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pak, ok := s.data.PreAuthKeys[id]
	if !ok {
		return ErrNotFound
	}
	pak.Revoked = true
	s.data.PreAuthKeys[id] = pak
	return s.saveLocked()
}

func (s *FileStore) GetDNSAndFilters() (types.DNSConfig, []types.FilterRule) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]types.FilterRule, len(s.data.FilterRules))
	copy(rules, s.data.FilterRules)
	return s.data.DNS, rules
}

func (s *FileStore) GetACLPolicy() types.ACLPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.ACLPolicy
}

func (s *FileStore) SetACLPolicy(pol types.ACLPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.ACLPolicy = pol
	return s.saveLocked()
}

func (s *FileStore) SetDNSConfig(dnsCfg types.DNSConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.DNS = dnsCfg
	return s.saveLocked()
}
