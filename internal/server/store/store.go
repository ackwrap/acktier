package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ackwrap/acktier/pkg/types"
)

var (
	ErrNotFound       = errors.New("store: record not found")
	ErrInvalidAuthKey = errors.New("store: invalid, expired, or exhausted auth key")
	ErrNameConflict   = errors.New("store: node DNS name already assigned to another node")
	ErrNodeAuth       = errors.New("store: valid node token required")
	ErrKeyConflict    = errors.New("store: key is already assigned or has been retired")
	ErrKeyRequired    = errors.New("store: recovery requires a new node key")
)

var reservedDNSLabels = map[string]bool{
	"localhost": true,
	"wpad":      true,
	"isatap":    true,
	"acktier":   true,
	"magicdns":  true,
}

// StoredNode carries coordination state. NodeToken is returned on registration
// or rekey, never serialized by the store.
type StoredNode struct {
	Node      types.PeerNode `json:"node"`
	NodeToken string         `json:"-"`
	TokenHash string         `json:"nodeTokenHash"`
}

type storedAuthKey struct {
	types.PreAuthKey
	KeyHash string `json:"keyHash"`
}

type snapshot struct {
	NextNodeID  types.NodeID
	Nodes       map[types.NodeID]StoredNode
	PreAuthKeys map[string]storedAuthKey
	RetiredKeys map[string]bool
	ACLPolicy   types.ACLPolicy
	FilterRules []types.FilterRule
	DNS         types.DNSConfig
	Owner       *storedOwner

	AdminPassword *PasswordHash
	Delegation    *ControllerDelegation
	Drafts        map[string]Draft
	Publications  []PublicationRecord
	Audit         []AuditEntry
	Inventory     map[string]Inventory
}

// FileStore coordinates mutations under one lock and persists them to SQLite
// when a database is configured.
type FileStore struct {
	mu     sync.RWMutex
	data   snapshot
	owner  ownerPublication
	sqlite *sqliteState
}

func emptySnapshot() snapshot {
	return snapshot{
		NextNodeID:  1,
		Nodes:       make(map[types.NodeID]StoredNode),
		PreAuthKeys: make(map[string]storedAuthKey),
		RetiredKeys: make(map[string]bool),
		DNS: types.DNSConfig{
			EnableMagicDNS: true,
			MagicDNSSuffix: "ack.internal",
		},
	}
}

// NewFileStore opens or creates an SQLite database. An empty path selects an
// in-memory store for tests and temporary runs.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return &FileStore{data: emptySnapshot()}, nil
	}
	return openSQLite(path, false)
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

func (s *FileStore) allocateUniqueNameLocked(desiredHostname string, nodeID types.NodeID) string {
	base := SanitizeDNSLabel(desiredHostname, nodeID)
	candidate := base
	for suffix := 2; ; suffix++ {
		if !s.isNameTakenLocked(candidate, nodeID) {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
}

func (s *FileStore) saveLocked(change stateChange) error {
	if s.sqlite != nil {
		return s.sqlite.save(&s.data, change)
	}
	return nil
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

// RegisterNode checks key ownership, authorizes the registration and saves the
// new state in one transaction. An enrollment key never updates an existing node.
func (s *FileStore) RegisterNode(req types.RegisterRequest, token string,
	allocate func() (netip.Addr, netip.Addr, error), release func(netip.Addr),
) (sn StoredNode, oldKey types.PublicKey, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.findByMachineKeyLocked(req.MachineKey)
	if exists && !matchesCredential(existing.TokenHash, token) {
		return sn, oldKey, ErrNodeAuth
	}
	if exists && existing.Node.KeyRevoked && existing.Node.NodeKey == req.NodeKey {
		return sn, oldKey, ErrKeyRequired
	}
	if s.keyUnavailableLocked(req.NodeKey, existing.Node.ID) {
		return sn, oldKey, ErrKeyConflict
	}
	sn = existing
	var change stateChange
	var audit []AuditEntry
	if !exists {
		pak, keyErr := s.findPreAuthKeyLocked(req.AuthKey)
		if keyErr != nil {
			return StoredNode{}, oldKey, keyErr
		}
		v4, v6, allocErr := allocate()
		if allocErr != nil {
			return StoredNode{}, oldKey, allocErr
		}
		id := s.data.NextNodeID
		if id == 0 || id == ^types.NodeID(0) {
			release(v4)
			return StoredNode{}, oldKey, errors.New("store: node ID space exhausted")
		}
		s.data.NextNodeID++
		token = GenerateNodeToken()
		sn = StoredNode{
			TokenHash: hashCredential(token),
			Node: types.PeerNode{
				ID: id, Name: s.allocateUniqueNameLocked(req.Hostname, id),
				MachineKey: req.MachineKey, IPv4: v4, IPv6: v6, Tags: pak.Tags,
				CreatedAt: time.Now().UTC(),
			},
		}
		used := pak
		used.UsedCount++
		s.data.PreAuthKeys[pak.ID] = used
		change.nextID, change.key = true, pak.ID
		if s.data.Owner != nil {
			audit = []AuditEntry{{Actor: "node", Action: "node.register", Target: req.NodeKey.String(), Result: "success", Detail: pak.ID}}
		}
		defer func() {
			if err != nil {
				s.data.NextNodeID = id
				s.data.PreAuthKeys[pak.ID] = pak
				release(v4)
			}
		}()
	}
	if sn.Node.NodeKey != req.NodeKey {
		oldKey = sn.Node.NodeKey
	}
	sn.Node.NodeKey = req.NodeKey
	sn.Node.KeyRevoked = false
	if req.Hostname != "" {
		sn.Node.Hostname = req.Hostname
	}
	if req.OS != "" {
		sn.Node.OS = req.OS
	}
	if req.TransportPorts != nil {
		sn.Node.TransportPorts = req.TransportPorts
	}
	sn.Node.Endpoints = req.Endpoints
	if req.AdvertisedRoutes != nil {
		sn.Node.AdvertisedRoutes = req.AdvertisedRoutes
	}
	sn.Node.CanRelay = req.CanRelay
	sn.Node.PreferredRelayID = req.PreferredRelayID
	sn.Node.Online = true
	sn.Node.LastSeen = time.Now().UTC()
	err = s.saveNodeChangeLocked(sn, oldKey, change, audit...)
	if err == nil {
		sn.NodeToken = token
	}
	return sn, oldKey, err
}

func hashCredential(secret string) string {
	digest := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(digest[:])
}

func matchesCredential(want, provided string) bool {
	return provided != "" && subtle.ConstantTimeCompare([]byte(want), []byte(hashCredential(provided))) == 1
}

func (s *FileStore) AuthenticateNode(key types.PublicKey, token string) (StoredNode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authenticateNodeLocked(key, token)
}

func (s *FileStore) authenticateNodeLocked(key types.PublicKey, token string) (StoredNode, bool) {
	sn, ok := s.findByNodeKeyLocked(key)
	return sn, ok && !key.IsZero() && !sn.Node.KeyRevoked && matchesCredential(sn.TokenHash, token)
}

// UpdateAuthenticatedNode authorizes against the current record under the same
// lock as the update. A concurrent deletion or rotation cannot be rolled back.
// The callback updates metadata only and returns whether it changed the record.
func (s *FileStore) UpdateAuthenticatedNode(key types.PublicKey, token string, update func(*types.PeerNode) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn, ok := s.authenticateNodeLocked(key, token)
	if !ok {
		return ErrNodeAuth
	}
	if !update(&sn.Node) {
		return nil
	}
	return s.saveNodeLocked(sn, types.PublicKey{})
}

// RekeyNode always retires the old data-plane key. Without a replacement the
// node stays out of topology until it registers a different key with the new token.
func (s *FileStore) RekeyNode(id types.NodeID, machineKey, nodeKey types.PublicKey) (StoredNode, types.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn, ok := s.data.Nodes[id]
	if !ok {
		return StoredNode{}, types.PublicKey{}, ErrNotFound
	}
	oldKey := sn.Node.NodeKey
	if !nodeKey.IsZero() && (nodeKey == oldKey || s.keyUnavailableLocked(nodeKey, id)) {
		return StoredNode{}, oldKey, ErrKeyConflict
	}
	if !machineKey.IsZero() {
		if other, ok := s.findByMachineKeyLocked(machineKey); ok && other.Node.ID != id {
			return StoredNode{}, oldKey, ErrKeyConflict
		}
		sn.Node.MachineKey = machineKey
	}
	sn.Node.KeyRevoked = nodeKey.IsZero()
	if !sn.Node.KeyRevoked {
		sn.Node.NodeKey = nodeKey
	}
	sn.Node.Online = false
	sn.Node.Links = nil
	sn.Node.Endpoints = nil
	token := GenerateNodeToken()
	sn.TokenHash = hashCredential(token)
	if err := s.saveNodeLocked(sn, oldKey); err != nil {
		return sn, oldKey, err
	}
	sn.NodeToken = token
	return sn, oldKey, nil
}

func (s *FileStore) keyUnavailableLocked(key types.PublicKey, except types.NodeID) bool {
	if s.data.RetiredKeys[key.String()] {
		return true
	}
	other, found := s.findByNodeKeyLocked(key)
	return found && other.Node.ID != except
}

func (s *FileStore) saveNodeLocked(sn StoredNode, retire types.PublicKey) error {
	return s.saveNodeChangeLocked(sn, retire, stateChange{})
}

func (s *FileStore) saveNodeChangeLocked(sn StoredNode, retire types.PublicKey, change stateChange, audit ...AuditEntry) error {
	id := sn.Node.ID
	change.node = id
	prev, existed := s.data.Nodes[id]
	s.data.Nodes[id] = sn
	retiredKey := retire.String()
	alreadyRetired := s.data.RetiredKeys[retiredKey]
	if !retire.IsZero() {
		s.data.RetiredKeys[retiredKey] = true
		change.retiredKey = retiredKey
	}
	if err := s.commitLocked(change, audit...); err != nil {
		if existed {
			s.data.Nodes[id] = prev
		} else {
			delete(s.data.Nodes, id)
		}
		if !alreadyRetired && !retire.IsZero() {
			delete(s.data.RetiredKeys, retiredKey)
		}
		return err
	}
	return nil
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
	return sn, s.saveNodeLocked(sn, types.PublicKey{})
}

func (s *FileStore) SetApprovedRoutes(id types.NodeID, routes []netip.Prefix) (StoredNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn, ok := s.data.Nodes[id]
	if !ok {
		return StoredNode{}, ErrNotFound
	}
	sn.Node.ApprovedRoutes = routes
	return sn, s.saveNodeLocked(sn, types.PublicKey{})
}

func (s *FileStore) findByMachineKeyLocked(mk types.PublicKey) (StoredNode, bool) {
	for _, sn := range s.data.Nodes {
		if sn.Node.MachineKey == mk {
			return sn, true
		}
	}
	return StoredNode{}, false
}

func (s *FileStore) findByNodeKeyLocked(nk types.PublicKey) (StoredNode, bool) {
	for _, sn := range s.data.Nodes {
		if sn.Node.NodeKey == nk {
			return sn, true
		}
	}
	return StoredNode{}, false
}

func (s *FileStore) ListNodes() []StoredNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listNodesLocked()
}

// TopologySnapshot reads membership and policy together so a map cannot mix
// nodes from before an update with ACL selectors from after it.
func (s *FileStore) TopologySnapshot() ([]StoredNode, types.DNSConfig, []types.FilterRule, types.ACLPolicy) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listNodesLocked(), s.data.DNS, s.data.FilterRules, s.data.ACLPolicy
}

func (s *FileStore) listNodesLocked() []StoredNode {
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
	retiredKey := sn.Node.NodeKey.String()
	alreadyRetired := s.data.RetiredKeys[retiredKey]
	s.data.RetiredKeys[retiredKey] = true
	if err := s.saveLocked(stateChange{node: id, retiredKey: retiredKey}); err != nil {
		s.data.Nodes[id] = sn
		if !alreadyRetired {
			delete(s.data.RetiredKeys, retiredKey)
		}
		return StoredNode{}, err
	}
	return sn, nil
}

func (s *FileStore) CreatePreAuthKey(label string, reusable, ephemeral bool, tags []string, ttl time.Duration, audit ...AuditEntry) (types.PreAuthKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	pak := types.PreAuthKey{
		Key:       "ackkey-" + randomHex(20),
		Label:     label,
		Reusable:  reusable,
		Ephemeral: ephemeral,
		Tags:      tags,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	for {
		pak.ID = "key_" + randomHex(6)
		if _, exists := s.data.PreAuthKeys[pak.ID]; !exists {
			break
		}
	}
	record := storedAuthKey{PreAuthKey: pak, KeyHash: hashCredential(pak.Key)}
	record.Key = ""
	s.data.PreAuthKeys[pak.ID] = record
	for i := range audit {
		audit[i].Target = pak.ID
	}
	if err := s.commitLocked(stateChange{key: pak.ID}, audit...); err != nil {
		delete(s.data.PreAuthKeys, pak.ID)
		return types.PreAuthKey{}, err
	}
	return pak, nil
}

func (s *FileStore) findPreAuthKeyLocked(rawKey string) (storedAuthKey, error) {
	if rawKey == "" {
		return storedAuthKey{}, ErrInvalidAuthKey
	}
	digest := []byte(hashCredential(rawKey))
	now := time.Now().UTC()
	for _, pak := range s.data.PreAuthKeys {
		if subtle.ConstantTimeCompare([]byte(pak.KeyHash), digest) != 1 {
			continue
		}
		if pak.Revoked || !now.Before(pak.ExpiresAt) {
			return storedAuthKey{}, ErrInvalidAuthKey
		}
		if !pak.Reusable && pak.UsedCount > 0 {
			return storedAuthKey{}, ErrInvalidAuthKey
		}
		return pak, nil
	}
	return storedAuthKey{}, ErrInvalidAuthKey
}

func (s *FileStore) ListPreAuthKeys() []types.PreAuthKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.PreAuthKey, 0, len(s.data.PreAuthKeys))
	for _, k := range s.data.PreAuthKeys {
		out = append(out, k.PreAuthKey)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *FileStore) RevokePreAuthKey(id string, audit ...AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pak, ok := s.data.PreAuthKeys[id]
	if !ok {
		return ErrNotFound
	}
	next := pak
	next.Revoked = true
	s.data.PreAuthKeys[id] = next
	if err := s.commitLocked(stateChange{key: id}, audit...); err != nil {
		s.data.PreAuthKeys[id] = pak
		return err
	}
	return nil
}

func (s *FileStore) GetACLPolicy() types.ACLPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.ACLPolicy
}

func (s *FileStore) SetACLPolicy(pol types.ACLPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.data.ACLPolicy
	s.data.ACLPolicy = pol
	if err := s.saveLocked(stateChange{unsignedPolicy: true}); err != nil {
		s.data.ACLPolicy = prev
		return err
	}
	return nil
}

func (s *FileStore) SetDNSConfig(dnsCfg types.DNSConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.data.DNS
	s.data.DNS = dnsCfg
	if err := s.saveLocked(stateChange{unsignedPolicy: true}); err != nil {
		s.data.DNS = prev
		return err
	}
	return nil
}
