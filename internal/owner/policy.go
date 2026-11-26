package owner

import (
	"fmt"
	"time"

	"github.com/ackwrap/acktier/internal/server/acl"
	"github.com/ackwrap/acktier/pkg/types"
)

// Policy is the human-maintained authorization source that the owner reviews
// and signs locally. The center may store and validate drafts of it, but the
// signed Snapshot is produced only by the owner's CLI.
type Policy struct {
	Members     []Member        `json:"members"`
	ACL         types.ACLPolicy `json:"acl"`
	DNS         types.DNSConfig `json:"dns"`
	STUNAddr    string          `json:"stunAddr,omitempty"`
	STUNAltAddr string          `json:"stunAltAddr,omitempty"`
}

// Peers returns the authorized identities used to resolve ACL selectors.
func (p Policy) Peers() []types.PeerNode {
	nodes := make([]types.PeerNode, 0, len(p.Members))
	for _, m := range p.Members {
		nodes = append(nodes, m.Peer())
	}
	return nodes
}

// Rules validates the ACL and compiles the network-wide packet filter. An
// empty ACL compiles to an explicit deny-all rule.
func (p Policy) Rules() ([]types.FilterRule, error) {
	if err := acl.Validate(p.ACL); err != nil {
		return nil, fmt.Errorf("invalid ACL: %w", err)
	}
	rules := acl.CompileForNode(p.ACL, types.PeerNode{}, p.Peers())
	if len(rules) == 0 {
		rules = []types.FilterRule{DenyAll()}
	}
	return rules, nil
}

// Snapshot builds the payload that the owner would sign. NetworkID is filled
// in by Sign from the signing key.
func (p Policy) Snapshot(version uint64, expiresAt time.Time) (Snapshot, error) {
	rules, err := p.Rules()
	if err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{
		Version: version, ExpiresAt: expiresAt, Members: p.Members,
		PacketFilter: rules, DNS: p.DNS, STUNAddr: p.STUNAddr, STUNAltAddr: p.STUNAltAddr,
	}
	return s, s.validate()
}

// Check reports whether the owner's CLI would accept this policy for signing.
func (p Policy) Check() error {
	_, err := p.Snapshot(1, time.Now().Add(time.Hour))
	return err
}
