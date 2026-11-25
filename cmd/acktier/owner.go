package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/secfile"
	"github.com/acktier/acktier/internal/server/acl"
	"github.com/acktier/acktier/pkg/types"
)

const (
	defaultOwnerDir = "./data/owner"
	signerFile      = "signer.json"
	trustFile       = "trust.json"
	publicationFile = "authorization.json"
)

type localSigner struct {
	Seed        []byte `json:"seed"`
	LastVersion uint64 `json:"lastVersion"`
}

type ownerPolicy struct {
	Members     []owner.Member  `json:"members"`
	ACL         types.ACLPolicy `json:"acl"`
	DNS         types.DNSConfig `json:"dns"`
	STUNAddr    string          `json:"stunAddr,omitempty"`
	STUNAltAddr string          `json:"stunAltAddr,omitempty"`
}

func runOwner(args []string) {
	if len(args) == 0 {
		fatalf("usage: acktier owner init|node-key|requests|sign|publish [flags]")
	}
	fs := flag.NewFlagSet("owner "+args[0], flag.ExitOnError)
	switch args[0] {
	case "init":
		dir := fs.String("dir", defaultOwnerDir, "New local owner directory (never copy the signer file to the center)")
		parseOwnerFlags(fs, args[1:])
		if err := initOwner(*dir); err != nil {
			fatalf("initialize owner: %v", err)
		}
		fmt.Printf("Owner initialized. Import %s in the center's /admin/ and provision it on nodes. Keep %s local.\n",
			filepath.Join(*dir, trustFile), filepath.Join(*dir, signerFile))
	case "node-key":
		path := fs.String("state", "./data/acktierd-state.json", "The local daemon's persistent state path")
		parseOwnerFlags(fs, args[1:])
		if *path == "" {
			fatalf("owner mode requires a persistent --state")
		}
		st, err := state.LoadOrCreate(*path)
		if err != nil {
			fatalf("load node identity: %v", err)
		}
		fmt.Println(st.Get().NodeKey.Public().String())
	case "sign":
		dir := fs.String("dir", defaultOwnerDir, "Local owner directory")
		policy := fs.String("policy", "", "Locally reviewed authorization draft JSON")
		ttl := fs.Duration("valid-for", 7*24*time.Hour, "How long the signed authorization remains valid")
		parseOwnerFlags(fs, args[1:])
		if *policy == "" || *ttl <= 0 {
			fatalf("--policy is required and --valid-for must be positive")
		}
		version, err := signOwner(*dir, *policy, *ttl)
		if err != nil {
			fatalf("sign authorization: %v", err)
		}
		fmt.Printf("Signed authorization v%d: %s\n", version, filepath.Join(*dir, publicationFile))
	case "requests", "publish":
		server := fs.String("server", "http://127.0.0.1:8080", "Control server URL")
		token := fs.String("admin-token", os.Getenv("ACKTIER_ADMIN_TOKEN"), "Coordination API bearer token")
		tlsCA := fs.String("tls-ca", os.Getenv("ACKTIER_TLS_CA"), "Optional TLS CA PEM file")
		var path *string
		if args[0] == "publish" {
			path = fs.String("file", defaultOwnerDir+"/"+publicationFile, "Previously signed authorization envelope")
		}
		parseOwnerFlags(fs, args[1:])
		ac := buildAdminClient(*server, *token, *tlsCA, false)
		ctx := context.Background()
		if path == nil {
			requests, err := ac.OwnerJoinRequests(ctx)
			if err != nil {
				fatalf("%v", err)
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(requests); err != nil {
				fatalf("write requests: %v", err)
			}
			return
		}
		var env types.OwnerAuthorization
		if err := owner.ReadJSON(*path, owner.MaxEnvelope, &env); err != nil {
			fatalf("read signed envelope: %v", err)
		}
		version, err := ac.PublishOwnerAuthorization(ctx, env)
		if err != nil {
			fatalf("%v", err)
		}
		fmt.Printf("Published owner authorization v%d.\n", version)
	default:
		fatalf("unknown owner subcommand %q", args[0])
	}
}

func parseOwnerFlags(fs *flag.FlagSet, args []string) {
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fatalf("unexpected arguments for %s", fs.Name())
	}
}

func initOwner(dir string) error {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err // Never replace a preexisting owner or key.
	}
	if err := writeOwnerFile(dir, signerFile, localSigner{Seed: key.Seed()}); err != nil {
		return err
	}
	return writeOwnerFile(dir, trustFile, owner.NewTrust(pub, 1))
}

func signOwner(dir, path string, ttl time.Duration) (uint64, error) {
	// A single signer directory must not issue two payloads at one version.
	lockPath := filepath.Join(dir, ".signing")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("acquire local signing lock: %w", err)
	}
	defer os.Remove(lockPath)
	if err := f.Close(); err != nil {
		return 0, err
	}
	var signer localSigner
	if err := owner.ReadJSON(filepath.Join(dir, signerFile), 4096, &signer); err != nil {
		return 0, err
	}
	version := signer.LastVersion + 1
	if len(signer.Seed) != ed25519.SeedSize || version == 0 {
		return 0, errors.New("invalid local signing state")
	}
	key := ed25519.NewKeyFromSeed(signer.Seed)
	var draft ownerPolicy
	if err := owner.ReadJSON(path, owner.MaxPayload, &draft); err != nil {
		return 0, err
	}
	if err := acl.Validate(draft.ACL); err != nil {
		return 0, fmt.Errorf("invalid ACL: %w", err)
	}
	nodes := make([]types.PeerNode, 0, len(draft.Members))
	for _, member := range draft.Members {
		nodes = append(nodes, member.Peer())
	}
	rules := acl.CompileForNode(draft.ACL, types.PeerNode{}, nodes)
	if len(rules) == 0 {
		rules = []types.FilterRule{owner.DenyAll()}
	}
	now := time.Now().UTC()
	env, err := owner.Sign(owner.Snapshot{
		Version: version, ExpiresAt: now.Add(ttl), Members: draft.Members,
		PacketFilter: rules, DNS: draft.DNS, STUNAddr: draft.STUNAddr, STUNAltAddr: draft.STUNAltAddr,
	}, key, now)
	if err != nil {
		return 0, err
	}
	signer.LastVersion = version
	// Reserve the version before exposing the signed bytes. A failed export
	// can leave a gap, but cannot lead to a second authorization at that version.
	if err := writeOwnerFile(dir, signerFile, signer); err != nil {
		return 0, err
	}
	if err := writeOwnerFile(dir, publicationFile, env); err != nil {
		return 0, err
	}
	return version, writeOwnerFile(dir, trustFile, owner.NewTrust(key.Public().(ed25519.PublicKey), version))
}

func writeOwnerFile(dir, name string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return secfile.WritePrivate(filepath.Join(dir, name), append(raw, '\n'))
}
