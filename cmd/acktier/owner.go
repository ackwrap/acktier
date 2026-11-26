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
	"github.com/acktier/acktier/pkg/client"
	"github.com/acktier/acktier/pkg/types"
)

const (
	defaultOwnerDir       = "./data/owner"
	signerFile            = "signer.json"
	trustFile             = "trust.json"
	publicationFile       = "authorization.json"
	controllerSignerFile  = "controller-signer.json"
	controllerTrustFile   = "controller-trust.json"
)

type localSigner struct {
	Seed        []byte `json:"seed"`
	LastVersion uint64 `json:"lastVersion"`
}

type ownerPolicy = owner.Policy

func runOwner(args []string) {
	if len(args) == 0 {
		fatalf("usage: acktier owner init|controller-init|node-key|requests|sign|publish [flags]")
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
	case "controller-init":
		dir := fs.String("dir", defaultOwnerDir, "Existing local owner directory containing trust.json")
		label := fs.String("label", "owner-controller", "Label shown in the center console")
		parseOwnerFlags(fs, args[1:])
		if err := initController(*dir, *label); err != nil {
			fatalf("initialize controller credential: %v", err)
		}
		fmt.Printf("Controller API key generated. Upload %s in /admin/ (Security -> API Delegation) and keep %s local.\n",
			filepath.Join(*dir, controllerTrustFile), filepath.Join(*dir, controllerSignerFile))
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
		server := fs.String("server", "http://127.0.0.1:8081", "Center management URL (-admin-listen)")
		dir := fs.String("dir", defaultOwnerDir, "Local owner directory containing controller-signer.json and trust.json")
		token := fs.String("admin-token", os.Getenv("ACKTIER_ADMIN_TOKEN"), "Legacy non-owner AdminToken fallback")
		tlsCA := fs.String("tls-ca", os.Getenv("ACKTIER_TLS_CA"), "Optional TLS CA PEM file")
		var path *string
		if args[0] == "publish" {
			path = fs.String("file", defaultOwnerDir+"/"+publicationFile, "Previously signed authorization envelope")
		}
		parseOwnerFlags(fs, args[1:])
		ctx := context.Background()
		if cc, ok := tryBuildControllerClient(*server, *dir, *tlsCA); ok {
			if path == nil {
				requests, err := cc.OwnerJoinRequests(ctx)
				if err != nil {
					fatalf("%v", err)
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(requests)
				return
			}
			var env types.OwnerAuthorization
			if err := owner.ReadJSON(*path, owner.MaxEnvelope, &env); err != nil {
				fatalf("read signed envelope: %v", err)
			}
			version, err := cc.PublishOwnerAuthorization(ctx, env)
			if err != nil {
				fatalf("%v", err)
			}
			fmt.Printf("Published owner authorization v%d.\n", version)
			return
		}
		ac := buildAdminClient(*server, *token, *tlsCA, false)
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
	now := time.Now().UTC()
	snapshot, err := draft.Snapshot(version, now.Add(ttl))
	if err != nil {
		return 0, err
	}
	env, err := owner.Sign(snapshot, key, now)
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

func initController(dir, label string) error {
	trust, err := owner.LoadTrust(filepath.Join(dir, trustFile))
	if err != nil {
		return fmt.Errorf("load owner trust.json: %w", err)
	}
	signerPath := filepath.Join(dir, controllerSignerFile)
	if _, err := os.Stat(signerPath); err == nil {
		return errors.New("controller-signer.json already exists; remove it explicitly to rotate")
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	ct, err := owner.NewControllerTrust(trust, key, label)
	if err != nil {
		return err
	}
	if err := writeOwnerFile(dir, controllerSignerFile, localSigner{Seed: key.Seed()}); err != nil {
		return err
	}
	return writeOwnerFile(dir, controllerTrustFile, ct)
}

func tryBuildControllerClient(serverURL, dir, tlsCA string) (*client.ControllerClient, bool) {
	var cs localSigner
	if err := owner.ReadJSON(filepath.Join(dir, controllerSignerFile), 4096, &cs); err != nil || len(cs.Seed) != ed25519.SeedSize {
		return nil, false
	}
	trust, err := owner.LoadTrust(filepath.Join(dir, trustFile))
	if err != nil {
		return nil, false
	}
	cc := client.NewControllerClient(serverURL, trust.NetworkID(), ed25519.NewKeyFromSeed(cs.Seed), nil)
	if err := cc.ConfigureTLS(tlsCA); err != nil {
		fatalf("%v", err)
	}
	return cc, true
}
