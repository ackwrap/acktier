package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ackwrap/acktier/internal/securehttp"
	"github.com/ackwrap/acktier/pkg/types"
)

// AdminClient is a typed Go SDK for managing an `acktier-server` Control Plane programmatically.
type AdminClient struct {
	serverURL         string
	adminToken        string
	httpClient        *http.Client
	customHTTP        bool
	allowInsecureHTTP bool
}

func NewAdminClient(serverURL, adminToken string, httpCli *http.Client) *AdminClient {
	custom := httpCli != nil
	if httpCli == nil {
		httpCli = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		}
	}
	return &AdminClient{
		serverURL:  strings.TrimRight(strings.TrimSpace(serverURL), "/"),
		adminToken: strings.TrimSpace(adminToken),
		httpClient: securehttp.NoRedirects(httpCli),
		customHTTP: custom,
	}
}

// ConfigureTLS sets a custom Root CA PEM file and/or insecure-http lab toggle on AdminClient.
func (a *AdminClient) ConfigureTLS(caFile string, allowInsecureHTTP bool) error {
	a.allowInsecureHTTP = allowInsecureHTTP
	if strings.TrimSpace(caFile) == "" || a.customHTTP {
		return nil
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read TLS CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("TLS CA file %s contains no valid PEM certificates", caFile)
	}
	a.httpClient = securehttp.NoRedirects(&http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	})
	return nil
}

type CreateKeyOptions struct {
	Label      string        `json:"label,omitempty"`
	Reusable   bool          `json:"reusable"`
	Ephemeral  bool          `json:"ephemeral,omitempty"`
	Tags       []string      `json:"tags,omitempty"`
	TTL        time.Duration `json:"-"`
	TTLSeconds int64         `json:"ttlSeconds,omitempty"`
}

func (a *AdminClient) CreatePreAuthKey(ctx context.Context, opts CreateKeyOptions) (*types.PreAuthKey, error) {
	if opts.TTL > 0 && opts.TTLSeconds == 0 {
		opts.TTLSeconds = int64(opts.TTL.Seconds())
	}
	var out types.PreAuthKey
	if err := a.doJSON(ctx, http.MethodPost, "/api/v1/admin/keys", opts, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *AdminClient) ListPreAuthKeys(ctx context.Context) ([]types.PreAuthKey, error) {
	var out []types.PreAuthKey
	if err := a.doJSON(ctx, http.MethodGet, "/api/v1/admin/keys", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *AdminClient) RevokePreAuthKey(ctx context.Context, keyID string) error {
	return a.doJSON(ctx, http.MethodDelete, "/api/v1/admin/keys/"+keyID, nil, nil)
}

func (a *AdminClient) ListNodes(ctx context.Context) ([]types.PeerNode, error) {
	var out []types.PeerNode
	if err := a.doJSON(ctx, http.MethodGet, "/api/v1/admin/nodes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *AdminClient) DeleteNode(ctx context.Context, nodeID types.NodeID) error {
	return a.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/admin/nodes/%d", nodeID), nil, nil)
}

type RekeyNodeResponse struct {
	NodeID    types.NodeID   `json:"nodeId"`
	NodeToken string         `json:"nodeToken"`
	Node      types.PeerNode `json:"node"`
}

// RekeyNode rotates the bearer token and retires the previous data-plane key.
// Without a replacement NodeKey, the node is excluded from topology until it
// registers a different key using the new token.
func (a *AdminClient) RekeyNode(ctx context.Context, nodeID types.NodeID, newMachineKey, newNodeKey types.PublicKey) (*RekeyNodeResponse, error) {
	body := map[string]any{}
	if !newMachineKey.IsZero() {
		body["machineKey"] = newMachineKey
	}
	if !newNodeKey.IsZero() {
		body["nodeKey"] = newNodeKey
	}
	var out RekeyNodeResponse
	if err := a.doJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/rekey", nodeID), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RenameNode assigns a server-verified unique MagicDNS name to an existing node.
func (a *AdminClient) RenameNode(ctx context.Context, nodeID types.NodeID, newName string) (*types.PeerNode, error) {
	var out types.PeerNode
	if err := a.doJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/rename", nodeID), map[string]string{"name": newName}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *AdminClient) ApproveRoutes(ctx context.Context, nodeID types.NodeID, routes []netip.Prefix) (*types.PeerNode, error) {
	var out types.PeerNode
	body := map[string]any{"routes": routes}
	if err := a.doJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/routes/approve", nodeID), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *AdminClient) GetACL(ctx context.Context) (*types.ACLPolicy, error) {
	var out types.ACLPolicy
	if err := a.doJSON(ctx, http.MethodGet, "/api/v1/admin/acl", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *AdminClient) SetACL(ctx context.Context, policy types.ACLPolicy) (*types.ACLPolicy, error) {
	var out types.ACLPolicy
	if err := a.doJSON(ctx, http.MethodPut, "/api/v1/admin/acl", policy, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *AdminClient) SetDNS(ctx context.Context, dnsCfg types.DNSConfig) (*types.DNSConfig, error) {
	var out types.DNSConfig
	if err := a.doJSON(ctx, http.MethodPut, "/api/v1/admin/dns", dnsCfg, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *AdminClient) checkTransportSecurity() error {
	if a.customHTTP || a.allowInsecureHTTP {
		return nil
	}
	u, err := url.Parse(a.serverURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid server URL %q", a.serverURL)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip, pErr := netip.ParseAddr(host); pErr == nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to send AdminToken over plaintext HTTP to non-loopback %q; use https:// (or --insecure-http for isolated lab testing)", a.serverURL)
}

func (a *AdminClient) doJSON(ctx context.Context, method, path string, reqBody any, respOut any) error {
	if err := a.checkTransportSecurity(); err != nil {
		return err
	}
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.serverURL+path, bodyReader)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.adminToken)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("admin %s %s failed (HTTP %d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if respOut != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(respOut)
	}
	return nil
}
