package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

// AdminClient is a typed Go SDK for managing an `acktier-server` Control Plane programmatically.
type AdminClient struct {
	serverURL  string
	adminToken string
	httpClient *http.Client
}

func NewAdminClient(serverURL, adminToken string, httpCli *http.Client) *AdminClient {
	if httpCli == nil {
		httpCli = &http.Client{Timeout: 15 * time.Second}
	}
	return &AdminClient{
		serverURL:  strings.TrimRight(strings.TrimSpace(serverURL), "/"),
		adminToken: strings.TrimSpace(adminToken),
		httpClient: httpCli,
	}
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

func (a *AdminClient) doJSON(ctx context.Context, method, path string, reqBody any, respOut any) error {
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
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin %s %s failed (HTTP %d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if respOut != nil {
		return json.NewDecoder(resp.Body).Decode(respOut)
	}
	return nil
}
