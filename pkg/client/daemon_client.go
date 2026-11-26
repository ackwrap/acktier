package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/localapi"
	"github.com/ackwrap/acktier/internal/securehttp"
	"github.com/ackwrap/acktier/pkg/types"
)

// DefaultLocalAPIURL is the default loopback IPC endpoint of a running acktierd service.
const DefaultLocalAPIURL = "http://" + localapi.DefaultAddr

// DaemonClient is a typed Go SDK client for controlling an out-of-process `acktierd` daemon
// authenticated via an OS-permission-protected LocalAPI token.
type DaemonClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewDaemonClient creates a client targeting an acktierd LocalAPI endpoint (defaults to http://127.0.0.1:41920),
// automatically loading the owner-only LocalAPI token from ACKTIER_LOCAL_TOKEN or the OS-protected token file.
func NewDaemonClient(apiURL string, httpCli *http.Client) *DaemonClient {
	if strings.TrimSpace(apiURL) == "" {
		apiURL = DefaultLocalAPIURL
	}
	if httpCli == nil {
		httpCli = &http.Client{Timeout: 15 * time.Second}
	}
	cleanURL := strings.TrimRight(apiURL, "/")
	return &DaemonClient{
		baseURL:    cleanURL,
		token:      localapi.ReadTokenFile(cleanURL),
		httpClient: securehttp.NoRedirects(httpCli),
	}
}

// SetToken explicitly configures the LocalAPI bearer token (useful for in-process Node.LocalAPIHandler() SDK usage).
func (c *DaemonClient) SetToken(token string) {
	c.token = strings.TrimSpace(token)
}

func (c *DaemonClient) Up(ctx context.Context, opts UpOptions) (*types.NetMap, error) {
	var out types.NetMap
	if err := c.doJSON(ctx, http.MethodPost, "/local/v1/up", opts, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *DaemonClient) Down(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/local/v1/down", map[string]any{}, nil)
}

func (c *DaemonClient) Status(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/local/v1/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *DaemonClient) Mesh(ctx context.Context) (*MeshStatusReport, error) {
	var out MeshStatusReport
	if err := c.doJSON(ctx, http.MethodGet, "/local/v1/mesh", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *DaemonClient) NetCheck(ctx context.Context) (*NetCheckReport, error) {
	var out NetCheckReport
	if err := c.doJSON(ctx, http.MethodGet, "/local/v1/netcheck", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *DaemonClient) Ping(ctx context.Context, target string, timeout time.Duration) (*PingResult, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var out PingResult
	req := map[string]any{
		"target":    target,
		"timeoutMs": int(timeout.Milliseconds()),
	}
	if err := c.doJSON(ctx, http.MethodPost, "/local/v1/ping", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type DNSLookupResult struct {
	FQDN string `json:"fqdn"`
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

func (c *DaemonClient) LookupDNS(ctx context.Context, host string) (*DNSLookupResult, error) {
	var out DNSLookupResult
	path := "/local/v1/dns?name=" + url.QueryEscape(host)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *DaemonClient) SetExitNode(ctx context.Context, peer string) error {
	return c.doJSON(ctx, http.MethodPost, "/local/v1/exit-node", map[string]string{"exitNode": peer}, nil)
}

func (c *DaemonClient) NotifyNetworkChange(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/local/v1/network-change", map[string]any{}, nil)
}

func (c *DaemonClient) doJSON(ctx context.Context, method, path string, reqBody any, respOut any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	tok := c.token
	if tok == "" {
		tok = localapi.ReadTokenFile(c.baseURL)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("localapi %s %s failed (HTTP %d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if respOut != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(respOut)
	}
	return nil
}
