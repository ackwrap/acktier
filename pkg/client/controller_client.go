package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/securehttp"
	"github.com/acktier/acktier/pkg/types"
)

// ControllerClient authenticates to the center's delegated management listener
// using per-request Ed25519 challenge signatures (never sharing Web passwords,
// browser cookies, node tokens, or the owner's policy-signing root key).
type ControllerClient struct {
	baseURL    string
	networkID  string
	privateKey ed25519.PrivateKey
	httpCli    *http.Client
}

func NewControllerClient(adminServerURL, networkID string, privateKey ed25519.PrivateKey, customHTTP *http.Client) *ControllerClient {
	if customHTTP == nil {
		customHTTP = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
	}
	return &ControllerClient{
		baseURL:    strings.TrimRight(strings.TrimSpace(adminServerURL), "/"),
		networkID:  strings.TrimSpace(networkID),
		privateKey: privateKey,
		httpCli:    securehttp.NoRedirects(customHTTP),
	}
}

func (c *ControllerClient) ConfigureTLS(caFile string) error {
	if strings.TrimSpace(caFile) == "" {
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
	c.httpCli = securehttp.NoRedirects(&http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		},
	})
	return nil
}

func (c *ControllerClient) challenge(ctx context.Context) (owner.AdminChallenge, error) {
	var ch owner.AdminChallenge
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+owner.AdminChallengePath, nil)
	if err != nil {
		return ch, err
	}
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return ch, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return ch, fmt.Errorf("challenge HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&ch); err != nil {
		return ch, err
	}
	return ch, nil
}

func (c *ControllerClient) doSigned(ctx context.Context, method, path string, reqBody any, respOut any) error {
	ch, err := c.challenge(ctx)
	if err != nil {
		return err
	}
	netID := c.networkID
	if netID == "" {
		netID = ch.NetworkID
	} else if ch.NetworkID != "" && ch.NetworkID != netID {
		return fmt.Errorf("server networkId %s does not match expected %s", ch.NetworkID, netID)
	}
	var raw []byte
	if reqBody != nil {
		raw, err = json.Marshal(reqBody)
		if err != nil {
			return err
		}
	}
	fullURL := c.baseURL + path
	parsed, err := url.Parse(fullURL)
	if err != nil {
		return err
	}
	authHdr, err := owner.FormatAdminProof(c.privateKey, netID, ch.Challenge, method, parsed.RequestURI(), raw)
	if err != nil {
		return err
	}
	var bodyReader io.Reader
	if len(raw) > 0 {
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authHdr)
	if len(raw) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("controller %s %s failed (HTTP %d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if respOut != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(respOut)
	}
	return nil
}

func (c *ControllerClient) OwnerJoinRequests(ctx context.Context) ([]types.OwnerJoinRequest, error) {
	var out []types.OwnerJoinRequest
	err := c.doSigned(ctx, http.MethodGet, "/api/v1/admin/owner/requests", nil, &out)
	return out, err
}

func (c *ControllerClient) Nodes(ctx context.Context) ([]types.PeerNode, error) {
	var out []types.PeerNode
	err := c.doSigned(ctx, http.MethodGet, "/api/v1/admin/nodes", nil, &out)
	return out, err
}

func (c *ControllerClient) GetOwnerAuthorization(ctx context.Context) (*types.OwnerAuthorization, error) {
	var env types.OwnerAuthorization
	if err := c.doSigned(ctx, http.MethodGet, "/api/v1/admin/owner/authorization", nil, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func (c *ControllerClient) PublishOwnerAuthorization(ctx context.Context, env types.OwnerAuthorization) (uint64, error) {
	var out struct {
		Version uint64 `json:"version"`
	}
	err := c.doSigned(ctx, http.MethodPut, "/api/v1/admin/owner/authorization", env, &out)
	return out.Version, err
}

func (c *ControllerClient) CreateKey(ctx context.Context, label string, reusable bool, ttlHours int) (types.PreAuthKey, error) {
	var out types.PreAuthKey
	err := c.doSigned(ctx, http.MethodPost, "/api/v1/admin/keys", map[string]any{
		"label": label, "reusable": reusable, "ttlHours": ttlHours,
	}, &out)
	return out, err
}

// ListPreAuthKeys returns enrollment metadata without key plaintext.
func (c *ControllerClient) ListPreAuthKeys(ctx context.Context) ([]types.PreAuthKey, error) {
	var out []types.PreAuthKey
	err := c.doSigned(ctx, http.MethodGet, "/api/v1/admin/keys", nil, &out)
	return out, err
}

func (c *ControllerClient) RevokeKey(ctx context.Context, id string) error {
	return c.doSigned(ctx, http.MethodDelete, "/api/v1/admin/keys/"+url.PathEscape(id), nil, nil)
}
