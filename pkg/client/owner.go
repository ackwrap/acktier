package client

import (
	"context"
	"net/http"

	"github.com/ackwrap/acktier/pkg/types"
)

// OwnerJoinRequests lists unverified applications. Verify node keys through
// an independent channel before signing any of them into membership.
func (a *AdminClient) OwnerJoinRequests(ctx context.Context) ([]types.OwnerJoinRequest, error) {
	var requests []types.OwnerJoinRequest
	err := a.doJSON(ctx, http.MethodGet, "/api/v1/admin/owner/requests", nil, &requests)
	return requests, err
}

// GetOwnerAuthorization fetches the signed artifact, without trusting it on
// behalf of the caller. The server does not possess the owner's private key.
func (a *AdminClient) GetOwnerAuthorization(ctx context.Context) (*types.OwnerAuthorization, error) {
	var env types.OwnerAuthorization
	if err := a.doJSON(ctx, http.MethodGet, "/api/v1/admin/owner/authorization", nil, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// PublishOwnerAuthorization uploads an artifact previously signed on the owner's computer.
func (a *AdminClient) PublishOwnerAuthorization(ctx context.Context, env types.OwnerAuthorization) (uint64, error) {
	var out struct {
		Version uint64 `json:"version"`
	}
	err := a.doJSON(ctx, http.MethodPut, "/api/v1/admin/owner/authorization", env, &out)
	return out.Version, err
}
