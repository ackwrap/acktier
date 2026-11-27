package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ControllerPolicyPath is the signed policy API on the center's management listener.
const ControllerPolicyPath = "/api/v1/admin/policy"

// ControllerPolicyOperation identifies an explicitly delegated policy operation.
type ControllerPolicyOperation string

const (
	PolicyActive             ControllerPolicyOperation = "active"
	PolicyValidate           ControllerPolicyOperation = "validate"
	PolicyListDrafts         ControllerPolicyOperation = "list_drafts"
	PolicyCreateDraft        ControllerPolicyOperation = "create_draft"
	PolicyGetDraft           ControllerPolicyOperation = "get_draft"
	PolicyUpdateDraft        ControllerPolicyOperation = "update_draft"
	PolicyDeleteDraft        ControllerPolicyOperation = "delete_draft"
	PolicySaveACL            ControllerPolicyOperation = "save_acl"
	PolicyAddMember          ControllerPolicyOperation = "add_member"
	PolicyRemoveMember       ControllerPolicyOperation = "remove_member"
	PolicyExportDraft        ControllerPolicyOperation = "export_draft"
	PolicyPreviewPublication ControllerPolicyOperation = "preview_publication"
	PolicyPublish            ControllerPolicyOperation = "publish"
	PolicyPublicationHistory ControllerPolicyOperation = "publication_history"
	PolicyGetPublication     ControllerPolicyOperation = "get_publication"
)

var controllerPolicyEndpoints = map[ControllerPolicyOperation]struct {
	method string
	path   string
}{
	PolicyActive:             {http.MethodGet, "/active"},
	PolicyValidate:           {http.MethodPost, "/validate"},
	PolicyListDrafts:         {http.MethodGet, "/drafts"},
	PolicyCreateDraft:        {http.MethodPost, "/drafts"},
	PolicyGetDraft:           {http.MethodGet, "/drafts/{}"},
	PolicyUpdateDraft:        {http.MethodPut, "/drafts/{}"},
	PolicyDeleteDraft:        {http.MethodDelete, "/drafts/{}"},
	PolicySaveACL:            {http.MethodPost, "/drafts/{}/acl"},
	PolicyAddMember:          {http.MethodPost, "/drafts/{}/members"},
	PolicyRemoveMember:       {http.MethodDelete, "/drafts/{}/members/{}"},
	PolicyExportDraft:        {http.MethodGet, "/drafts/{}/export"},
	PolicyPreviewPublication: {http.MethodPost, "/authorization/preview"},
	PolicyPublish:            {http.MethodPost, "/authorization"},
	PolicyPublicationHistory: {http.MethodGet, "/authorization/history"},
	PolicyGetPublication:     {http.MethodGet, "/authorization/history/{}"},
}

// Policy calls a fixed, signed policy endpoint. Pass the draft ID, then the
// member key for PolicyRemoveMember, or the version for PolicyGetPublication.
// A nonempty revision is the draft's updatedAt value for a draft mutation.
// JSON is retained to preserve exact integer member IDs and policy fields.
func (c *ControllerClient) Policy(ctx context.Context, operation ControllerPolicyOperation, body json.RawMessage, revision string, params ...string) (json.RawMessage, error) {
	endpoint, ok := controllerPolicyEndpoints[operation]
	if !ok || strings.Count(endpoint.path, "{}") != len(params) {
		return nil, errors.New("invalid controller policy operation or parameters")
	}
	path := endpoint.path
	for _, param := range params {
		if param == "" || param == "." || param == ".." || strings.ContainsAny(param, "/\\") {
			return nil, errors.New("invalid controller policy path parameter")
		}
		path = strings.Replace(path, "{}", url.PathEscape(param), 1)
	}
	if revision != "" {
		path += "?" + (url.Values{"revision": {revision}}).Encode()
	}
	var input any
	if len(body) > 0 {
		input = body
	}
	var result json.RawMessage
	err := c.doSigned(ctx, endpoint.method, ControllerPolicyPath+path, input, &result)
	return result, err
}
