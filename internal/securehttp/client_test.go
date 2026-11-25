package securehttp

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestNoRedirectsPreservesTransportAndReturnsOriginalResponse(t *testing.T) {
	calls := 0
	base := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": {"/elsewhere"}},
				Body:       io.NopCloser(strings.NewReader("redirect")),
				Request:    req,
			}, nil
		}),
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://control.example.test/register", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer fixture")
	resp, err := NoRedirects(base).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if calls != 1 || resp.StatusCode != http.StatusTemporaryRedirect || base.CheckRedirect != nil {
		t.Fatalf("unexpected redirect handling: calls=%d status=%d", calls, resp.StatusCode)
	}
}
