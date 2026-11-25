package securehttp

import "net/http"

// NoRedirects copies an HTTP client for a credential-bearing API. Neither an
// Authorization header nor a replayable request body may follow a redirect.
func NoRedirects(client *http.Client) *http.Client {
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &copy
}
