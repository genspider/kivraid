package web

import (
	"net/url"
	"strings"
	"testing"
)

// Only S256 PKCE is accepted: "plain", explicit or by omission, puts the
// verifier in the authorization URL.
func TestPKCEPlainRejected(t *testing.T) {
	issuer, _ := startIssuer(t, true)
	for _, method := range []string{"plain", ""} {
		q := url.Values{
			"client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "response_type": {"code"},
			"scope": {"openid"}, "state": {"s"}, "code_challenge": {"the-verifier-itself-0123456789abcdef0123456"},
		}
		if method != "" {
			q.Set("code_challenge_method", method)
		}
		resp, err := newClient(t).Get(issuer + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "/login") || !strings.Contains(loc, "error=invalid_request") {
			t.Errorf("method %q: want an invalid_request error to the client, got %d %q", method, resp.StatusCode, loc)
		}
	}
}
