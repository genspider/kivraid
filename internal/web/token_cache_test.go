package web

import (
	"net/http"
	"net/url"
	"testing"
)

// Responses that carry tokens must not be cached.
func TestTokenEndpointNoStore(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	resp, err := http.PostForm(issuer+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {"nope"}, "redirect_uri": {testRedirectURI},
		"client_id": {testClientID}, "client_secret": {testClientSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("token endpoint Cache-Control: got %q, want no-store", got)
	}
}
