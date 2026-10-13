package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// An expired access token is reported inactive, not active until the
// periodic cleanup deletes it.
func TestIntrospectionExpiredTokenInactive(t *testing.T) {
	issuer, st := startIssuer(t, false)
	ctx := context.Background()
	relying, err := rp.NewRelyingPartyOIDC(ctx, issuer, testClientID, testClientSecret, testRedirectURI, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, browseAuthFlow(t, rp.AuthURL("teststate", relying)), relying)
	if err != nil {
		t.Fatal(err)
	}
	introspect := func() bool {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, issuer+"/oauth/introspect",
			strings.NewReader(url.Values{"token": {tokens.AccessToken}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testClientID, testClientSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Active bool `json:"active"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out.Active
	}
	if !introspect() {
		t.Fatal("a fresh access token should be active")
	}
	if _, err := st.DB.Exec(`UPDATE access_tokens SET expires_at = $1`, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if introspect() {
		t.Error("an expired access token must be reported inactive")
	}
}
