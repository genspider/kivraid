package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// authorizeSignedIn runs authorize → resume → callback for a browser that
// is already signed in, signing in again if Kivraid asks for it, and
// returns the code and whether a fresh sign-in was asked.
func authorizeSignedIn(t *testing.T, c *http.Client, issuer, authURL string) (code string, reauth bool) {
	t.Helper()
	next := authURL
	for range 8 {
		u, err := url.Parse(next)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(next, testRedirectURI) {
			return u.Query().Get("code"), reauth
		}
		if u.Path == "/login" && u.Query().Get("reauth") == "1" {
			reauth = true
			csrf := fetchCSRF(t, c, issuer+u.RequestURI()) // the form, although signed in
			resp, err := c.PostForm(issuer+"/login", url.Values{
				"_csrf": {csrf}, "username": {"alice"}, "next": {u.Query().Get("next")},
			})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			resp = passwordStep(t, c, issuer, csrf, "s3cret-pass")
			resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("re-authentication: want 303, got %d", resp.StatusCode)
			}
			next = resp.Header.Get("Location")
			continue
		}
		if !u.IsAbs() {
			next = issuer + next
		}
		resp, err := c.Get(next)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			t.Fatalf("GET %s: want a redirect, got %d", next, resp.StatusCode)
		}
		next = resp.Header.Get("Location")
	}
	t.Fatal("authorization did not reach the client")
	return "", false
}

// auth_time is the session's real sign-in time, prompt=login asks for a
// new sign-in, and amr reflects how the user signed in.
func TestAuthTimePromptLoginAndAMR(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	ctx := context.Background()
	relying, err := rp.NewRelyingPartyOIDC(ctx, issuer, testClientID, testClientSecret,
		testRedirectURI, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	browser := newClient(t)
	login(t, browser, issuer, "alice", "s3cret-pass")
	signedIn := time.Now()
	time.Sleep(1100 * time.Millisecond)

	code, reauth := authorizeSignedIn(t, browser, issuer, rp.AuthURL("s1", relying))
	if reauth {
		t.Fatal("no fresh sign-in was asked for")
	}
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, relying)
	if err != nil {
		t.Fatal(err)
	}
	if at := tokens.IDTokenClaims.AuthTime.AsTime(); at.After(signedIn) {
		t.Errorf("auth_time %v should be the sign-in time (≤ %v), not the authorization time", at, signedIn)
	}
	if amr := tokens.IDTokenClaims.AuthenticationMethodsReferences; len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("amr for a password sign-in: got %v", amr)
	}

	before := time.Now().Truncate(time.Second)
	code, reauth = authorizeSignedIn(t, browser, issuer, rp.AuthURL("s2", relying, rp.WithPrompt(oidc.PromptLogin)))
	if !reauth {
		t.Fatal("prompt=login must ask for a fresh sign-in")
	}
	tokens, err = rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, relying)
	if err != nil {
		t.Fatal(err)
	}
	if at := tokens.IDTokenClaims.AuthTime.AsTime(); at.Before(before) {
		t.Errorf("after prompt=login, auth_time %v should be the new sign-in (≥ %v)", at, before)
	}
}
