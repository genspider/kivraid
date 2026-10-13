package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

// An attacker who starts an authorization request and gets a signed-in
// victim to open its resume link must not be able to collect the code.
func TestAuthorizeCallbackBoundToCompletingSession(t *testing.T) {
	issuer, _ := startIssuer(t, false)
	relying, err := rp.NewRelyingPartyOIDC(context.Background(), issuer, testClientID, testClientSecret,
		testRedirectURI, []string{"openid", "profile"})
	if err != nil {
		t.Fatal(err)
	}

	// The attacker starts a request and learns its id from the redirect.
	attacker := newClient(t)
	resp, err := attacker.Get(rp.AuthURL("attacker-state", relying))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loginURL, _ := url.Parse(resp.Header.Get("Location"))
	resumeURL, _ := url.Parse(loginURL.Query().Get("next"))
	id := resumeURL.Query().Get("id")
	if id == "" {
		t.Fatalf("no request id in %q", resp.Header.Get("Location"))
	}

	// The signed-in victim opens the resume link.
	victim := newClient(t)
	login(t, victim, issuer, "alice", "s3cret-pass")
	resp, err = victim.Get(issuer + resumeURL.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	callback := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(callback, "/authorize/callback") {
		t.Fatalf("resume: want 303 to the callback, got %d %q", resp.StatusCode, callback)
	}

	// The attacker cannot collect the code, with or without a session.
	for _, c := range []*http.Client{attacker, newClient(t)} {
		resp, err = c.Get(issuer + "/authorize/callback?id=" + url.QueryEscape(id))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); strings.Contains(loc, "code=") || resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attacker callback: want 400 and no code, got %d %q", resp.StatusCode, loc)
		}
	}

	// Opening the resume link again does not rebind the request.
	other := newClient(t)
	login(t, other, issuer, "alice", "s3cret-pass")
	resp, err = other.Get(issuer + resumeURL.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("second completion: want 400, got %d", resp.StatusCode)
	}

	// The victim's own browser still gets the response (sent to the
	// relying party, whose state check rejects the attacker's state).
	resp, err = victim.Get(issuer + callback)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, testRedirectURI) || !strings.Contains(loc, "code=") {
		t.Fatalf("victim callback: want a redirect to the client with a code, got %d %q", resp.StatusCode, loc)
	}
}
