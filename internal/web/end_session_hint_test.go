package web

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/kivraid/kivraid/internal/sources/local"
)

// An application's own ID token as id_token_hint signs the user out
// without asking; a hint for someone else does not.
func TestEndSessionWithIDTokenHint(t *testing.T) {
	issuer, st := startIssuer(t, false)
	if _, err := local.NewSource(st).CreateUser(context.Background(), "bob", "bob@example.com", "Bob", "bob-pass-123", false); err != nil {
		t.Fatal(err)
	}
	aliceBrowser := newClient(t)
	aliceToken := signIn(t, issuer, aliceBrowser).IDToken

	bob := newClient(t)
	login(t, bob, issuer, "bob", "bob-pass-123")
	if status, _ := getPage(t, bob, issuer+"/end_session?id_token_hint="+url.QueryEscape(aliceToken)); status != http.StatusOK {
		t.Fatalf("someone else's hint: want the confirmation page, got %d", status)
	}
	if status, _ := getPage(t, bob, issuer+"/profile"); status != http.StatusOK {
		t.Error("someone else's ID token must not sign bob out")
	}

	resp, err := aliceBrowser.Get(issuer + "/end_session?id_token_hint=" + url.QueryEscape(aliceToken))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		t.Fatalf("own hint: want the logout redirect, got %d", resp.StatusCode)
	}
	resp, err = aliceBrowser.Get(issuer + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("alice should be signed out, got %d", resp.StatusCode)
	}
}
