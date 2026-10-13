package web

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/kivraid/kivraid/internal/sources/local"
)

// Signing in as someone else in a browser that was impersonating must not
// keep the impersonation: "return to your account" would hand the new
// session back the administrator's identity.
func TestSignInClearsImpersonation(t *testing.T) {
	ts, st, admin, csrf := adminClient(t)
	ctx := context.Background()
	bob, err := local.NewSource(st).CreateUser(ctx, "bob", "bob@example.com", "Bob", "bob-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.NewSource(st).CreateUser(ctx, "carol", "carol@example.com", "Carol", "carol-pass-123", false); err != nil {
		t.Fatal(err)
	}
	resp, err := admin.PostForm(ts.URL+"/admin/users/"+bob.ID+"/impersonate", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Same browser, a regular sign-in as carol (the forms work while signed in).
	resp, err = admin.PostForm(ts.URL+"/login", url.Values{"_csrf": {csrf}, "username": {"carol"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp = passwordStep(t, admin, ts.URL, csrf, "carol-pass-123")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign in as carol: want 303, got %d", resp.StatusCode)
	}

	csrf = fetchCSRFFromPage(t, admin, ts.URL+"/profile")
	resp, err = admin.PostForm(ts.URL+"/impersonate/stop", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if status, _ := getPage(t, admin, ts.URL+"/admin/users"); status == http.StatusOK {
		t.Error("carol's session must not turn back into the administrator's")
	}
}
