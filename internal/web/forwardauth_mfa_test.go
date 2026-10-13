package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/kivraid/kivraid/internal/sources/local"
)

// When the instance requires two-factor, a password-only session is sent
// to set it up before reaching a protected application too.
func TestForwardAuthAppliesInstanceMFAPolicy(t *testing.T) {
	ts, st, admin, csrf := adminClient(t)
	if _, err := local.NewSource(st).CreateUser(context.Background(), "bob", "bob@example.com", "Bob", "bob-pass-123", false); err != nil {
		t.Fatal(err)
	}
	setMFAPolicy(t, admin, ts.URL, csrf, mfaPolicyAll)

	bob := newClient(t)
	login(t, bob, ts.URL, "bob", "bob-pass-123")
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/outpost/auth", nil)
	req.Header.Set("X-Forwarded-Host", "files.example.com") // not a registered application
	resp, err := bob.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.Header.Get("Remote-User") != "" {
		t.Fatalf("password-only session under the 'all' policy: want no access, got %d %q",
			resp.StatusCode, resp.Header.Get("Remote-User"))
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode == http.StatusFound && !strings.Contains(loc, mfaRequiredPath) {
		t.Errorf("redirect should lead to %s, got %q", mfaRequiredPath, loc)
	}
}
