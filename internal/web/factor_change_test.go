package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// A user who has a passkey but signed in with the password alone must not
// be able to enroll a factor of their own choosing — that would satisfy
// the two-factor policy with the password only — nor remove the passkey.
func TestPasswordOnlySessionCannotReplaceFactors(t *testing.T) {
	ts, st, admin, adminCSRF := adminClient(t)
	ctx := context.Background()
	bob, err := local.NewSource(st).CreateUser(ctx, "bob", "bob@example.com", "Bob", "bob-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWebauthnCredential(ctx, sqlcgen.CreateWebauthnCredentialParams{
		ID: "pk1", UserID: bob.ID, CredentialID: "cred-1", Name: "YubiKey", Data: "{}", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	setMFAPolicy(t, admin, ts.URL, adminCSRF, mfaPolicyAll)

	c := newClient(t)
	login(t, c, ts.URL, "bob", "bob-pass-123")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/mfa/required")

	// The required page sends him to his passkey, not to enrollment.
	_, page := getPage(t, c, ts.URL+"/mfa/required")
	if !strings.Contains(page, "Sign out to use my passkey") || strings.Contains(page, "Set up two-factor") {
		t.Error("a user with a passkey should be asked to use it, not to enroll another factor")
	}

	post := func(path string, form url.Values, json bool) int {
		t.Helper()
		var resp *http.Response
		var err error
		if json {
			req, _ := http.NewRequest(http.MethodPost, ts.URL+path, nil)
			req.Header.Set("X-CSRF-Token", csrf)
			req.Header.Set("Content-Type", "application/json")
			resp, err = c.Do(req)
		} else {
			form.Set("_csrf", csrf)
			resp, err = c.PostForm(ts.URL+path, form)
		}
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("/profile/mfa/begin", url.Values{}, false); code != http.StatusForbidden {
		t.Errorf("TOTP enrollment from a password-only session: want 403, got %d", code)
	}
	if code := post("/profile/passkeys/begin", nil, true); code != http.StatusForbidden {
		t.Errorf("passkey registration from a password-only session: want 403, got %d", code)
	}
	if n, _ := st.CountWebauthnCredentials(ctx, bob.ID); n != 1 {
		t.Fatalf("passkeys: want 1, got %d", n)
	}
	post("/profile/passkeys/pk1/delete", url.Values{}, false)
	if n, _ := st.CountWebauthnCredentials(ctx, bob.ID); n != 1 {
		t.Error("a password-only session must not remove the passkey")
	}
	if u, _ := st.GetUserByID(ctx, bob.ID); u.TotpEnabled {
		t.Error("TOTP must not have been enabled")
	}
}
