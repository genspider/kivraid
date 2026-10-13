package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/oidcserver"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// A reset or invitation link mailed to an address the account no longer
// has (an administrator corrected a mistyped email) must not set the
// password, nor mark the corrected address verified.
func TestResetLinkDiesWithEmailChange(t *testing.T) {
	ts, st, admin, csrf := adminClient(t)
	ctx := context.Background()
	user, err := local.NewSource(st).CreateUser(ctx, "carol", "carol@exampel.com", "Carol", "carol-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	newToken := func(raw string) {
		t.Helper()
		if err := st.CreateEmailToken(ctx, sqlcgen.CreateEmailTokenParams{
			TokenHash: oidcserver.HashToken(raw), Purpose: purposePasswordReset, UserID: user.ID,
			Email: user.Email, ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	newToken("invite-mistyped")
	// Even a token that escaped deletion is refused, on the address check.
	resp, err := admin.PostForm(ts.URL+"/admin/users/"+user.ID, url.Values{
		"_csrf": {csrf}, "name": {"Carol"}, "email": {"carol@example.com"}, "active": {"on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("email change: want 303, got %d", resp.StatusCode)
	}
	var left int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM email_tokens WHERE user_id = $1`, user.ID).Scan(&left); err != nil || left != 0 {
		t.Errorf("reset tokens after the email change: %d (err %v)", left, err)
	}
	newToken("stale-copy") // stored with the old address

	c := newClient(t)
	resetCSRF := fetchCSRF(t, c, ts.URL+"/login")
	resp, err = c.PostForm(ts.URL+"/reset", url.Values{
		"_csrf": {resetCSRF}, "token": {"stale-copy"},
		"password": {"attacker-pass-123"}, "confirm_password": {"attacker-pass-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a link for the old address must not reset the password")
	}
	if _, err := local.NewSource(st).Authenticate(ctx, "carol", "attacker-pass-123"); err == nil {
		t.Error("the password was changed")
	}
	if u, _ := st.GetUserByID(ctx, user.ID); u.EmailVerified {
		t.Error("the new address must not be marked verified")
	}
}
