package web

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// Changing one's password signs every other session out and drops the
// OAuth tokens; the browser that made the change stays signed in.
func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	ctx := context.Background()
	alice, err := st.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
		ID: "rt1", UserID: alice.ID, ClientID: "some-client", Scopes: "[]", Audience: "[]", Amr: "[]",
		AuthTime: now, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	here, elsewhere := newClient(t), newClient(t)
	login(t, here, ts.URL, "alice", "s3cret-pass")
	login(t, elsewhere, ts.URL, "alice", "s3cret-pass")

	csrf := fetchCSRFFromPage(t, here, ts.URL+"/profile")
	resp, err := here.PostForm(ts.URL+"/profile/password", url.Values{
		"_csrf": {csrf}, "current_password": {"s3cret-pass"},
		"new_password": {"new-pass-123"}, "confirm_password": {"new-pass-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("change: want 303, got %d", resp.StatusCode)
	}
	if status, _ := getPage(t, here, ts.URL+"/profile"); status != http.StatusOK {
		t.Errorf("the browser that changed the password should stay signed in, got %d", status)
	}
	if status, _ := getPage(t, elsewhere, ts.URL+"/profile"); status == http.StatusOK {
		t.Error("the other session should be signed out")
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1`, alice.ID).Scan(&n); err != nil || n != 0 {
		t.Errorf("refresh tokens left: %d (err %v)", n, err)
	}
}
