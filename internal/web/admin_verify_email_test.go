package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kivraid/kivraid/internal/sources/local"
)

// Without email delivery, an administrator can still vouch for a local
// account's address, as the profile page tells the user.
func TestAdminMarksEmailVerified(t *testing.T) {
	ts, st, admin, csrf := adminClient(t)
	ctx := context.Background()
	bob, err := local.NewSource(st).CreateUser(ctx, "bob", "bob@example.com", "Bob", "bob-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, page := getPage(t, admin, ts.URL+"/admin/users/"+bob.ID); !strings.Contains(page, `action="/admin/users/`+bob.ID+`/email-verified"`) {
		t.Fatal("the user page should offer to mark the address verified")
	}

	// A non-administrator cannot.
	c := newClient(t)
	login(t, c, ts.URL, "bob", "bob-pass-123")
	bobCSRF := fetchCSRFFromPage(t, c, ts.URL+"/profile")
	resp, err := c.PostForm(ts.URL+"/admin/users/"+bob.ID+"/email-verified", url.Values{"_csrf": {bobCSRF}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if u, _ := st.GetUserByID(ctx, bob.ID); u.EmailVerified {
		t.Fatal("a non-administrator verified their own address")
	}

	resp, err = admin.PostForm(ts.URL+"/admin/users/"+bob.ID+"/email-verified", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("mark verified: want 303, got %d", resp.StatusCode)
	}
	if u, _ := st.GetUserByID(ctx, bob.ID); !u.EmailVerified {
		t.Error("the address should be verified")
	}
}
