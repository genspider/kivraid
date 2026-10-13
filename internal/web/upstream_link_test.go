package web

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/broker"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
	"github.com/kivraid/kivraid/internal/store/storetest"
)

// An upstream identity with a matching verified email links to an ordinary
// account, but never to a protected one: an administrator, an account with
// its own second factor, or one already linked to another provider.
func TestUpstreamEmailLinkingProtectsAccounts(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	srv := newServerInstance(t, st)
	p := newUpstreamProvider(t, st, "up1")
	other := newUpstreamProvider(t, st, "up2")

	mk := func(name string, admin bool) sqlcgen.User {
		t.Helper()
		u, err := local.NewSource(st).CreateUser(ctx, name, name+"@example.com", name, name+"-pass-123", admin)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetEmailVerified(ctx, sqlcgen.SetEmailVerifiedParams{EmailVerified: true, UpdatedAt: time.Now().UTC(), ID: u.ID}); err != nil {
			t.Fatal(err)
		}
		return u
	}
	mk("root", true)
	totp := mk("tina", false)
	if _, err := st.DB.Exec(`UPDATE users SET totp_enabled = TRUE WHERE id = $1`, totp.ID); err != nil {
		t.Fatal(err)
	}
	linked := mk("lena", false)
	sub := "elsewhere"
	if err := st.SetUserUpstreamIdentity(ctx, sqlcgen.SetUserUpstreamIdentityParams{
		UpstreamSourceID: &other.ID, ExternalID: &sub, UpdatedAt: time.Now().UTC(), ID: linked.ID,
	}); err != nil {
		t.Fatal(err)
	}
	plain := mk("paul", false)

	for _, name := range []string{"root", "tina", "lena"} {
		_, err := srv.provisionUpstreamUser(ctx, p, &broker.Identity{
			Subject: "sub-" + name, Email: name + "@example.com", EmailVerified: true,
		})
		if !errors.Is(err, errLinkRefused) {
			t.Errorf("%s: want errLinkRefused, got %v", name, err)
		}
	}
	u, err := srv.provisionUpstreamUser(ctx, p, &broker.Identity{
		Subject: "sub-paul", Email: "paul@example.com", EmailVerified: true,
	})
	if err != nil || u.ID != plain.ID {
		t.Fatalf("ordinary account: want linked to paul, got %v / %v", u.ID, err)
	}
}
