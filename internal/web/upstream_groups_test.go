package web

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/config"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
	"github.com/kivraid/kivraid/internal/store/storetest"
)

// A federated user's groups claim mirrors only the provider's own groups:
// naming a local group (here, one that grants the administrator role) must
// not join it.
func TestUpstreamGroupsDoNotJoinLocalGroups(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	srv := newServerInstance(t, st)
	now := time.Now().UTC()
	p := newUpstreamProvider(t, st, "up1")
	admins, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{ID: "g-admins", Name: "admins", Source: "local", CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE groups SET grants_admin = TRUE WHERE id = $1`, admins.ID); err != nil {
		t.Fatal(err)
	}
	user, err := local.NewSource(st).CreateUser(ctx, "mallory", "mallory@example.com", "Mallory", "unused-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}

	if err := srv.syncUpstreamGroups(ctx, p, user.ID, []string{"admins", "devs"}); err != nil {
		t.Fatal(err)
	}
	groups, err := st.ListUserGroups(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, g := range groups {
		names = append(names, g.Name+"("+g.Source+")")
		if g.ID == admins.ID {
			t.Error("the claim must not join the local admins group")
		}
	}
	if len(groups) != 1 || groups[0].Name != "devs" || groups[0].Source != "upstream" {
		t.Errorf("want only the provider's own group devs, got %v", names)
	}
	if n, err := st.CountAdminGroupMemberships(ctx, user.ID); err != nil || n != 0 {
		t.Errorf("admin-granting memberships: %d (err %v)", n, err)
	}
}

// newServerInstance builds a Server (not wrapped in an HTTP test server)
// for tests that call its methods directly.
func newServerInstance(t *testing.T, st *store.Store) *Server {
	t.Helper()
	cfg := config.Config{BaseURL: "http://localhost", SecretKey: strings.Repeat("k", 32),
		Session: config.Session{Lifetime: config.Duration(time.Hour)}}
	srv, err := NewServer(Deps{
		Config: cfg, Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions: session.NewManager(st.DB, st.Driver, false, time.Hour, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func newUpstreamProvider(t *testing.T, st *store.Store, id string) sqlcgen.UpstreamProvider {
	t.Helper()
	now := time.Now().UTC()
	p, err := st.CreateUpstreamProvider(context.Background(), sqlcgen.CreateUpstreamProviderParams{
		ID: id, Name: "Forge " + id, Issuer: "https://" + id + ".example.com", ClientID: "kivraid",
		Scopes: "openid", ClaimEmail: "email", ClaimName: "name", ClaimGroups: "groups",
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
