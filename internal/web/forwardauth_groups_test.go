package web

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// A group name containing a comma must not read as several groups in the
// comma-separated Remote-Groups header.
func TestForwardAuthGroupsWithComma(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	ctx := context.Background()
	alice, err := st.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"staff", "staff,admins"} {
		g, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{ID: "g-" + name, Name: name, Source: "local", CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddUserGroup(ctx, sqlcgen.AddUserGroupParams{UserID: alice.ID, GroupID: g.ID}); err != nil {
			t.Fatal(err)
		}
	}
	c := newClient(t)
	login(t, c, ts.URL, "alice", "s3cret-pass")
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/outpost/auth", nil)
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Remote-Groups"); got != "staff" {
		t.Errorf("Remote-Groups: got %q, want %q", got, "staff")
	}
}
