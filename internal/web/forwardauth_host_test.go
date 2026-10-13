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

// The fully qualified form of a protected host ("app.example.com.", which
// Traefik routes like the bare name) gets the same policy; it used to
// match no application and let any signed-in user through.
func TestForwardAuthTrailingDotHost(t *testing.T) {
	ts, st, c, csrf := adminClient(t)
	ctx := context.Background()
	resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
		"_csrf": {csrf}, "kind": {"proxy"}, "name": {"Vault"}, "proxy_hosts": {"vault.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var appID string
	if err := st.DB.QueryRowContext(ctx, `SELECT id FROM applications WHERE slug = 'vault'`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	grp, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{ID: "ops", Name: "ops", Source: "local", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddAppPolicy(ctx, sqlcgen.AddAppPolicyParams{ApplicationID: appID, GroupID: grp.ID}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplicationRestricted(ctx, sqlcgen.SetApplicationRestrictedParams{Restricted: true, ID: appID}); err != nil {
		t.Fatal(err)
	}
	if _, err := local.NewSource(st).CreateUser(ctx, "eve", "eve@example.com", "Eve", "eve-pass-123", false); err != nil {
		t.Fatal(err)
	}
	eve := newClient(t)
	login(t, eve, ts.URL, "eve", "eve-pass-123")

	for _, host := range []string{"vault.example.com", "vault.example.com.", "VAULT.example.com.:443"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/outpost/auth", nil)
		req.Header.Set("X-Forwarded-Host", host)
		resp, err := eve.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("host %q: want 403 for a non-member, got %d", host, resp.StatusCode)
		}
	}
}

// Protected hosts must be bare host names: anything else would never match
// a request and leave the application without its policy.
func TestProxyHostsValidated(t *testing.T) {
	ts, _, c, csrf := adminClient(t)
	for _, bad := range []string{"https://app.example.com", "app.example.com/", "*.example.com", "user@app.example.com"} {
		resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
			"_csrf": {csrf}, "kind": {"proxy"}, "name": {"App"}, "proxy_hosts": {bad},
		})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusSeeOther || !strings.Contains(string(body), "is not a host name") {
			t.Errorf("%q: want a validation error, got %d", bad, resp.StatusCode)
		}
	}
	resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
		"_csrf": {csrf}, "kind": {"proxy"}, "name": {"App"}, "proxy_hosts": {"App.Example.com.\napp2.example.com:8443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("valid hosts: want 303, got %d", resp.StatusCode)
	}
}
