package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// appBrowser simulates the browser's side of an application host behind a
// proxy: its own cookie jar for that host, and every request to it going
// through the proxy's forward-auth subrequest.
type appBrowser struct {
	t       *testing.T
	kivraid string            // Kivraid's base URL
	host    string            // the application's host
	cookies map[string]string // cookies the browser holds for host
}

func newAppBrowser(t *testing.T, kivraid, host string) *appBrowser {
	return &appBrowser{t: t, kivraid: kivraid, host: host, cookies: map[string]string{}}
}

// visit sends the forward-auth subrequest for uri on the application's
// host, applies the Set-Cookie headers the proxy relays back, and returns
// the response.
func (b *appBrowser) visit(uri string) *http.Response {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.kivraid+"/outpost/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", b.host)
	req.Header.Set("X-Forwarded-Uri", uri)
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		b.t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return resp
}

// signIn follows the exchange for uri: the application redirects to
// Kivraid's start, Kivraid (where the browser is signed in) redirects to
// the callback on the application's host, which sets the session cookie.
func (b *appBrowser) signIn(kivraidBrowser *http.Client, uri string) {
	b.t.Helper()
	resp := b.visit(uri)
	start := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(start, "http://localhost/outpost/start?") {
		b.t.Fatalf("anonymous visit: want a redirect to the start, got %d %q", resp.StatusCode, start)
	}
	startURL, _ := url.Parse(start)
	resp, err := kivraidBrowser.Get(b.kivraid + startURL.RequestURI())
	if err != nil {
		b.t.Fatal(err)
	}
	resp.Body.Close()
	callback, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || callback.Host != b.host || callback.Path != forwardAuthCallbackPath {
		b.t.Fatalf("start: want a redirect to the callback on %s, got %d %q", b.host, resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = b.visit(callback.RequestURI())
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://"+b.host+uri {
		b.t.Fatalf("callback: want a redirect to the original page, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if b.cookies[forwardAuthCookie] == "" {
		b.t.Fatal("callback: no session cookie for the application host")
	}
}

func newForwardAuthTest(t *testing.T) (*httptest.Server, *http.Client, *appBrowser, func() *http.Client) {
	t.Helper()
	ts, _ := buildTestServer(t, []string{".example.com"})
	kivraid := newClient(t)
	login(t, kivraid, ts.URL, "alice", "s3cret-pass")
	return ts, kivraid, newAppBrowser(t, ts.URL, "app.example.com"), func() *http.Client { return newClient(t) }
}

func TestForwardAuthCodeExchange(t *testing.T) {
	ts, kivraid, app, _ := newForwardAuthTest(t)
	app.signIn(kivraid, "/dashboards?x=1")

	resp := app.visit("/dashboards?x=1")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Remote-User") != "alice" {
		t.Fatalf("with the application session: want 200 as alice, got %d %q", resp.StatusCode, resp.Header.Get("Remote-User"))
	}

	// The application cookie is only good on the host it was issued for.
	other := newAppBrowser(t, ts.URL, "other.example.com")
	other.cookies = app.cookies
	if resp := other.visit("/"); resp.StatusCode == http.StatusOK {
		t.Error("an application session must not authenticate another host")
	}

	// Signing out of Kivraid ends it.
	csrf := fetchCSRFFromPage(t, kivraid, ts.URL+"/profile")
	out, err := kivraid.PostForm(ts.URL+"/logout", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	out.Body.Close()
	if resp := app.visit("/dashboards"); resp.StatusCode == http.StatusOK {
		t.Error("the application session should end with the Kivraid session")
	}
}

// A code is single use, bound to its host and to the browser that holds
// the state cookie.
func TestForwardAuthCodeBinding(t *testing.T) {
	ts, kivraid, app, _ := newForwardAuthTest(t)
	resp := app.visit("/")
	startURL, _ := url.Parse(resp.Header.Get("Location"))
	resp, err := kivraid.Get(ts.URL + startURL.RequestURI())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	callback, _ := url.Parse(resp.Header.Get("Location"))

	// Another browser (no state cookie, as in a login CSRF) cannot use it.
	victim := newAppBrowser(t, ts.URL, "app.example.com")
	if resp := victim.visit(callback.RequestURI()); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("code without the state cookie: want 400, got %d", resp.StatusCode)
	}
	// Nor can it be replayed once spent (the attempt above consumed it).
	if resp := app.visit(callback.RequestURI()); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("spent code: want 400, got %d", resp.StatusCode)
	}

	// A code issued for one host is refused on another.
	resp = app.visit("/")
	startURL, _ = url.Parse(resp.Header.Get("Location"))
	resp, _ = kivraid.Get(ts.URL + startURL.RequestURI())
	resp.Body.Close()
	callback, _ = url.Parse(resp.Header.Get("Location"))
	elsewhere := newAppBrowser(t, ts.URL, "other.example.com")
	elsewhere.cookies = app.cookies
	if resp := elsewhere.visit(callback.RequestURI()); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("code on another host: want 400, got %d", resp.StatusCode)
	}

	// A start for a host outside forward_auth.domains is refused.
	resp, _ = kivraid.Get(ts.URL + "/outpost/start?" + url.Values{
		"rd": {"https://evil.test/"}, "state": {"0123456789abcdef0123"},
	}.Encode())
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("start for an unlisted host: want 400, got %d", resp.StatusCode)
	}
}

// Policies keep applying with an application session: a restricted
// application refuses non-members, and its two-factor requirement sends a
// password-only session back through the start.
func TestForwardAuthAppSessionPolicies(t *testing.T) {
	ts, st := buildTestServer(t, []string{".example.com"})
	ctx := context.Background()
	kivraid := newClient(t)
	login(t, kivraid, ts.URL, "alice", "s3cret-pass")
	now := time.Now().UTC()
	app, err := st.CreateApplication(ctx, sqlcgen.CreateApplicationParams{
		ID: "vault", Name: "Vault", Slug: "vault", Kind: "proxy", ProxyHosts: `["vault.example.com"]`,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	b := newAppBrowser(t, ts.URL, "vault.example.com")
	b.signIn(kivraid, "/")
	if resp := b.visit("/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("open application: want 200, got %d", resp.StatusCode)
	}

	if _, err := st.DB.Exec(`UPDATE applications SET require_mfa = TRUE WHERE id = $1`, app.ID); err != nil {
		t.Fatal(err)
	}
	resp := b.visit("/")
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/outpost/start?") {
		t.Errorf("two-factor required: want a redirect to the start, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, err := st.DB.Exec(`UPDATE applications SET require_mfa = FALSE, restricted = TRUE WHERE id = $1`, app.ID); err != nil {
		t.Fatal(err)
	}
	if resp := b.visit("/"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("restricted application: want 403, got %d", resp.StatusCode)
	}
}

// nginx routes the callback path straight to /outpost/callback.
func TestForwardAuthDirectCallback(t *testing.T) {
	ts, kivraid, app, _ := newForwardAuthTest(t)
	resp := app.visit("/")
	startURL, _ := url.Parse(resp.Header.Get("Location"))
	resp, _ = kivraid.Get(ts.URL + startURL.RequestURI())
	resp.Body.Close()
	callback, _ := url.Parse(resp.Header.Get("Location"))

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/outpost/callback?"+callback.RawQuery, nil)
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.AddCookie(&http.Cookie{Name: forwardAuthStateCookie, Value: app.cookies[forwardAuthStateCookie]})
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var session string
	for _, c := range resp.Cookies() {
		if c.Name == forwardAuthCookie {
			session = c.Value
		}
	}
	if resp.StatusCode != http.StatusFound || session == "" {
		t.Fatalf("direct callback: want a redirect with the session cookie, got %d", resp.StatusCode)
	}
	app.cookies[forwardAuthCookie] = session
	if resp := app.visit("/"); resp.StatusCode != http.StatusOK {
		t.Errorf("with the session from the direct callback: want 200, got %d", resp.StatusCode)
	}
}

// nginx's auth_request only understands 2xx, 401 and 403: its endpoint
// answers 401 where the others redirect.
func TestForwardAuthNginxEndpoint(t *testing.T) {
	ts, _ := buildTestServer(t, []string{".example.com"})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/outpost/auth/nginx", nil)
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Uri", "/")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous on the nginx endpoint: want 401, got %d", resp.StatusCode)
	}
}
