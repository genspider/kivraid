package web

import (
	"io"
	"net/url"
	"strings"
	"testing"
)

// The side menus mark the current page for assistive technologies.
func TestSideMenuMarksCurrentPage(t *testing.T) {
	ts, _, c, _ := adminClient(t)
	for path, link := range map[string]string{
		"/admin/users":          `href="/admin/users" class="sidenav-link sidenav-active" aria-current="page"`,
		"/admin/routing":        `href="/admin/routing" class="sidenav-link sidenav-active" aria-current="page"`,
		"/profile/security":     `href="/profile/security" class="sidenav-link sidenav-active" aria-current="page"`,
		"/admin/settings/email": `href="/admin/settings/email" class="sidenav-link sidenav-active" aria-current="page"`,
	} {
		_, body := getPage(t, c, ts.URL+path)
		if !strings.Contains(body, link) {
			t.Errorf("%s: active side menu entry not marked", path)
		}
		if strings.Count(body, `aria-current="page"`) != 1 {
			t.Errorf("%s: want exactly one current page, got %d", path, strings.Count(body, `aria-current="page"`))
		}
	}
}

// Two-factor enrollment starts from, and returns to, the two-factor page.
func TestMFAEnrollReturnsToSecurityPage(t *testing.T) {
	ts, _, c, csrf := adminClient(t)
	resp, err := c.PostForm(ts.URL+"/profile/mfa/begin", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(b)
	if !strings.Contains(body, "Enable two-factor") {
		t.Fatalf("enrollment page not shown (status %d)", resp.StatusCode)
	}
	if !strings.Contains(body, `<a href="/profile/security" class="btn-ghost">`) || strings.Contains(body, `href="/profile" class="back-link"`) {
		t.Error("enrollment should link back to /profile/security")
	}
}
