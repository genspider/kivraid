package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Alternating the username and the email address of an account draws on
// the same failure budget.
func TestLoginThrottleSharedAcrossIdentifiers(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	attempt := func(identifier string) int {
		t.Helper()
		csrf := identify(t, c, ts.URL, identifier, "")
		resp := passwordStep(t, c, ts.URL, csrf, "wrong-password")
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := range 5 {
		id := "alice"
		if i%2 == 1 {
			id = "alice@example.com"
		}
		if code := attempt(id); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, code)
		}
	}
	if code := attempt("alice@example.com"); code != http.StatusTooManyRequests {
		t.Errorf("6th failure across both identifiers: want 429, got %d", code)
	}
}

// Code checks on the two-factor page are throttled like sign-in.
func TestProfileTOTPChecksThrottled(t *testing.T) {
	ts, _, c, csrf := adminClient(t)
	enrollTOTP(t, ts, c, csrf)
	var body string
	for range 6 {
		resp, err := c.PostForm(ts.URL+"/profile/mfa/disable", url.Values{"_csrf": {csrf}, "code": {"000000"}})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body = string(b)
	}
	if !strings.Contains(body, "Too many attempts") {
		t.Error("repeated wrong codes on the two-factor page should be throttled")
	}
}
