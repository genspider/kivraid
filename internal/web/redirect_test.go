package web

import (
	"net/http"
	"strings"
	"testing"
)

func TestIsLocalPath(t *testing.T) {
	for next, want := range map[string]bool{
		"/profile":           true,
		"/oidc/resume?id=x":  true,
		"/a/b?c=d#e":         true,
		"/":                  false,
		"":                   false,
		"//evil.example":     false,
		"/\\evil.example":    false,
		"/\t/evil.example":   false, // browsers drop the tab: //evil.example
		"/\n/evil.example":   false,
		"/\r\n/evil.example": false,
		"/x\x7f":             false,
		"https://evil.test":  false,
		"evil.example":       false,
	} {
		if got := isLocalPath(next); got != want {
			t.Errorf("isLocalPath(%q) = %v, want %v", next, got, want)
		}
	}
}

// The language switcher redirects anonymous visitors to next: a tab must
// not smuggle a protocol-relative URL through it.
func TestLangNextRejectsControlCharacters(t *testing.T) {
	ts := newTestServer(t)
	resp, err := newClient(t).Get(ts.URL + "/lang?set=fr&next=%2F%09%2Fevil.example")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "evil.example") {
		t.Fatalf("open redirect: Location %q (status %d)", loc, resp.StatusCode)
	}
	if resp.StatusCode < http.StatusMultipleChoices || resp.StatusCode >= http.StatusBadRequest {
		t.Errorf("want a redirect to a safe default, got %d", resp.StatusCode)
	}
}
