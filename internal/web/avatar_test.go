package web

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// The public avatar route sits outside the security-headers middleware: it
// must only ever serve images, with nosniff and a sandboxing CSP.
func TestPublicAvatarServesOnlyImages(t *testing.T) {
	ts, st := buildTestServer(t, nil)
	ctx := context.Background()
	alice, err := st.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	setPhoto := func(data, mime string) {
		t.Helper()
		if err := st.UpdateUserPhoto(ctx, sqlcgen.UpdateUserPhotoParams{
			Photo: []byte(data), PhotoMime: &mime, UpdatedAt: time.Now().UTC(), ID: alice.ID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	get := func() *http.Response {
		t.Helper()
		resp, err := http.Get(ts.URL + "/oidc/avatar/" + alice.ID)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	// A row stored before photos were restricted to images is not served.
	setPhoto("<script>alert(1)</script>", "text/html; charset=utf-8")
	if resp := get(); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("HTML photo: want 404, got %d (%s)", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	setPhoto("\x89PNG\r\n\x1a\nfake", "image/png")
	resp := get()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("PNG photo: got %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("missing nosniff/CSP: %v", resp.Header)
	}
}
