package pwpolicy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeChecker struct {
	breached bool
	err      error
}

func (f fakeChecker) Breached(context.Context, string) (bool, error) { return f.breached, f.err }

func TestPolicyLength(t *testing.T) {
	ctx := context.Background()
	p := Policy{MinLength: 10}
	if _, err := p.Check(ctx, "123456789", nil); !errors.Is(err, ErrTooShort) {
		t.Errorf("9 characters with min 10: got %v, want ErrTooShort", err)
	}
	if _, err := p.Check(ctx, "1234567890", nil); err != nil {
		t.Errorf("10 characters with min 10: got %v", err)
	}
	// Length counts characters, not bytes: 10 accented letters are 20
	// bytes but still 10 characters, and 9 of them are too short.
	if _, err := p.Check(ctx, "ééééééééé", nil); !errors.Is(err, ErrTooShort) {
		t.Errorf("9 two-byte characters: got %v, want ErrTooShort", err)
	}
	// A minimum below the default is raised to it.
	if _, err := (Policy{MinLength: 4}).Check(ctx, "1234567", nil); !errors.Is(err, ErrTooShort) {
		t.Errorf("7 characters with min 4: got %v, want ErrTooShort", err)
	}
}

func TestPolicyBreach(t *testing.T) {
	ctx := context.Background()
	pw := "correct horse battery staple"

	if _, err := (Policy{MinLength: 8}).Check(ctx, pw, fakeChecker{breached: true}); err != nil {
		t.Errorf("breach check off: got %v", err)
	}
	on := Policy{MinLength: 8, CheckBreached: true}
	if _, err := on.Check(ctx, pw, fakeChecker{breached: true}); !errors.Is(err, ErrBreached) {
		t.Errorf("breached password: got %v, want ErrBreached", err)
	}
	if _, err := on.Check(ctx, pw, fakeChecker{}); err != nil {
		t.Errorf("clean password: got %v", err)
	}
	// An unreachable service fails open and reports why.
	down := errors.New("dial tcp: no route to host")
	unavailable, err := on.Check(ctx, pw, fakeChecker{err: down})
	if err != nil || !errors.Is(unavailable, down) {
		t.Errorf("service down: got unavailable=%v err=%v", unavailable, err)
	}
}

func TestPwnedPasswords(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
	var gotPath, gotPadding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotPadding = r.URL.Path, r.Header.Get("Add-Padding")
		fmt.Fprint(w, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n")
		fmt.Fprint(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n")
		fmt.Fprint(w, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n")
	}))
	defer srv.Close()
	p := &PwnedPasswords{BaseURL: srv.URL, Client: srv.Client()}

	found, err := p.Breached(context.Background(), "password")
	if err != nil || !found {
		t.Fatalf(`"password": found=%v err=%v, want found`, found, err)
	}
	if gotPath != "/range/5BAA6" {
		t.Errorf("only the 5-character prefix may be sent, got path %q", gotPath)
	}
	if gotPadding != "true" {
		t.Errorf("Add-Padding header = %q, want true", gotPadding)
	}
	// A suffix absent from the range is not breached.
	if found, err := p.Breached(context.Background(), "a long and unusual passphrase"); err != nil || found {
		t.Errorf("unknown password: found=%v err=%v", found, err)
	}
}

func TestPwnedPasswordsPaddingEntry(t *testing.T) {
	// SHA-1("password") suffix listed with a padding count of 0.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\r\n")
	}))
	defer srv.Close()
	p := &PwnedPasswords{BaseURL: srv.URL, Client: srv.Client()}
	if found, err := p.Breached(context.Background(), "password"); err != nil || found {
		t.Errorf("padding entry: found=%v err=%v, want not found", found, err)
	}
}

func TestPwnedPasswordsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := &PwnedPasswords{BaseURL: srv.URL, Client: srv.Client()}
	if _, err := p.Breached(context.Background(), "password"); err == nil {
		t.Error("want an error on a 503")
	}
}
