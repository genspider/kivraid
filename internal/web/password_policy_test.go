package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/storetest"
)

// fakeBreaches reports the passwords in leaked as breached, or fails every
// lookup when err is set.
type fakeBreaches struct {
	leaked map[string]bool
	err    error
}

func (f fakeBreaches) Breached(_ context.Context, pw string) (bool, error) {
	return f.leaked[pw], f.err
}

func savePasswordPolicy(t *testing.T, c *http.Client, baseURL, csrf, minLen string, breachCheck bool) {
	t.Helper()
	form := url.Values{
		"_csrf": {csrf}, "mfa_policy": {mfaPolicyOff}, "key_rotation_days": {"0"},
		"audit_retention_days": {"90"}, "password_min_length": {minLen},
	}
	if breachCheck {
		form.Set("password_breach_check", "on")
	}
	resp, err := c.PostForm(baseURL+"/admin/settings/security", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save password policy: want 303, got %d", resp.StatusCode)
	}
}

func changePassword(t *testing.T, c *http.Client, baseURL, csrf, current, newPW string) (int, string) {
	t.Helper()
	resp, err := c.PostForm(baseURL+"/profile/password", url.Values{
		"_csrf": {csrf}, "current_password": {current},
		"new_password": {newPW}, "confirm_password": {newPW},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestPasswordPolicyEnforced(t *testing.T) {
	st := storetest.Open(t)
	breaches := fakeBreaches{leaked: map[string]bool{"password1234": true}}
	ts := newServerForStore(t, st, nil, func(d *Deps) { d.Breaches = breaches })
	ctx := context.Background()
	for _, u := range []struct {
		name  string
		admin bool
	}{{"root", true}, {"bob", false}} {
		if _, err := local.NewSource(st).CreateUser(ctx, u.name, u.name+"@example.com", u.name, u.name+"-pass-123", u.admin); err != nil {
			t.Fatal(err)
		}
	}
	admin := newClient(t)
	login(t, admin, ts.URL, "root", "root-pass-123")
	adminCSRF := fetchCSRFFromPage(t, admin, ts.URL+"/admin/settings/security")
	savePasswordPolicy(t, admin, ts.URL, adminCSRF, "12", true)

	// The settings page reflects the saved policy, and password inputs
	// carry the new minimum.
	if _, body := getPage(t, admin, ts.URL+"/admin/settings/security"); !strings.Contains(body, `<option value="12" selected>`) ||
		!strings.Contains(body, `name="password_breach_check" class="mt-0.5 accent-accent" checked`) {
		t.Error("security settings should show the saved password policy")
	}

	bobUser, err := st.GetUserByUsername(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, body := getPage(t, admin, ts.URL+"/admin/users/"+bobUser.ID); !strings.Contains(body, `minlength="12"`) {
		t.Error("password inputs should use the configured minimum length")
	}

	bob := newClient(t)
	login(t, bob, ts.URL, "bob", "bob-pass-123")
	csrf := fetchCSRFFromPage(t, bob, ts.URL+"/profile")

	// 11 characters: too short under a 12-character minimum.
	if status, body := changePassword(t, bob, ts.URL, csrf, "bob-pass-123", "eleven-char"); status != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "at least 12 characters") {
		t.Fatalf("short password: got %d", status)
	}
	// Long enough but leaked.
	if status, body := changePassword(t, bob, ts.URL, csrf, "bob-pass-123", "password1234"); status != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "known data breach") {
		t.Fatalf("breached password: got %d", status)
	}
	// Long enough and clean.
	if status, _ := changePassword(t, bob, ts.URL, csrf, "bob-pass-123", "a-clean-passphrase"); status != http.StatusSeeOther {
		t.Fatalf("valid password: want 303, got %d", status)
	}

	// Administrator-set passwords follow the same policy.
	resp, err := admin.PostForm(ts.URL+"/admin/users", url.Values{
		"_csrf": {adminCSRF}, "username": {"carol"}, "email": {"carol@example.com"}, "password": {"short-pass"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "at least 12 characters") {
		t.Errorf("admin-created user with a short password: got %d", resp.StatusCode)
	}
}

// When the breach service cannot be reached, passwords are accepted.
func TestPasswordPolicyBreachServiceDown(t *testing.T) {
	st := storetest.Open(t)
	ts := newServerForStore(t, st, nil, func(d *Deps) {
		d.Breaches = fakeBreaches{err: errors.New("no route to host")}
	})
	ctx := context.Background()
	if _, err := local.NewSource(st).CreateUser(ctx, "root", "root@example.com", "Root", "root-pass-123", true); err != nil {
		t.Fatal(err)
	}
	c := newClient(t)
	login(t, c, ts.URL, "root", "root-pass-123")
	csrf := fetchCSRFFromPage(t, c, ts.URL+"/admin/settings/security")
	savePasswordPolicy(t, c, ts.URL, csrf, "8", true)
	if status, _ := changePassword(t, c, ts.URL, csrf, "root-pass-123", "another-pass-456"); status != http.StatusSeeOther {
		t.Fatalf("breach service down: want the password accepted (303), got %d", status)
	}
}
