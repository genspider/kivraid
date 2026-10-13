package web

import (
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// configureSMTP points the instance at a mail server.
func configureSMTP(t *testing.T, c *http.Client, baseURL, csrf, addr string) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	resp, err := c.PostForm(baseURL+"/admin/settings/email", url.Values{
		"_csrf": {csrf}, "enabled": {"on"}, "host": {host}, "port": {port}, "encryption": {"none"},
		"from_address": {"kivraid@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("SMTP settings: want 303, got %d", resp.StatusCode)
	}
}

// The forgot-password answer must not wait for the mail server: a slow
// answer for existing accounts only would reveal which accounts exist.
func TestForgotDoesNotWaitForMail(t *testing.T) {
	ts, _, admin, csrf := adminClient(t)

	// A mail server that accepts connections and never answers.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	configureSMTP(t, admin, ts.URL, csrf, l.Addr().String())

	c := newClient(t)
	formCSRF := fetchCSRF(t, c, ts.URL+"/forgot")
	start := time.Now()
	resp, err := c.PostForm(ts.URL+"/forgot", url.Values{"_csrf": {formCSRF}, "identifier": {"root"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("forgot for an existing account took %v: it waits for the mail server", elapsed)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want the neutral page, got %d", resp.StatusCode)
	}
}

// The reset email is still delivered, from the background.
func TestForgotStillSendsMail(t *testing.T) {
	ts, _, admin, csrf := adminClient(t)
	smtp := startFakeSMTP(t)
	configureSMTP(t, admin, ts.URL, csrf, smtp.addr)
	c := newClient(t)
	formCSRF := fetchCSRF(t, c, ts.URL+"/forgot")
	resp, err := c.PostForm(ts.URL+"/forgot", url.Values{"_csrf": {formCSRF}, "identifier": {"root"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	select {
	case <-smtp.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no reset email delivered")
	}
}
