package web

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Request bodies are capped before anything reads them: an anonymous
// client cannot make the server buffer an arbitrarily large body.
func TestRequestBodiesAreLimited(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t)
	csrf := fetchCSRF(t, c, ts.URL+"/login")

	// Declared too large: refused before reading.
	big := bytes.Repeat([]byte("A"), maxBodySize+1)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/login/passkey/finish", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized JSON body: want 413, got %d", resp.StatusCode)
	}

	// Streamed without a length: cut off at the limit, so the request fails
	// instead of being buffered whole.
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/login/passkey/finish",
		io.MultiReader(strings.NewReader(`{"id":"`), io.LimitReader(zeros{}, 8*maxBodySize), strings.NewReader(`"}`)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = c.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("streamed oversized body: want an error status, got %d", resp.StatusCode)
		}
	}

	// A normal form still works.
	resp, err = c.Post(ts.URL+"/login", "application/x-www-form-urlencoded",
		strings.NewReader("_csrf="+csrf+"&username=alice"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("normal login form: want 303, got %d", resp.StatusCode)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '0'
	}
	return len(p), nil
}
