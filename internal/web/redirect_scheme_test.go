package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Redirect URIs that would run script where the browser follows them are
// refused; native custom schemes stay allowed.
func TestRedirectURISchemes(t *testing.T) {
	ts, _, c, csrf := adminClient(t)
	for uri, ok := range map[string]bool{
		"javascript:alert(document.domain)//": false,
		"data:text/html,<script>x</script>":   false,
		"JavaScript:alert(1)":                 false,
		"https://app.example.com/callback":    true,
		"com.example.app:/oauth2redirect":     true,
	} {
		resp, err := c.PostForm(ts.URL+"/admin/applications", url.Values{
			"_csrf": {csrf}, "name": {"App " + uri[:4]}, "client_type": {"public"}, "redirect_uris": {uri},
		})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		created := resp.StatusCode == http.StatusOK && !strings.Contains(string(body), "is not an absolute URI")
		if created != ok {
			t.Errorf("%q: accepted=%v, want %v (status %d)", uri, created, ok, resp.StatusCode)
		}
	}
}
