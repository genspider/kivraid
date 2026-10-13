package web

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// An unknown icon name renders the "question" fallback without any error,
// so a typo in a template would go unnoticed: check every name used.
func TestTemplateIconsExist(t *testing.T) {
	iconCall := regexp.MustCompile(`[{(\s]icon\s+"([^"]+)"`)
	files, err := filepath.Glob("templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	used := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range iconCall.FindAllStringSubmatch(string(b), -1) {
			used++
			if _, ok := iconPaths[m[1]]; !ok {
				t.Errorf("%s: unknown icon %q", f, m[1])
			}
		}
	}
	if used == 0 {
		t.Fatal("no icon calls found in the templates; the pattern is out of date")
	}
}
