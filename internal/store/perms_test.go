//go:build !windows

package store

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The SQLite database holds session tokens and password hashes: it must
// not be readable by other local users, whatever the umask.
func TestSQLiteFilesOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "kivraid.db")
	st, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, f := range []string{path, path + "-wal"} {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s: mode %o, want no group or other access", filepath.Base(f), perm)
		}
	}
}
