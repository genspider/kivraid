package mfa

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
	"github.com/kivraid/kivraid/internal/store/storetest"
)

// A recovery code is single use, even when several requests race with it.
func TestRecoveryCodeSingleUseUnderRace(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	user, err := local.NewSource(st).CreateUser(ctx, "alice", "alice@example.com", "Alice", "alice-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(st, secrets.DeriveKey(strings.Repeat("k", 32), "totp-secrets"))
	codes, err := m.GenerateRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}

	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if used, err := m.ConsumeRecoveryCode(ctx, user.ID, codes[0]); err == nil && used {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("the same recovery code was accepted %d times", ok.Load())
	}

	// The claim itself refuses a code already marked used.
	rows, err := st.ListUnusedRecoveryCodes(ctx, user.ID)
	if err != nil || len(rows) == 0 {
		t.Fatal(err)
	}
	mark := func() int64 {
		n, err := st.MarkRecoveryCodeUsed(ctx, sqlcgen.MarkRecoveryCodeUsedParams{
			UsedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}, ID: rows[0].ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if mark() != 1 || mark() != 0 {
		t.Error("marking a used code again must affect no row")
	}
}
