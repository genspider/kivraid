package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/mfa"
	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// testInstance writes a configuration backed by a fresh SQLite database
// and returns its path.
func testInstance(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "kivraid.yaml")
	content := "base_url: \"http://localhost:9000\"\n" +
		"secret_key: \"" + strings.Repeat("k", 32) + "\"\n" +
		"database:\n  driver: sqlite\n  dsn: \"" + filepath.Join(dir, "kivraid.db") + "\"\n" +
		"log_level: error\n"
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func openTestStore(t *testing.T, cfgPath string) *userEnv {
	t.Helper()
	env, err := openUserEnv(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	return env
}

func mustUser(t *testing.T, st *store.Store, username string) sqlcgen.User {
	t.Helper()
	u, err := st.GetUserByUsername(context.Background(), username)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUserAddAndResetPassword(t *testing.T) {
	cfg := testInstance(t)
	if err := userAdd([]string{"--config", cfg, "--username", "Admin", "--email", "admin@example.com",
		"--admin", "--password", "first-pass-123"}); err != nil {
		t.Fatal(err)
	}
	// The password policy applies: 8 characters minimum by default.
	if err := userAdd([]string{"--config", cfg, "--username", "bob", "--email", "bob@example.com",
		"--password", "short"}); err == nil || !strings.Contains(err.Error(), "at least 8 characters") {
		t.Fatalf("short password: got %v", err)
	}

	env := openTestStore(t, cfg)
	ctx := context.Background()
	// A stricter minimum set in the admin applies to the CLI too.
	if err := env.store.SetPasswordPolicy(ctx, sqlcgen.SetPasswordPolicyParams{
		PasswordMinLength: 14, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := userResetPassword([]string{"--config", cfg, "--user", "admin", "--password", "only-13-chars"}); err == nil ||
		!strings.Contains(err.Error(), "at least 14 characters") {
		t.Fatalf("reset below the configured minimum: got %v", err)
	}

	// The account is found by email too, and --must-change is honored.
	if err := userResetPassword([]string{"--config", cfg, "--user", "ADMIN@example.com",
		"--password", "a-new-long-passphrase", "--must-change"}); err != nil {
		t.Fatal(err)
	}
	src := local.NewSource(env.store)
	if _, err := src.Authenticate(ctx, "admin", "first-pass-123"); err == nil {
		t.Error("the old password should no longer work")
	}
	if _, err := src.Authenticate(ctx, "admin", "a-new-long-passphrase"); err != nil {
		t.Errorf("the new password should work: %v", err)
	}
	if u := mustUser(t, env.store, "admin"); !u.MustChangePassword {
		t.Error("--must-change should require a new password at next sign-in")
	}

	if err := userResetPassword([]string{"--config", cfg, "--user", "nobody", "--password", "whatever-123456"}); err == nil ||
		!strings.Contains(err.Error(), "no user") {
		t.Errorf("unknown user: got %v", err)
	}
}

func TestUserResetPasswordRefusesDirectoryAccounts(t *testing.T) {
	cfg := testInstance(t)
	env := openTestStore(t, cfg)
	now := time.Now().UTC()
	if _, err := env.store.CreateUser(context.Background(), sqlcgen.CreateUserParams{
		ID: "u-ldap", Username: "dana", Email: "dana@example.com", Name: "Dana",
		Source: "ldap", Active: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := userResetPassword([]string{"--config", cfg, "--user", "dana", "--password", "a-new-long-passphrase"}); err == nil ||
		!strings.Contains(err.Error(), "ldap account") {
		t.Fatalf("directory account: got %v", err)
	}
}

func TestUserResetMFA(t *testing.T) {
	cfg := testInstance(t)
	env := openTestStore(t, cfg)
	ctx := context.Background()
	user, err := local.NewSource(env.store).CreateUser(ctx, "admin", "admin@example.com", "Admin", "first-pass-123", true)
	if err != nil {
		t.Fatal(err)
	}
	m := mfa.NewManager(env.store, secrets.DeriveKey(env.cfg.SecretKey, "totp-secrets"))
	secret, err := m.GenerateSecret(user.Username)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(ctx, user.ID, secret, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GenerateRecoveryCodes(ctx, user.ID); err != nil {
		t.Fatal(err)
	}

	if err := userResetMFA([]string{"--config", cfg, "--user", "admin"}); err != nil {
		t.Fatal(err)
	}
	if u := mustUser(t, env.store, "admin"); u.TotpEnabled {
		t.Error("two-factor should be off after reset-mfa")
	}
	if n, err := m.RemainingRecoveryCodes(ctx, user.ID); err != nil || n != 0 {
		t.Errorf("recovery codes should be dropped, %d left (err %v)", n, err)
	}
	// Running it again is harmless.
	if err := userResetMFA([]string{"--config", cfg, "--user", "admin"}); err != nil {
		t.Errorf("second reset: %v", err)
	}
}

func TestUserPromote(t *testing.T) {
	cfg := testInstance(t)
	env := openTestStore(t, cfg)
	ctx := context.Background()
	user, err := local.NewSource(env.store).CreateUser(ctx, "carol", "carol@example.com", "Carol", "first-pass-123", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.UpdateUserFlags(ctx, sqlcgen.UpdateUserFlagsParams{
		IsAdmin: false, Active: false, UpdatedAt: time.Now().UTC(), ID: user.ID,
	}); err != nil {
		t.Fatal(err)
	}

	if err := userPromote([]string{"--config", cfg, "--user", "carol"}); err != nil {
		t.Fatal(err)
	}
	if u := mustUser(t, env.store, "carol"); !u.IsAdmin || !u.Active {
		t.Errorf("promote: want an active administrator, got admin=%v active=%v", u.IsAdmin, u.Active)
	}
	if err := userList([]string{"--config", cfg}); err != nil {
		t.Errorf("list: %v", err)
	}
}

// A reset from the command line revokes the user's sessions and tokens.
func TestUserResetRevokesAccess(t *testing.T) {
	cfg := testInstance(t)
	env := openTestStore(t, cfg)
	ctx := context.Background()
	user, err := local.NewSource(env.store).CreateUser(ctx, "admin", "admin@example.com", "Admin", "first-pass-123", true)
	if err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager(env.store.DB, env.store.Driver, false, time.Hour, 0)
	sctx, err := sm.Load(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	sm.Put(sctx, session.KeyUserID, user.ID)
	token, _, err := sm.Commit(sctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := env.store.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
		ID: "rt1", UserID: user.ID, ClientID: "c", Scopes: "[]", Audience: "[]", Amr: "[]",
		AuthTime: now, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := userResetPassword([]string{"--config", cfg, "--user", "admin", "--password", "a-new-long-passphrase"}); err != nil {
		t.Fatal(err)
	}
	sctx, err = sm.Load(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if sm.GetString(sctx, session.KeyUserID) != "" {
		t.Error("the session should be revoked")
	}
	var n int
	if err := env.store.DB.QueryRow(`SELECT COUNT(*) FROM refresh_tokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("refresh tokens left: %d (err %v)", n, err)
	}
}

// --user refuses to guess when a value is one account's username and
// another's email.
func TestFindUserAmbiguous(t *testing.T) {
	cfg := testInstance(t)
	env := openTestStore(t, cfg)
	ctx := context.Background()
	src := local.NewSource(env.store)
	if _, err := src.CreateUser(ctx, "boss@corp.example", "first@corp.example", "First", "first-pass-123", false); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateUser(ctx, "second", "boss@corp.example", "Second", "second-pass-123", false); err != nil {
		t.Fatal(err)
	}
	if err := userPromote([]string{"--config", cfg, "--user", "boss@corp.example"}); err == nil || !strings.Contains(err.Error(), "pass the username") {
		t.Fatalf("ambiguous --user: got %v", err)
	}
	for _, name := range []string{"boss@corp.example", "second"} {
		if u := mustUser(t, env.store, name); u.IsAdmin {
			t.Errorf("%s was promoted", name)
		}
	}
	if err := userPromote([]string{"--config", cfg, "--user", "second"}); err != nil {
		t.Fatal(err)
	}
}
