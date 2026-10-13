package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/config"
	"github.com/kivraid/kivraid/internal/mfa"
	"github.com/kivraid/kivraid/internal/oidcserver"
	"github.com/kivraid/kivraid/internal/pwpolicy"
	"github.com/kivraid/kivraid/internal/secrets"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/sources/local"
	"github.com/kivraid/kivraid/internal/store"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// cliActor is the audit-log actor for changes made from the command line.
const cliActor = "cli"

// userCommands are the "kivraid user ..." subcommands.
var userCommands = map[string]func(args []string) error{
	"add":            userAdd,
	"list":           userList,
	"reset-password": userResetPassword,
	"reset-mfa":      userResetMFA,
	"promote":        userPromote,
}

// userEnv is what every user subcommand works with: the configuration,
// the open store and the audit recorder.
type userEnv struct {
	cfg   config.Config
	store *store.Store
	audit *audit.Recorder
}

func openUserEnv(ctx context.Context, cfgPath string) (*userEnv, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return nil, err
	}
	return &userEnv{cfg: cfg, store: st, audit: audit.NewRecorder(st, newLogger(cfg.LogLevel))}, nil
}

func (e *userEnv) Close() { e.store.Close() }

// findUser looks an account up by username, then by email address.
func (e *userEnv) findUser(ctx context.Context, ident string) (sqlcgen.User, error) {
	ident = strings.ToLower(strings.TrimSpace(ident))
	if ident == "" {
		return sqlcgen.User{}, errors.New("--user is required")
	}
	byName, nameErr := e.store.GetUserByUsername(ctx, ident)
	if nameErr != nil && !errors.Is(nameErr, sql.ErrNoRows) {
		return sqlcgen.User{}, nameErr
	}
	byEmail, emailErr := e.store.GetUserByEmail(ctx, ident)
	if emailErr != nil && !errors.Is(emailErr, sql.ErrNoRows) {
		return sqlcgen.User{}, emailErr
	}
	switch {
	case nameErr == nil && emailErr == nil && byName.ID != byEmail.ID:
		// Usernames may look like email addresses: one account's username
		// can be another's email. Promoting or resetting the wrong one is
		// not something to guess.
		return sqlcgen.User{}, fmt.Errorf("%q is the username of %s and the email of %s; pass the username of the account you mean",
			ident, byName.Username, byEmail.Username)
	case nameErr == nil:
		return byName, nil
	case emailErr == nil:
		return byEmail, nil
	}
	return sqlcgen.User{}, fmt.Errorf("no user with username or email %q (see \"kivraid user list\")", ident)
}

// checkPassword applies the instance password policy (Settings → Security)
// to a password chosen on the command line.
func (e *userEnv) checkPassword(ctx context.Context, pw string) error {
	settings, err := e.store.GetInstanceSettings(ctx)
	if err != nil {
		return err
	}
	policy := pwpolicy.Policy{MinLength: int(settings.PasswordMinLength), CheckBreached: settings.PasswordBreachCheck}
	unavailable, err := policy.Check(ctx, pw, pwpolicy.NewPwnedPasswords())
	if unavailable != nil {
		fmt.Fprintln(os.Stderr, "warning: breach check unavailable, password accepted:", unavailable)
	}
	switch {
	case errors.Is(err, pwpolicy.ErrTooShort):
		return fmt.Errorf("password must be at least %d characters", max(policy.MinLength, pwpolicy.DefaultMinLength))
	case errors.Is(err, pwpolicy.ErrBreached):
		return errors.New("this password appears in a known data breach; choose a different one")
	}
	return err
}

// revokeAccess signs the user out everywhere, as the admin's "sign out
// everywhere" does: Kivraid sessions, OAuth tokens, and the applications
// that support back-channel logout. A reset from the command line is often
// a response to a compromise, which a still-valid session would outlive.
func (e *userEnv) revokeAccess(ctx context.Context, userID string) error {
	sessions := session.NewManager(e.store.DB, e.store.Driver, false,
		time.Duration(e.cfg.Session.Lifetime), time.Duration(e.cfg.Session.IdleTimeout))
	if err := sessions.Iterate(ctx, func(sctx context.Context) error {
		if sessions.GetString(sctx, session.KeyUserID) == userID {
			return sessions.Store.Delete(sessions.Token(sctx))
		}
		return nil
	}); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	if err := e.store.DeleteAccessTokensByUser(ctx, userID); err != nil {
		return err
	}
	if err := e.store.DeleteRefreshTokensByUser(ctx, userID); err != nil {
		return err
	}
	log := newLogger(e.cfg.LogLevel)
	_, storage, err := oidcserver.New(ctx, e.cfg, e.store, log)
	if err != nil {
		return fmt.Errorf("back-channel logout: %w", err)
	}
	backchannel := oidcserver.NewBackchannelLogout(storage, log)
	backchannel.User(ctx, userID)
	backchannel.Wait()
	return nil
}

// readPassword returns the --password value, or prompts for one.
func readPassword(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return promptPassword()
}

func userAdd(args []string) error {
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	cfgPath := fs.String("config", "kivraid.yaml", "path to the configuration file")
	username := fs.String("username", "", "login name (required)")
	email := fs.String("email", "", "email address (required)")
	name := fs.String("name", "", "display name")
	admin := fs.Bool("admin", false, "grant administrator rights")
	password := fs.String("password", "", "password (omit to be prompted; prefer the prompt)")
	fs.Parse(args)

	if *username == "" || *email == "" {
		return errors.New("--username and --email are required")
	}
	if *name == "" {
		*name = *username
	}

	// Open the instance before prompting: a missing config or database
	// should fail fast, not after the password has been typed twice.
	ctx := context.Background()
	env, err := openUserEnv(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer env.Close()

	pw, err := readPassword(*password)
	if err != nil {
		return err
	}
	if err := env.checkPassword(ctx, pw); err != nil {
		return err
	}

	user, err := local.NewSource(env.store).CreateUser(ctx, *username, *email, *name, pw, *admin)
	if err != nil {
		return err
	}
	// An operator-created account has an operator-attested email.
	if err := env.store.SetEmailVerified(ctx, sqlcgen.SetEmailVerifiedParams{
		EmailVerified: true, UpdatedAt: time.Now().UTC(), ID: user.ID,
	}); err != nil {
		return err
	}
	env.audit.Record(ctx, cliActor, audit.ActionUserCreate, user.Username, "", "")
	fmt.Printf("created user %s (%s)\n", user.Username, user.ID)
	return nil
}

func userList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	cfgPath := fs.String("config", "kivraid.yaml", "path to the configuration file")
	fs.Parse(args)

	ctx := context.Background()
	env, err := openUserEnv(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer env.Close()

	users, err := env.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	viaGroup, err := env.store.ListAdminGroupMemberIDs(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tEMAIL\tSOURCE\tADMIN\tACTIVE\tAUTHENTICATOR")
	for _, u := range users {
		admin := yesNo(u.IsAdmin)
		if !u.IsAdmin && slices.Contains(viaGroup, u.ID) {
			admin = "via group"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			u.Username, u.Email, u.Source, admin, yesNo(u.Active), yesNo(u.TotpEnabled))
	}
	return tw.Flush()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func userResetPassword(args []string) error {
	fs := flag.NewFlagSet("user reset-password", flag.ExitOnError)
	cfgPath := fs.String("config", "kivraid.yaml", "path to the configuration file")
	ident := fs.String("user", "", "username or email of the account (required)")
	password := fs.String("password", "", "new password (omit to be prompted; prefer the prompt)")
	mustChange := fs.Bool("must-change", false, "require a new password at the next sign-in")
	fs.Parse(args)

	ctx := context.Background()
	env, err := openUserEnv(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer env.Close()

	user, err := env.findUser(ctx, *ident)
	if err != nil {
		return err
	}
	if user.Source != "local" {
		return fmt.Errorf("%s is a %s account: change its password in its directory or identity provider", user.Username, user.Source)
	}
	pw, err := readPassword(*password)
	if err != nil {
		return err
	}
	if err := env.checkPassword(ctx, pw); err != nil {
		return err
	}
	if err := local.NewSource(env.store).SetPassword(ctx, user.ID, pw); err != nil {
		return err
	}
	if *mustChange {
		if err := env.store.SetUserMustChangePassword(ctx, sqlcgen.SetUserMustChangePasswordParams{
			MustChangePassword: true, ID: user.ID,
		}); err != nil {
			return err
		}
	}
	if err := env.revokeAccess(ctx, user.ID); err != nil {
		return err
	}
	env.audit.Record(ctx, cliActor, audit.ActionUserPWReset, user.Username, "", "")
	fmt.Printf("password reset for %s; their sessions and tokens were revoked\n", user.Username)
	if !user.Active {
		fmt.Printf("note: %s is deactivated; run \"kivraid user promote\" or reactivate it in the admin to let it sign in\n", user.Username)
	}
	return nil
}

func userResetMFA(args []string) error {
	fs := flag.NewFlagSet("user reset-mfa", flag.ExitOnError)
	cfgPath := fs.String("config", "kivraid.yaml", "path to the configuration file")
	ident := fs.String("user", "", "username or email of the account (required)")
	fs.Parse(args)

	ctx := context.Background()
	env, err := openUserEnv(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer env.Close()

	user, err := env.findUser(ctx, *ident)
	if err != nil {
		return err
	}
	if !user.TotpEnabled {
		fmt.Printf("%s has no authenticator app enrolled; nothing to reset\n", user.Username)
		return nil
	}
	// Same effect as the admin's "Reset two-factor": the secret and the
	// recovery codes are dropped. Passkeys are kept.
	if err := mfa.NewManager(env.store, secrets.DeriveKey(env.cfg.SecretKey, "totp-secrets")).Disable(ctx, user.ID); err != nil {
		return err
	}
	if err := env.revokeAccess(ctx, user.ID); err != nil {
		return err
	}
	env.audit.Record(ctx, cliActor, audit.ActionMFADisable, user.Username, "reset from the command line", "")
	fmt.Printf("two-factor authentication reset for %s; their sessions and tokens were revoked, and they can sign in with their password and enroll again\n", user.Username)
	return nil
}

func userPromote(args []string) error {
	fs := flag.NewFlagSet("user promote", flag.ExitOnError)
	cfgPath := fs.String("config", "kivraid.yaml", "path to the configuration file")
	ident := fs.String("user", "", "username or email of the account (required)")
	fs.Parse(args)

	ctx := context.Background()
	env, err := openUserEnv(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer env.Close()

	user, err := env.findUser(ctx, *ident)
	if err != nil {
		return err
	}
	if user.IsAdmin && user.Active {
		fmt.Printf("%s is already an active administrator\n", user.Username)
		return nil
	}
	// Promoting also reactivates: the point is to get a working
	// administrator account back.
	if err := env.store.UpdateUserFlags(ctx, sqlcgen.UpdateUserFlagsParams{
		IsAdmin: true, Active: true, UpdatedAt: time.Now().UTC(), ID: user.ID,
	}); err != nil {
		return err
	}
	env.audit.Record(ctx, cliActor, audit.ActionUserUpdate, user.Username, "promoted to administrator from the command line", "")
	fmt.Printf("%s is now an active administrator\n", user.Username)
	return nil
}
