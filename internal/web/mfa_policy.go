package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/pwpolicy"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// How a session was authenticated, recorded at sign-in. Every method but a
// bare password counts as two-factor: TOTP adds a second factor, a passkey
// is phishing-resistant possession plus user verification, and federated
// sign-ins delegate authentication to the upstream provider.
const (
	loginPassword     = "password"
	loginPasswordTOTP = "password+totp"
	loginPasskey      = "passkey"
	loginFederated    = "federated"
)

// Instance-wide two-factor policies.
const (
	mfaPolicyOff    = "off"
	mfaPolicyAdmins = "admins"
	mfaPolicyAll    = "all"
)

var mfaPolicies = []string{mfaPolicyOff, mfaPolicyAdmins, mfaPolicyAll}

// mfaRequiredPath is where a session lacking a required second factor is
// sent to set one up.
const mfaRequiredPath = "/mfa/required"

// mfaSetupPaths stay reachable while a second factor is required, so the
// user can actually enroll one (or deal with a pending password change).
var mfaSetupPaths = []string{
	mfaRequiredPath, passwordChangePath,
	"/profile/mfa/begin", "/profile/mfa/qr", "/profile/mfa/enable",
	"/profile/passkeys/begin", "/profile/passkeys/finish",
}

// loadSecuritySettings refreshes the cached security settings (two-factor
// policy, new-device alerts, password policy) from the database.
func (s *Server) loadSecuritySettings(ctx context.Context) {
	row, err := s.store.GetInstanceSettings(ctx)
	if err != nil {
		if s.log != nil {
			s.log.Warn("load security settings", "err", err)
		}
		return
	}
	policy := row.MfaPolicy
	if !slices.Contains(mfaPolicies, policy) {
		policy = mfaPolicyOff
	}
	s.mfaPolicy.Store(policy)
	s.newDeviceAlerts.Store(row.NewDeviceAlerts)
	s.passwordPolicy.Store(pwpolicy.Policy{
		MinLength: int(row.PasswordMinLength), CheckBreached: row.PasswordBreachCheck,
	})
}

func (s *Server) currentMFAPolicy() string {
	if p, ok := s.mfaPolicy.Load().(string); ok {
		return p
	}
	return mfaPolicyOff
}

// mfaRequiredFor reports whether the instance policy demands a second factor
// from this user (whose IsAdmin is the effective role).
func (s *Server) mfaRequiredFor(user sqlcgen.User) bool {
	switch s.currentMFAPolicy() {
	case mfaPolicyAll:
		return true
	case mfaPolicyAdmins:
		return user.IsAdmin
	}
	return false
}

// sessionHasSecondFactor reports whether the current session was
// authenticated with more than a bare password. Sessions that predate the
// recorded method count as password-only.
func (s *Server) sessionHasSecondFactor(ctx context.Context) bool {
	switch s.sessions.GetString(ctx, session.KeyLoginMethod) {
	case loginPasswordTOTP, loginPasskey, loginFederated:
		return true
	}
	return false
}

// redirectToMFASetup sends the browser to set up a second factor, then back.
func (s *Server) redirectToMFASetup(w http.ResponseWriter, r *http.Request, next string) {
	http.Redirect(w, r, mfaRequiredPath+"?next="+url.QueryEscape(next), http.StatusSeeOther)
}

type mfaRequiredData struct {
	Next        string
	HasTOTP     bool // enrolled, but this session skipped it: sign in again
	HasPasskeys bool
	ForApp      bool // required by an application rather than the instance
}

// handleMFARequired explains why a second factor is needed and offers to
// set one up. A user who already has one but signed in without it (e.g. a
// session older than the policy) is asked to sign in again.
func (s *Server) handleMFARequired(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	next := s.safeNext(r.URL.Query().Get("next"), "/")
	if s.sessionHasSecondFactor(r.Context()) {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.sessions.Put(r.Context(), session.KeyMFANext, next)
	data := mfaRequiredData{Next: next, HasTOTP: user.TotpEnabled, ForApp: !s.mfaRequiredFor(user)}
	if s.webauthn != nil {
		if n, err := s.webauthn.Count(r.Context(), user.ID); err == nil {
			data.HasPasskeys = n > 0
		}
	}
	s.render(w, r, "mfa_required.html", pageData{
		Title: "Two-factor required", CSRF: s.csrfToken(r.Context()), User: user, Data: data,
	})
}

// factorChangeAllowed reports whether the current session may add or
// remove a second factor. A user who already has one (an authenticator app
// or a passkey) must have signed in with it: otherwise the password alone
// would let anyone enroll their own factor in its place and get through
// every two-factor requirement. A user with none yet enrolls on trust, as
// before.
func (s *Server) factorChangeAllowed(ctx context.Context, user sqlcgen.User) (bool, error) {
	if s.sessionHasSecondFactor(ctx) {
		return true, nil
	}
	if user.TotpEnabled {
		return false, nil
	}
	if s.webauthn != nil {
		n, err := s.webauthn.Count(ctx, user.ID)
		if err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	return true, nil
}

// factorsLockedMsg explains why factorChangeAllowed refused.
const factorsLockedMsg = "To add or remove a two-factor method, sign out and sign in again with your passkey or authenticator code."

// markSecondFactor upgrades the current session once the user has just
// proven a second factor while signed in (TOTP enrollment).
func (s *Server) markSecondFactor(ctx context.Context, method string) {
	if !s.sessionHasSecondFactor(ctx) {
		s.sessions.Put(ctx, session.KeyLoginMethod, method)
	}
}

// --- Settings → Security ---------------------------------------------------

// keyRotationChoices are the automatic rotation periods offered, in days
// (0 = manual only).
var keyRotationChoices = []int32{0, 30, 90, 180}

// auditRetentionChoices are the activity-log retention periods offered, in
// days (0 = forever).
var auditRetentionChoices = []int32{30, 90, 180, 365, 0}

type adminSecurityData struct {
	MFAPolicy        string
	RotationDays     int32
	RotationChoices  []int32
	RetentionDays    int32
	RetentionChoices []int32
	NewDeviceAlerts  bool
	PasswordMinLen   int32
	PasswordChoices  []int32
	BreachCheck      bool
	CanEmail         bool
	Saved            bool
	Error            string
}

func (s *Server) renderSecurity(w http.ResponseWriter, r *http.Request, errMsg string) {
	settings, err := s.store.GetInstanceSettings(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "admin_security.html", pageData{
		Title: "Security", Active: "security", CSRF: s.csrfToken(r.Context()), User: currentUser(r),
		Data: adminSecurityData{
			MFAPolicy: s.currentMFAPolicy(), NewDeviceAlerts: s.newDeviceAlerts.Load(),
			RotationDays: settings.KeyRotationDays, RotationChoices: keyRotationChoices,
			RetentionDays: settings.AuditRetentionDays, RetentionChoices: auditRetentionChoices,
			PasswordMinLen: settings.PasswordMinLength, PasswordChoices: pwpolicy.MinLengthChoices, BreachCheck: settings.PasswordBreachCheck,
			CanEmail: s.smtpEnabled.Load(), Saved: r.URL.Query().Get("saved") == "1", Error: errMsg,
		},
	})
}

func (s *Server) handleAdminSecurity(w http.ResponseWriter, r *http.Request) {
	s.renderSecurity(w, r, "")
}

func (s *Server) handleAdminSecuritySave(w http.ResponseWriter, r *http.Request) {
	policy := r.PostFormValue("mfa_policy")
	if !slices.Contains(mfaPolicies, policy) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderSecurity(w, r, s.t(r, "Choose who must use two-factor authentication."))
		return
	}
	alerts := r.PostFormValue("new_device_alerts") == "on"
	days64, _ := strconv.ParseInt(r.PostFormValue("key_rotation_days"), 10, 32)
	days := int32(days64)
	if !slices.Contains(keyRotationChoices, days) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderSecurity(w, r, s.t(r, "Choose a key rotation period."))
		return
	}
	retention64, rerr := strconv.ParseInt(r.PostFormValue("audit_retention_days"), 10, 32)
	retention := int32(retention64)
	if rerr != nil {
		retention = 90 // field absent (older form): keep the default
	}
	if !slices.Contains(auditRetentionChoices, retention) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderSecurity(w, r, s.t(r, "Choose how long to keep the activity log."))
		return
	}
	minLen64, merr := strconv.ParseInt(r.PostFormValue("password_min_length"), 10, 32)
	minLen := int32(minLen64)
	if merr != nil {
		minLen = pwpolicy.DefaultMinLength // field absent (older form): keep the default
	}
	if !slices.Contains(pwpolicy.MinLengthChoices, minLen) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderSecurity(w, r, s.t(r, "Choose a minimum password length."))
		return
	}
	breachCheck := r.PostFormValue("password_breach_check") == "on"
	now := time.Now().UTC()
	if err := s.store.SetMFAPolicy(r.Context(), sqlcgen.SetMFAPolicyParams{MfaPolicy: policy, UpdatedAt: now}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetNewDeviceAlerts(r.Context(), sqlcgen.SetNewDeviceAlertsParams{NewDeviceAlerts: alerts, UpdatedAt: now}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetKeyRotationDays(r.Context(), sqlcgen.SetKeyRotationDaysParams{KeyRotationDays: days, UpdatedAt: now}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetAuditRetentionDays(r.Context(), sqlcgen.SetAuditRetentionDaysParams{AuditRetentionDays: retention, UpdatedAt: now}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetPasswordPolicy(r.Context(), sqlcgen.SetPasswordPolicyParams{
		PasswordMinLength: minLen, PasswordBreachCheck: breachCheck, UpdatedAt: now,
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.loadSecuritySettings(r.Context())
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionSecurityUpdate, "",
		"mfa_policy="+policy+" new_device_alerts="+strconv.FormatBool(alerts)+
			" key_rotation_days="+strconv.Itoa(int(days))+" audit_retention_days="+strconv.Itoa(int(retention))+
			" password_min_length="+strconv.Itoa(int(minLen))+" password_breach_check="+strconv.FormatBool(breachCheck), s.clientIP(r))
	http.Redirect(w, r, "/admin/settings/security?saved=1", http.StatusSeeOther)
}
