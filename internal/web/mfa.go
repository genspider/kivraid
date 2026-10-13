package web

import (
	"net/http"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/mfa"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type mfaEnrollData struct {
	Secret    string // formatted for manual entry
	SecretRaw string
	Error     string
}

type mfaRecoveryData struct {
	Codes []string
	New   bool   // freshly regenerated (vs first enrollment)
	Next  string // where "Done" leads: back to what required two-factor
}

// handleMFABegin generates a pending TOTP secret and shows the enrollment
// page (QR + manual key + confirmation code).
func (s *Server) handleMFABegin(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user.TotpEnabled {
		http.Redirect(w, r, "/profile/security", http.StatusSeeOther)
		return
	}
	if !s.allowFactorChange(w, r, user) {
		return
	}
	secret, err := s.mfa.GenerateSecret(user.Username)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.Put(r.Context(), session.KeyMFAEnroll, secret)
	s.renderMFAEnroll(w, r, secret, "")
}

func (s *Server) renderMFAEnroll(w http.ResponseWriter, r *http.Request, secret, errMsg string) {
	s.render(w, r, "mfa_enroll.html", pageData{
		Title: "Two-factor", Active: "security-account", CSRF: s.csrfToken(r.Context()),
		User: currentUser(r),
		Data: mfaEnrollData{SecretRaw: secret, Secret: mfa.FormatSecret(secret), Error: errMsg},
	})
}

// handleMFAQR streams the enrollment QR for the pending secret.
func (s *Server) handleMFAQR(w http.ResponseWriter, r *http.Request) {
	secret := s.sessions.GetString(r.Context(), session.KeyMFAEnroll)
	if secret == "" {
		http.NotFound(w, r)
		return
	}
	png, err := s.mfa.QRCodePNG(currentUser(r).Username, secret)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

// handleMFAEnable verifies the first code against the pending secret,
// turns TOTP on and shows the recovery codes once.
func (s *Server) handleMFAEnable(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	secret := s.sessions.GetString(r.Context(), session.KeyMFAEnroll)
	if secret == "" {
		http.Redirect(w, r, "/profile/security", http.StatusSeeOther)
		return
	}
	if !s.allowFactorChange(w, r, user) {
		return
	}
	counter, ok := mfa.MatchCounter(secret, r.PostFormValue("code"), time.Now())
	if !ok {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderMFAEnroll(w, r, secret, s.t(r, "That code didn't match. Check your authenticator's time and try again."))
		return
	}
	if err := s.mfa.Enable(r.Context(), user.ID, secret, counter); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.Remove(r.Context(), session.KeyMFAEnroll)
	codes, err := s.mfa.GenerateRecoveryCodes(r.Context(), user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// The code just entered proves the second factor for this session too,
	// which satisfies a two-factor requirement without signing in again.
	s.markSecondFactor(r.Context(), loginPasswordTOTP)
	next := s.safeNext(s.sessions.PopString(r.Context(), session.KeyMFANext), "/profile/security")
	s.audit.Record(r.Context(), user.Username, audit.ActionMFAEnable, "", "", s.clientIP(r))
	s.render(w, r, "mfa_recovery.html", pageData{
		Title: "Recovery codes", Active: "security-account", CSRF: s.csrfToken(r.Context()),
		User: user, Data: mfaRecoveryData{Codes: codes, Next: next},
	})
}

// allowFactorChange enforces factorChangeAllowed for a form post, showing
// the two-factor page with an explanation when refused.
func (s *Server) allowFactorChange(w http.ResponseWriter, r *http.Request, user sqlcgen.User) bool {
	ok, err := s.factorChangeAllowed(r.Context(), user)
	if err != nil {
		s.serverError(w, r, err)
		return false
	}
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		s.renderProfile(w, r, user, s.t(r, factorsLockedMsg), false)
	}
	return ok
}

// handleMFADisable turns TOTP off after re-verifying a current code.
func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if !user.TotpEnabled {
		http.Redirect(w, r, "/profile/security", http.StatusSeeOther)
		return
	}
	if s.mfaRequiredFor(user) {
		s.renderProfile(w, r, user, s.t(r, "Two-factor authentication is required for your account, so it cannot be turned off."), false)
		return
	}
	// Same per-account budget as the sign-in steps: a stolen session must
	// not be able to guess codes here without limit.
	if s.userLimiter.Blocked(user.Username) {
		s.renderProfile(w, r, user, s.t(r, "Too many attempts. Please wait a minute and try again."), false)
		return
	}
	code := r.PostFormValue("code")
	ok, err := s.mfa.ValidateForUser(r.Context(), user, code)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		if used, err := s.mfa.ConsumeRecoveryCode(r.Context(), user.ID, code); err != nil {
			s.serverError(w, r, err)
			return
		} else {
			ok = used
		}
	}
	if !ok {
		s.userLimiter.Allow(user.Username) // consume a failure token
		s.renderProfile(w, r, user, s.t(r, "Enter a current authenticator code to disable two-factor."), false)
		return
	}
	if err := s.mfa.Disable(r.Context(), user.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionMFADisable, "", "", s.clientIP(r))
	http.Redirect(w, r, "/profile/security?mfa=off", http.StatusSeeOther)
}

// handleMFARegenerateRecovery issues a fresh set of recovery codes after
// re-verifying a current code.
func (s *Server) handleMFARegenerateRecovery(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if !user.TotpEnabled {
		http.Redirect(w, r, "/profile/security", http.StatusSeeOther)
		return
	}
	if s.userLimiter.Blocked(user.Username) {
		s.renderProfile(w, r, user, s.t(r, "Too many attempts. Please wait a minute and try again."), false)
		return
	}
	ok, err := s.mfa.ValidateForUser(r.Context(), user, r.PostFormValue("code"))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.userLimiter.Allow(user.Username) // consume a failure token
		s.renderProfile(w, r, user, s.t(r, "Enter a current authenticator code to regenerate recovery codes."), false)
		return
	}
	codes, err := s.mfa.GenerateRecoveryCodes(r.Context(), user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), user.Username, audit.ActionMFARecovery, "", "regenerated", s.clientIP(r))
	s.render(w, r, "mfa_recovery.html", pageData{
		Title: "Recovery codes", Active: "security-account", CSRF: s.csrfToken(r.Context()),
		User: user, Data: mfaRecoveryData{Codes: codes, New: true},
	})
}

// handleAdminUserMFAReset lets an admin clear a locked-out user's MFA.
func (s *Server) handleAdminUserMFAReset(w http.ResponseWriter, r *http.Request) {
	target, ok := s.loadTargetUser(w, r)
	if !ok {
		return
	}
	if err := s.mfa.Disable(r.Context(), target.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit.Record(r.Context(), currentUser(r).Username, audit.ActionMFADisable, target.Username, "admin reset", s.clientIP(r))
	http.Redirect(w, r, "/admin/users/"+target.ID+"?saved=1", http.StatusSeeOther)
}
