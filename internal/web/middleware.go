package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

type ctxKey int

const (
	ctxKeyUser ctxKey = iota
	// ctxKeyImpersonator carries the impersonating admin's display name when
	// the current session is an impersonation; empty otherwise.
	ctxKeyImpersonator
)

func (s *Server) secureHeaders(next http.Handler) http.Handler {
	// HSTS only makes sense (and is only safe to assert) when the
	// instance is actually served over TLS.
	hsts := strings.HasPrefix(s.cfg.BaseURL, "https://")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// No form-action: Chromium enforces it on every hop of the redirect
		// chain that follows a submission, and the login forms legitimately
		// end on another origin (a relying party's redirect_uri, an upstream
		// identity provider, a forward-auth host). With form-action 'self',
		// Chrome and Edge silently cancel that last redirect and the login
		// never returns to the application.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=63072000")
		}
		next.ServeHTTP(w, r)
	})
}

const (
	// maxBodySize bounds an ordinary request body: forms, the passkey and
	// token endpoints. The largest legitimate one is a few kilobytes.
	maxBodySize = 1 << 20
	// maxUploadBodySize bounds a multipart upload: the branding form can
	// carry a logo and a sign-in background at once, plus the encoding.
	maxUploadBodySize = maxUploadPhotoSize + maxUploadBackgroundSize + 1<<20
)

// limitRequestBodies caps every request body before any handler (or the
// CSRF check, which parses forms) reads it. Without it, an anonymous
// client could make the server buffer an arbitrarily large body, e.g. a
// JSON passkey assertion, and exhaust memory.
func limitRequestBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := int64(maxBodySize)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			limit = maxUploadBodySize
		}
		if r.ContentLength > limit {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// applyEffectiveAdmin makes user.IsAdmin the effective role, not just the
// stored flag: membership in a granting group confers it for the duration
// of the request.
func (s *Server) applyEffectiveAdmin(ctx context.Context, user *sqlcgen.User) error {
	if user.IsAdmin {
		return nil
	}
	n, err := s.store.CountAdminGroupMemberships(ctx, user.ID)
	if err != nil {
		return err
	}
	user.IsAdmin = n > 0
	return nil
}

// passwordChangePath is where a user with an administrator-chosen password
// picks their own.
const passwordChangePath = "/password/change"

// requireAuth redirects anonymous requests to the login page and loads
// the current user into the request context.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := s.sessions.GetString(r.Context(), session.KeyUserID)
		if userID == "" {
			redirectToLogin(w, r)
			return
		}
		user, err := s.store.GetUserByID(r.Context(), userID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !user.Active) {
			// Account deleted or deactivated: the session is worthless.
			s.sessions.Destroy(r.Context())
			redirectToLogin(w, r)
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if err := s.applyEffectiveAdmin(r.Context(), &user); err != nil {
			s.serverError(w, r, err)
			return
		}
		// An administrator-chosen password must be replaced before anything
		// else (not while an admin is merely viewing as the user).
		if user.MustChangePassword && r.URL.Path != passwordChangePath &&
			s.sessions.GetString(r.Context(), session.KeyImpersonatorName) == "" {
			http.Redirect(w, r, passwordChangePath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		// A second factor required by the instance policy must be set up (or
		// used to sign in) before anything else.
		if s.mfaRequiredFor(user) && !s.sessionHasSecondFactor(r.Context()) &&
			!slices.Contains(mfaSetupPaths, r.URL.Path) &&
			s.sessions.GetString(r.Context(), session.KeyImpersonatorName) == "" {
			s.redirectToMFASetup(w, r, r.URL.RequestURI())
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyUser, user)
		// Surface an active impersonation so every rendered page can show
		// the return-to-your-account banner.
		if name := s.sessions.GetString(r.Context(), session.KeyImpersonatorName); name != "" {
			ctx = context.WithValue(ctx, ctxKeyImpersonator, name)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// impersonator returns the display name of the admin impersonating the
// current user, or "" when the session is not an impersonation.
func impersonator(r *http.Request) string {
	name, _ := r.Context().Value(ctxKeyImpersonator).(string)
	return name
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if r.URL.Path != "/" {
		target += "?next=" + url.QueryEscape(r.URL.RequestURI())
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func currentUser(r *http.Request) sqlcgen.User {
	user, _ := r.Context().Value(ctxKeyUser).(sqlcgen.User)
	return user
}

// csrfProtect enforces a session-bound token on every state-changing
// request. Templates embed the token via csrfToken as a hidden _csrf field.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		want := s.sessions.GetString(r.Context(), session.KeyCSRF)
		// Form posts carry the token in a hidden field; fetch-based callers
		// (WebAuthn ceremonies, which send a JSON body) use the header so the
		// request body is left intact for the handler to parse.
		got := r.Header.Get("X-CSRF-Token")
		if got == "" {
			got = r.PostFormValue("_csrf")
		}
		if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
			// Fetch-based callers expect a plain error body, not a page.
			if r.Header.Get("X-CSRF-Token") != "" {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
			if want == "" {
				// No token in the session: it expired (or was revoked)
				// while a form sat open in a tab — by far the most common
				// way to land here, and not the user's fault.
				s.renderErrorAction(w, r, http.StatusForbidden, s.t(r, "Session expired"),
					s.t(r, "Your session ended while this page was open, so the form could not be submitted. Sign in again to continue."),
					s.t(r, "Sign in again"), "/login")
				return
			}
			s.renderErrorAction(w, r, http.StatusForbidden, s.t(r, "Form expired"),
				s.t(r, "This form is no longer valid. Go back, reload the page, and try again."),
				"", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfToken returns the session's CSRF token, creating it on first use.
func (s *Server) csrfToken(ctx context.Context) string {
	if tok := s.sessions.GetString(ctx, session.KeyCSRF); tok != "" {
		return tok
	}
	buf := make([]byte, 32)
	rand.Read(buf)
	tok := hex.EncodeToString(buf)
	s.sessions.Put(ctx, session.KeyCSRF, tok)
	return tok
}

// isLocalPath reports whether next is a same-site path (no scheme, no
// protocol-relative tricks).
func isLocalPath(next string) bool {
	if len(next) < 2 || next[0] != '/' || next[1] == '/' || next[1] == '\\' {
		return false
	}
	// Browsers drop tabs and newlines anywhere in a URL, so "/\t/evil.com"
	// would turn into the protocol-relative "//evil.com" once followed:
	// refuse control characters outright.
	for i := 0; i < len(next); i++ {
		if next[i] < 0x20 || next[i] == 0x7f {
			return false
		}
	}
	return true
}
