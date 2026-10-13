package web

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/oidcserver"
	"github.com/kivraid/kivraid/internal/session"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// Forward auth across hosts. The browser never sends Kivraid's session
// cookie to a protected application on another host, so the application
// gets a session of its own, set on its host through a one-time code:
//
//  1. An anonymous request reaches /outpost/auth through the proxy. Kivraid
//     sets a state cookie on the application's host and redirects to
//     /outpost/start on its own host.
//  2. /outpost/start (signed in to Kivraid) issues a short-lived code bound
//     to the user's Kivraid session, the application's host and the state,
//     and redirects to the callback path on the application's host.
//  3. The proxy sends the callback through /outpost/auth (or, for nginx,
//     straight to /outpost/callback). The code is redeemed once, on the
//     host it was issued for, by the browser holding the state cookie, for
//     an application-host session cookie.
//
// Application-host sessions live no longer than the Kivraid session they
// came from, and end with it: signing out of Kivraid, revoking the session
// or the account deletes them.

const (
	// forwardAuthCallbackPath is the path, on a protected application's
	// host, where the code is exchanged; the proxy routes it to Kivraid.
	forwardAuthCallbackPath = "/.kivraid/callback"
	forwardAuthCookie       = "kivraid_fa"
	forwardAuthStateCookie  = "kivraid_fa_state"
	forwardAuthCodeTTL      = 2 * time.Minute
	forwardAuthStateTTL     = 10 * time.Minute
)

// forwardAuthState is the shape accepted for a state value: Kivraid's own
// hex, or nginx's $request_id.
var forwardAuthState = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// forwardIdentity is who a forward-auth request comes from, with what the
// policy checks need from their session.
type forwardIdentity struct {
	user         sqlcgen.User
	method       string // how the Kivraid session signed in
	impersonated bool
	appSession   bool // from an application-host session, not Kivraid's cookie
}

// forwardAuthIdentity authenticates a forward-auth request: by Kivraid's
// session cookie (Kivraid on the application's host), else by the
// application-host session cookie, valid only on the host it was issued
// for. ok is false for an anonymous request.
func (s *Server) forwardAuthIdentity(r *http.Request) (id forwardIdentity, ok bool, err error) {
	ctx := r.Context()
	if userID := s.sessions.GetString(ctx, session.KeyUserID); userID != "" {
		user, err := s.store.GetUserByID(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !user.Active) {
			return forwardIdentity{}, false, nil
		}
		if err != nil {
			return forwardIdentity{}, false, err
		}
		return forwardIdentity{
			user: user, method: s.sessions.GetString(ctx, session.KeyLoginMethod),
			impersonated: s.sessions.GetString(ctx, session.KeyImpersonatorName) != "",
		}, true, nil
	}

	c, err := r.Cookie(forwardAuthCookie)
	if err != nil || c.Value == "" {
		return forwardIdentity{}, false, nil
	}
	row, err := s.store.GetForwardAuthSession(ctx, oidcserver.HashToken(c.Value))
	if errors.Is(err, sql.ErrNoRows) {
		return forwardIdentity{}, false, nil
	}
	if err != nil {
		return forwardIdentity{}, false, err
	}
	if row.Host != normalizeHost(r.Header.Get("X-Forwarded-Host")) || time.Now().UTC().After(row.ExpiresAt) {
		return forwardIdentity{}, false, nil
	}
	user, err := s.store.GetUserByID(ctx, row.UserID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !user.Active) {
		return forwardIdentity{}, false, nil
	}
	if err != nil {
		return forwardIdentity{}, false, err
	}
	return forwardIdentity{
		user: user, method: row.LoginMethod, impersonated: row.Impersonator != "", appSession: true,
	}, true, nil
}

// forwardAuthSignIn starts the code exchange for a browser request to an
// allowlisted host: a state cookie on the application's host, and a
// redirect to /outpost/start. Anything else gets a bare 401.
func (s *Server) forwardAuthSignIn(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" || !s.forwardHostAllowed(host) || nginxAuthRequest(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	state := randomHex(16)
	http.SetCookie(w, &http.Cookie{
		Name: forwardAuthStateCookie, Value: state, Path: "/",
		MaxAge: int(forwardAuthStateTTL / time.Second), HttpOnly: true,
		Secure: r.Header.Get("X-Forwarded-Proto") != "http", SameSite: http.SameSiteLaxMode,
	})
	start := s.issuer() + "/outpost/start?" + url.Values{"rd": {forwardedURL(r)}, "state": {state}}.Encode()
	http.Redirect(w, r, start, http.StatusFound)
}

// nginxAuthRequest reports a subrequest from nginx's auth_request, which
// only understands 2xx, 401 and 403 (anything else is an error): it gets
// 401 instead of a redirect, and nginx's error_page sends the browser
// through /outpost/auth for the redirect itself.
func nginxAuthRequest(r *http.Request) bool {
	return r.URL.Path == "/outpost/auth/nginx"
}

// handleForwardAuthStart issues the one-time code for a signed-in user and
// sends the browser to the callback on the application's host. requireAuth
// has already handled sign-in, a forced password change and the instance
// two-factor policy; the application's own policy is checked here too, so
// a refusal is a readable page rather than the proxy's bare 403.
func (s *Server) handleForwardAuthStart(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	q := r.URL.Query()
	target, err := url.Parse(q.Get("rd"))
	state := q.Get("state")
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Host == "" ||
		target.User != nil || !s.forwardHostAllowed(target.Host) || !forwardAuthState.MatchString(state) {
		s.renderError(w, r, http.StatusBadRequest, s.t(r, "Invalid sign-in link"),
			s.t(r, "This sign-in link is not valid. Go back to the application and try again."))
		return
	}
	impersonator := s.sessions.GetString(r.Context(), session.KeyImpersonatorName)

	app, matched, err := s.matchProxyApp(r.Context(), target.Host)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if matched {
		allowed, err := s.userCanAccessApp(r.Context(), app, user.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if !allowed {
			s.audit.Record(r.Context(), user.Username, audit.ActionOIDCDeny, app.Slug, "forward-auth", s.clientIP(r))
			w.WriteHeader(http.StatusForbidden)
			s.render(w, r, "denied.html", pageData{Title: "Access denied", CSRF: s.csrfToken(r.Context()), User: user, Data: app})
			return
		}
		if app.RequireMfa && !s.sessionHasSecondFactor(r.Context()) && impersonator == "" {
			s.redirectToMFASetup(w, r, r.URL.RequestURI())
			return
		}
	}

	raw := randomHex(32)
	now := time.Now().UTC()
	if err := s.store.CreateForwardAuthCode(r.Context(), sqlcgen.CreateForwardAuthCodeParams{
		CodeHash: oidcserver.HashToken(raw), UserID: user.ID, Sid: s.sessionSID(r.Context()),
		Host: normalizeHost(target.Host), State: state,
		LoginMethod: s.sessions.GetString(r.Context(), session.KeyLoginMethod), Impersonator: impersonator,
		// The application-host session ends no later than this one.
		SessionExpiresAt: s.sessions.Deadline(r.Context()).UTC(),
		ExpiresAt:        now.Add(forwardAuthCodeTTL),
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	rd := target.RequestURI()
	callback := target.Scheme + "://" + target.Host + forwardAuthCallbackPath + "?" +
		url.Values{"code": {raw}, "rd": {rd}}.Encode()
	http.Redirect(w, r, callback, http.StatusSeeOther)
}

// handleForwardAuthCallback is the callback for proxies that route the
// callback path straight to Kivraid (nginx), with X-Forwarded-Host and
// X-Forwarded-Proto describing the application's host.
func (s *Server) handleForwardAuthCallback(w http.ResponseWriter, r *http.Request) {
	s.forwardAuthCallback(w, r, r.URL.Query())
}

// forwardAuthCallback redeems a code on the application's host for an
// application-host session cookie, then returns to the page first asked
// for. The code is single use, short-lived, valid only on the host it was
// issued for, and only for the browser holding the matching state cookie:
// a code alone cannot sign someone else's browser in as its owner.
func (s *Server) forwardAuthCallback(w http.ResponseWriter, r *http.Request, q url.Values) {
	invalid := func() {
		http.Error(w, "invalid or expired sign-in, go back to the application and try again", http.StatusBadRequest)
	}
	host := normalizeHost(r.Header.Get("X-Forwarded-Host"))
	rd := q.Get("rd")
	if host == "" || (rd != "/" && !isLocalPath(rd)) {
		invalid()
		return
	}
	row, err := s.store.ConsumeForwardAuthCode(r.Context(), oidcserver.HashToken(q.Get("code")))
	if err != nil {
		invalid()
		return
	}
	state, err := r.Cookie(forwardAuthStateCookie)
	if err != nil || row.Host != host || time.Now().UTC().After(row.ExpiresAt) ||
		subtle.ConstantTimeCompare([]byte(state.Value), []byte(row.State)) != 1 {
		invalid()
		return
	}

	raw := randomHex(32)
	if err := s.store.CreateForwardAuthSession(r.Context(), sqlcgen.CreateForwardAuthSessionParams{
		TokenHash: oidcserver.HashToken(raw), UserID: row.UserID, Sid: row.Sid, Host: row.Host,
		LoginMethod: row.LoginMethod, Impersonator: row.Impersonator,
		ExpiresAt: row.SessionExpiresAt, CreatedAt: time.Now().UTC(),
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	secure := r.Header.Get("X-Forwarded-Proto") != "http"
	http.SetCookie(w, &http.Cookie{
		Name: forwardAuthCookie, Value: raw, Path: "/", Expires: row.SessionExpiresAt,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: forwardAuthStateCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "https"
	}
	http.Redirect(w, r, proto+"://"+r.Header.Get("X-Forwarded-Host")+rd, http.StatusFound)
}
