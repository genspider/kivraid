package web

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// handleForwardAuth is the auth_request-style endpoint for reverse
// proxies (Traefik forwardAuth, nginx auth_request, Caddy forward_auth).
// Authenticated requests get 200 plus identity headers the proxy can copy
// upstream. A request is authenticated by Kivraid's own session cookie
// when Kivraid shares the application's host, otherwise by the
// application-host session obtained through the one-time code exchange
// (see forwardauth_session.go). Anonymous browser requests for an
// allowlisted host are sent to sign in, anything else gets 401. When a
// proxy application is registered for the host, its group access policy is
// enforced (403 for members who fail it).
func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	// The code exchange lands on the application's host, so the proxy
	// sends it here like any other request to that host.
	if uri, err := url.ParseRequestURI(r.Header.Get("X-Forwarded-Uri")); err == nil && uri.Path == forwardAuthCallbackPath {
		s.forwardAuthCallback(w, r, uri.Query())
		return
	}
	id, ok, err := s.forwardAuthIdentity(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.forwardAuthSignIn(w, r)
		return
	}
	user := id.user
	// A password set by an administrator must be replaced before reaching
	// protected applications too, not only Kivraid's own pages.
	if user.MustChangePassword && !id.impersonated {
		s.forwardAuthRequire(w, r, id, passwordChangePath)
		return
	}
	// The instance two-factor policy covers protected applications as it
	// covers Kivraid's own pages: a password-only session must first set up
	// or use its second factor.
	if err := s.applyEffectiveAdmin(r.Context(), &user); err != nil {
		s.serverError(w, r, err)
		return
	}
	if s.mfaRequiredFor(user) && !isSecondFactorMethod(id.method) && !id.impersonated {
		s.forwardAuthRequire(w, r, id, mfaRequiredPath)
		return
	}

	// If a proxy application is registered for the requested host, enforce
	// its group access policy (an unrestricted app admits any authenticated user).
	if app, matched, err := s.matchProxyApp(r.Context(), r.Header.Get("X-Forwarded-Host")); err != nil {
		s.serverError(w, r, err)
		return
	} else if matched {
		allowed, err := s.userCanAccessApp(r.Context(), app, user.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if !allowed {
			s.audit.Record(r.Context(), user.Username, audit.ActionOIDCDeny, app.Slug, "forward-auth", s.clientIP(r))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if app.RequireMfa && !isSecondFactorMethod(id.method) && !id.impersonated {
			s.forwardAuthRequire(w, r, id, mfaRequiredPath)
			return
		}
	}

	groups, err := s.store.ListUserGroups(r.Context(), user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// Remote-Groups is a comma-separated list: a name containing a comma
	// would read as several groups downstream ("staff,admins" as staff and
	// admins), so such a group is left out rather than split.
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		if strings.Contains(g.Name, ",") {
			s.log.Warn("forward auth: group left out of Remote-Groups, its name contains a comma", "group", g.Name)
			continue
		}
		names = append(names, g.Name)
	}
	h := w.Header()
	h.Set("Remote-User", user.Username)
	h.Set("Remote-Email", user.Email)
	h.Set("Remote-Name", user.Name)
	h.Set("Remote-Groups", strings.Join(names, ","))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// forwardAuthRequire sends a signed-in user who still owes something
// (a new password, a second factor) to the Kivraid page that handles it.
// With Kivraid's own session, that page returns to the original URL. With
// an application-host session, it goes back through the sign-in start, so
// that a fresh code carries the session's new state to the application.
func (s *Server) forwardAuthRequire(w http.ResponseWriter, r *http.Request, id forwardIdentity, path string) {
	if id.appSession {
		s.forwardAuthSignIn(w, r)
		return
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host != "" && s.forwardHostAllowed(host) && !nginxAuthRequest(r) {
		http.Redirect(w, r, s.issuer()+path+"?next="+url.QueryEscape(forwardedURL(r)), http.StatusFound)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// forwardedURL rebuilds the URL the browser asked the proxy for.
func forwardedURL(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "https"
	}
	return proto + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
}

// normalizeHost lowercases host and strips any port and trailing dot. The
// trailing dot matters: "app.example.com." is the same host to DNS and to
// some proxies' routing (Traefik), and must not slip past the policy of
// the application registered for "app.example.com".
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return trimHostDot(strings.ToLower(host))
}

// trimHostDot removes the trailing dot(s) of a fully qualified host name,
// keeping any port.
func trimHostDot(host string) string {
	if h, port, err := net.SplitHostPort(host); err == nil {
		return net.JoinHostPort(strings.TrimRight(h, "."), port)
	}
	return strings.TrimRight(host, ".")
}

// forwardHostAllowed reports whether host may be a post-login redirect
// target: it must match a configured forward-auth domain (".suffix"
// entries match subdomains and the bare domain; others match exactly) or
// a registered proxy application's host.
func (s *Server) forwardHostAllowed(host string) bool {
	hostname := normalizeHost(host)
	for _, d := range s.cfg.ForwardAuth.Domains {
		d = strings.ToLower(d)
		if strings.HasPrefix(d, ".") {
			if hostname == d[1:] || strings.HasSuffix(hostname, d) {
				return true
			}
		} else if hostname == d {
			return true
		}
	}
	if _, matched, err := s.matchProxyApp(context.Background(), host); err == nil && matched {
		return true
	}
	return false
}

// matchProxyApp returns the proxy application registered for host, if any.
func (s *Server) matchProxyApp(ctx context.Context, host string) (sqlcgen.Application, bool, error) {
	hostname := normalizeHost(host)
	if hostname == "" {
		return sqlcgen.Application{}, false, nil
	}
	apps, err := s.store.ListProxyApplications(ctx)
	if err != nil {
		return sqlcgen.Application{}, false, err
	}
	for _, app := range apps {
		for _, h := range decodeList(app.ProxyHosts) {
			if normalizeHost(h) == hostname {
				return app, true, nil
			}
		}
	}
	return sqlcgen.Application{}, false, nil
}

// safeNext returns next when it is a same-site path or an absolute URL
// on an allowlisted forward-auth domain, otherwise the fallback.
func (s *Server) safeNext(next, fallback string) string {
	if isLocalPath(next) {
		return next
	}
	if u, err := url.Parse(next); err == nil &&
		(u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		s.forwardHostAllowed(u.Host) {
		return next
	}
	return fallback
}
