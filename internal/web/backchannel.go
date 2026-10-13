package web

import (
	"context"

	"github.com/kivraid/kivraid/internal/session"
)

// sessionSID returns the current session's OpenID Connect session id (the
// sid claim), creating one for a session that has none yet (signed in
// before sids existed, or through first-run setup).
func (s *Server) sessionSID(ctx context.Context) string {
	sid := s.sessions.GetString(ctx, session.KeySID)
	if sid == "" {
		sid = randomHex(16)
		s.sessions.Put(ctx, session.KeySID, sid)
	}
	return sid
}

// sessionSIDs lists the sids a session carries: its own, plus the
// administrator's during an impersonation. Read it before the session is
// destroyed.
func (s *Server) sessionSIDs(ctx context.Context) []string {
	var sids []string
	for _, key := range []string{session.KeySID, session.KeyImpersonatorSID} {
		if sid := s.sessions.GetString(ctx, key); sid != "" {
			sids = append(sids, sid)
		}
	}
	return sids
}

// logoutSessionApps signs the given sessions out of the applications they
// opened: back-channel logout tokens for OIDC applications, and deletion of
// their forward-auth sessions.
func (s *Server) logoutSessionApps(ctx context.Context, sids ...string) {
	for _, sid := range sids {
		// Forward-auth sessions on application hosts end with the Kivraid
		// session they came from.
		if err := s.store.DeleteForwardAuthSessionsBySID(ctx, sid); err != nil {
			s.log.Warn("end forward-auth sessions", "err", err)
		}
		if s.backchannel != nil {
			s.backchannel.Session(ctx, sid)
		}
	}
}
