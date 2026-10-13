package web

import (
	"errors"
	"net/http"

	"github.com/kivraid/kivraid/internal/pwpolicy"
)

func (s *Server) currentPasswordPolicy() pwpolicy.Policy {
	if p, ok := s.passwordPolicy.Load().(pwpolicy.Policy); ok {
		return p
	}
	return pwpolicy.Policy{MinLength: pwpolicy.DefaultMinLength}
}

// passwordMinLength is the minimum password length in characters, for
// form validation messages and the inputs' minlength attribute.
func (s *Server) passwordMinLength() int {
	return max(s.currentPasswordPolicy().MinLength, pwpolicy.DefaultMinLength)
}

// passwordProblem checks a new password against the instance policy and
// returns the message to show the user, or "" when it is acceptable.
func (s *Server) passwordProblem(r *http.Request, pw string) string {
	unavailable, err := s.currentPasswordPolicy().Check(r.Context(), pw, s.breaches)
	if unavailable != nil && s.log != nil {
		s.log.Warn("password breach check unavailable, password accepted", "err", unavailable)
	}
	switch {
	case errors.Is(err, pwpolicy.ErrTooShort):
		return s.t(r, "The password must be at least %d characters.", s.passwordMinLength())
	case errors.Is(err, pwpolicy.ErrBreached):
		return s.t(r, "This password appears in a known data breach. Choose a different one.")
	}
	return ""
}
