package oidcserver

import (
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// authRequest is the persisted state of an authorization request. It is
// stored as JSON in the auth_requests table and implements op.AuthRequest.
type authRequest struct {
	ID                  string                   `json:"id"`
	CreatedAt           time.Time                `json:"created_at"`
	ClientID            string                   `json:"client_id"`
	RedirectURI         string                   `json:"redirect_uri"`
	State               string                   `json:"state"`
	Nonce               string                   `json:"nonce"`
	Scopes              []string                 `json:"scopes"`
	ResponseType        oidc.ResponseType        `json:"response_type"`
	ResponseMode        oidc.ResponseMode        `json:"response_mode"`
	CodeChallenge       string                   `json:"code_challenge,omitempty"`
	CodeChallengeMethod oidc.CodeChallengeMethod `json:"code_challenge_method,omitempty"`
	// Prompt and MaxAge carry the client's demand for a fresh sign-in
	// (prompt=login, max_age), honoured by the web layer before completion.
	Prompt []string `json:"prompt,omitempty"`
	MaxAge *uint    `json:"max_age,omitempty"`

	// Filled in when the user completes the login flow.
	UserID   string    `json:"user_id,omitempty"`
	AuthTime time.Time `json:"auth_time,omitzero"`
	IsDone   bool      `json:"done"`
	// AMR lists the authentication methods of the session that completed
	// the request (RFC 8176 values).
	AMR []string `json:"amr,omitempty"`
	// SessionID is the Kivraid session (sid) the user signed in with; it
	// is the sid claim of the ID token and of back-channel logout tokens.
	SessionID string `json:"sid,omitempty"`
}

func newAuthRequest(id string, r *oidc.AuthRequest, now time.Time) *authRequest {
	return &authRequest{
		ID:                  id,
		CreatedAt:           now,
		ClientID:            r.ClientID,
		RedirectURI:         r.RedirectURI,
		State:               r.State,
		Nonce:               r.Nonce,
		Scopes:              r.Scopes,
		ResponseType:        r.ResponseType,
		ResponseMode:        r.ResponseMode,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		Prompt:              r.Prompt,
		MaxAge:              r.MaxAge,
	}
}

// needsFreshLogin reports whether the client asked for a sign-in more
// recent than loginAt: prompt=login, or a max_age that loginAt exceeds. A
// sign-in made after the request was created always satisfies it.
func (a *authRequest) needsFreshLogin(loginAt, now time.Time) bool {
	if !loginAt.Before(a.CreatedAt.Truncate(time.Second)) {
		return false
	}
	if slices.Contains(a.Prompt, oidc.PromptLogin) {
		return true
	}
	return a.MaxAge != nil && now.Sub(loginAt) > time.Duration(*a.MaxAge)*time.Second
}

func (a *authRequest) GetID() string          { return a.ID }
func (a *authRequest) GetACR() string         { return "" }
func (a *authRequest) GetAudience() []string  { return []string{a.ClientID} }
func (a *authRequest) GetAuthTime() time.Time { return a.AuthTime }
func (a *authRequest) GetClientID() string    { return a.ClientID }
func (a *authRequest) GetNonce() string       { return a.Nonce }
func (a *authRequest) GetRedirectURI() string { return a.RedirectURI }
func (a *authRequest) GetScopes() []string    { return a.Scopes }
func (a *authRequest) GetState() string       { return a.State }
func (a *authRequest) GetSubject() string     { return a.UserID }
func (a *authRequest) Done() bool             { return a.IsDone }
func (a *authRequest) sessionID() string      { return a.SessionID }

func (a *authRequest) GetAMR() []string {
	if !a.IsDone {
		return nil
	}
	if a.AMR == nil {
		return []string{"pwd"} // completed before methods were recorded
	}
	return a.AMR
}

func (a *authRequest) GetResponseType() oidc.ResponseType { return a.ResponseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.ResponseMode }

func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.CodeChallenge,
		Method:    a.CodeChallengeMethod,
	}
}
