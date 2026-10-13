package oidcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	// logoutTokenTTL bounds a logout token's validity; it is delivered
	// right away, so a short window is enough.
	logoutTokenTTL = 2 * time.Minute
	// oidcSessionRetention is how long a session's sign-ins to applications
	// are remembered as back-channel logout targets. Application sessions
	// can outlive the Kivraid session, so this is longer than its lifetime.
	oidcSessionRetention = 90 * 24 * time.Hour
	// logoutDeliveryTimeout bounds one delivery, including the request.
	logoutDeliveryTimeout = 10 * time.Second
)

// logoutTarget is one application session to end: the application, the
// user it knows, and the Kivraid session it was opened from.
type logoutTarget struct {
	sid, clientID, userID, uri string
}

// BackchannelLogout implements OpenID Connect Back-Channel Logout 1.0: it
// tells applications, server to server, that a user's session has ended.
// zitadel/oidc only advertises the capability; the tokens are built and
// delivered here.
type BackchannelLogout struct {
	storage *Storage
	client  *http.Client
	log     *slog.Logger
	pending sync.WaitGroup
}

// Wait blocks until every delivery started so far has finished, for a
// short-lived process (the CLI) that must not exit before sending.
func (b *BackchannelLogout) Wait() { b.pending.Wait() }

// NewBackchannelLogout returns a notifier signing with storage's keys.
func NewBackchannelLogout(storage *Storage, log *slog.Logger) *BackchannelLogout {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &BackchannelLogout{
		storage: storage,
		log:     log,
		client: &http.Client{
			Timeout: logoutDeliveryTimeout,
			// The logout endpoint answers directly; never follow a redirect
			// to some other host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Session notifies every application the Kivraid session sid signed in
// to. Delivery happens in the background: a slow or unreachable
// application must not hold up the user's logout.
func (b *BackchannelLogout) Session(ctx context.Context, sid string) {
	if sid == "" {
		return
	}
	rows, err := b.storage.store.ListOIDCSessionsBySID(ctx, sid)
	if err != nil {
		b.log.Warn("back-channel logout: list session applications", "err", err)
		return
	}
	targets := make([]logoutTarget, len(rows))
	for i, r := range rows {
		targets[i] = logoutTarget{r.Sid, r.ClientID, r.UserID, r.BackchannelLogoutUri}
	}
	if err := b.storage.store.DeleteOIDCSessionsBySID(ctx, sid); err != nil {
		b.log.Warn("back-channel logout: forget session", "err", err)
	}
	b.deliverAll(targets)
}

// User notifies every application any session of the user signed in to;
// used when the account is deactivated, deleted or signed out everywhere.
func (b *BackchannelLogout) User(ctx context.Context, userID string) {
	rows, err := b.storage.store.ListOIDCSessionsByUser(ctx, userID)
	if err != nil {
		b.log.Warn("back-channel logout: list user applications", "err", err)
		return
	}
	targets := make([]logoutTarget, len(rows))
	for i, r := range rows {
		targets[i] = logoutTarget{r.Sid, r.ClientID, r.UserID, r.BackchannelLogoutUri}
	}
	if err := b.storage.store.DeleteOIDCSessionsByUser(ctx, userID); err != nil {
		b.log.Warn("back-channel logout: forget user sessions", "err", err)
	}
	b.deliverAll(targets)
}

func (b *BackchannelLogout) deliverAll(targets []logoutTarget) {
	for _, t := range targets {
		if t.uri == "" {
			continue // the application does not support back-channel logout
		}
		b.pending.Add(1)
		go func() {
			defer b.pending.Done()
			ctx, cancel := context.WithTimeout(context.Background(), logoutDeliveryTimeout)
			defer cancel()
			if err := b.deliver(ctx, t); err != nil {
				b.log.Warn("back-channel logout failed", "client_id", t.clientID, "uri", t.uri, "err", err)
				return
			}
			b.log.Debug("back-channel logout delivered", "client_id", t.clientID)
		}()
	}
}

func (b *BackchannelLogout) deliver(ctx context.Context, t logoutTarget) error {
	token, err := b.storage.signLogoutToken(t.clientID, t.userID, t.sid)
	if err != nil {
		return err
	}
	form := url.Values{"logout_token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.uri, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

// signLogoutToken builds a logout token for one application session,
// signed with the current ID token key. The typ header follows the spec's
// recommendation, so it cannot be mistaken for an ID token.
func (s *Storage) signLogoutToken(clientID, userID, sid string) (string, error) {
	s.keyMu.RLock()
	key := s.key
	s.keyMu.RUnlock()

	claims := oidc.NewLogoutTokenClaims(s.issuer, userID, oidc.Audience{clientID},
		time.Now().Add(logoutTokenTTL), uuid.NewString(), sid, 0)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: key.alg, Key: jose.JSONWebKey{Key: key.private, KeyID: key.id}},
		(&jose.SignerOptions{}).WithType("logout+jwt"),
	)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
