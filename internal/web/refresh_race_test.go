package web

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Concurrent exchanges of the same refresh token yield one new token, not
// one per request (two live token chains from a stolen token).
func TestRefreshRotationRace(t *testing.T) {
	issuer, st := startIssuer(t, false)
	ctx := context.Background()
	relying, err := rp.NewRelyingPartyOIDC(ctx, issuer, testClientID, testClientSecret,
		testRedirectURI, []string{"openid", "offline_access"})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, browseAuthFlow(t, rp.AuthURL("teststate", relying)), relying)
	if err != nil {
		t.Fatal(err)
	}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, tokens.RefreshToken, "", ""); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	var live int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM refresh_tokens`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if ok.Load() > 1 || live > 1 {
		t.Fatalf("one refresh token was exchanged %d times, leaving %d live refresh tokens", ok.Load(), live)
	}
}
