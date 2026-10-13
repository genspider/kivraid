package web

import (
	"context"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// Refreshing re-checks the application's access policy: restricting the
// application to a group the user is not in ends their refresh token.
func TestRefreshHonoursAccessPolicyChanges(t *testing.T) {
	issuer, st := startIssuer(t, false)
	ctx := context.Background()
	relying, err := rp.NewRelyingPartyOIDC(ctx, issuer, testClientID, testClientSecret,
		testRedirectURI, []string{"openid", "offline_access"})
	if err != nil {
		t.Fatal(err)
	}
	code := browseAuthFlow(t, rp.AuthURL("teststate", relying))
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, relying)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, tokens.RefreshToken, "", "")
	if err != nil {
		t.Fatalf("refresh before the policy change: %v", err)
	}

	grp, err := st.CreateGroup(ctx, sqlcgen.CreateGroupParams{ID: "staff", Name: "staff", Source: "local", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddAppPolicy(ctx, sqlcgen.AddAppPolicyParams{ApplicationID: "app1", GroupID: grp.ID}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplicationRestricted(ctx, sqlcgen.SetApplicationRestrictedParams{Restricted: true, ID: "app1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, refreshed.RefreshToken, "", ""); err == nil {
		t.Fatal("refresh must fail once the user no longer passes the access policy")
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM refresh_tokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("refresh tokens left: %d (err %v)", n, err)
	}
}
