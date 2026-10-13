package broker

import (
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

// email_verified vouches for the standard email claim only.
func TestMapIdentityEmailVerified(t *testing.T) {
	ui := &oidc.UserInfo{Subject: "s1"}
	ui.Email = "alice@example.com"
	ui.EmailVerified = true
	ui.PreferredUsername = "admin@example.com"
	m := &Manager{}

	id := m.mapIdentity(sqlcgen.UpstreamProvider{ClaimEmail: "email"}, ui)
	if !id.EmailVerified || id.Email != "alice@example.com" {
		t.Errorf("email claim: got %q verified=%v", id.Email, id.EmailVerified)
	}
	id = m.mapIdentity(sqlcgen.UpstreamProvider{ClaimEmail: "preferred_username"}, ui)
	if id.EmailVerified || id.Email != "admin@example.com" {
		t.Errorf("preferred_username mapping: got %q verified=%v, want unverified", id.Email, id.EmailVerified)
	}
}
