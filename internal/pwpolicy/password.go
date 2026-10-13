// Package pwpolicy holds the instance password policy: a minimum length
// and an optional check against known data breaches (Have I Been Pwned).
// It applies to every password Kivraid sets, whatever the source of the
// account; a directory may still enforce its own, stricter rules.
package pwpolicy

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultMinLength is the minimum length when nothing else is configured.
const DefaultMinLength = 8

// MinLengthChoices are the minimum lengths an administrator can pick.
var MinLengthChoices = []int32{8, 10, 12, 14, 16}

var (
	// ErrTooShort means the password has fewer characters than the policy
	// requires.
	ErrTooShort = errors.New("password too short")
	// ErrBreached means the password appears in a known data breach.
	ErrBreached = errors.New("password found in a data breach")
)

// BreachChecker reports whether a password is known to have leaked.
type BreachChecker interface {
	Breached(ctx context.Context, password string) (bool, error)
}

// Policy is the instance password policy.
type Policy struct {
	MinLength int
	// CheckBreached rejects passwords found by Breaches.
	CheckBreached bool
}

// Check validates a password against the policy. It returns ErrTooShort
// or ErrBreached for a password the policy rejects. When the breach check
// cannot be done (no network, service down), the password is accepted and
// the lookup error is returned in unavailable so the caller can log it:
// an outage must not block every password change.
func (p Policy) Check(ctx context.Context, pw string, breaches BreachChecker) (unavailable, err error) {
	minLen := p.MinLength
	if minLen < DefaultMinLength {
		minLen = DefaultMinLength
	}
	if utf8.RuneCountInString(pw) < minLen {
		return nil, ErrTooShort
	}
	if !p.CheckBreached || breaches == nil {
		return nil, nil
	}
	found, lookupErr := breaches.Breached(ctx, pw)
	if lookupErr != nil {
		return lookupErr, nil
	}
	if found {
		return nil, ErrBreached
	}
	return nil, nil
}

// PwnedPasswords queries the Have I Been Pwned range API. Only the first
// five hex characters of the password's SHA-1 leave the host
// (k-anonymity), and responses are padded so their size reveals nothing.
type PwnedPasswords struct {
	// BaseURL defaults to the public API; tests point it elsewhere.
	BaseURL string
	Client  *http.Client
}

const pwnedBaseURL = "https://api.pwnedpasswords.com"

// NewPwnedPasswords returns a client for the public API with a short
// timeout, since it runs while a user waits on a form.
func NewPwnedPasswords() *PwnedPasswords {
	return &PwnedPasswords{BaseURL: pwnedBaseURL, Client: &http.Client{Timeout: 3 * time.Second}}
}

// Breached implements BreachChecker.
func (p *PwnedPasswords) Breached(ctx context.Context, pw string) (bool, error) {
	sum := sha1.Sum([]byte(pw))
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.BaseURL+"/range/"+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "Kivraid")
	resp, err := p.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("pwned passwords: %s", resp.Status)
	}
	// Each line is "SUFFIX:COUNT"; padding entries have a count of 0.
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		hash, count, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && hash == suffix {
			return count != "0", nil
		}
	}
	return false, sc.Err()
}
