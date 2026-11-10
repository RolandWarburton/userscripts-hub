package main

// Dex token checks shared by the MCP server and the admin dashboard. A caller sends a Dex
// access token; Dex's userinfo endpoint vouches for it, the token must have been issued to
// the Dex client that endpoint expects, and the email must be in MCP_ALLOWED_EMAILS.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// userHeader carries the Dex-verified email from the auth middleware to the handlers.
// The middleware always overwrites it, so a caller can't set it.
const userHeader = "X-Userscripts-User"

// userinfo answers are reused briefly so a burst of requests costs one Dex round trip.
const authCacheTTL = time.Minute

var (
	errDexRejected = errors.New("Dex rejected the token")
	errDexNoEmail  = errors.New("no verified email")
)

type dexVerifier struct {
	issuer  string
	allowed []string
	client  *http.Client

	mu    sync.Mutex
	cache map[string]cachedUser // sha256(token) -> caller
}

type cachedUser struct {
	email string
	until time.Time
}

func newDexVerifier(issuer, allowed string) (*dexVerifier, error) {
	if issuer == "" {
		return nil, errors.New("MCP_OIDC_ISSUER must be set (the Dex URL)")
	}
	emails := splitEmails(allowed)
	if len(emails) == 0 {
		return nil, errors.New("MCP_ALLOWED_EMAILS must list who may use the MCP server and the dashboard")
	}
	return &dexVerifier{
		issuer: strings.TrimRight(issuer, "/"), allowed: emails,
		client: &http.Client{Timeout: 10 * time.Second}, cache: map[string]cachedUser{},
	}, nil
}

func splitEmails(s string) []string {
	var emails []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			emails = append(emails, e)
		}
	}
	return emails
}

// check returns the email of the token's owner, or an HTTP status and reason. The token
// must have been issued to audience, so one meant for another client can't be replayed.
func (v *dexVerifier) check(ctx context.Context, token, audience string) (string, int, string) {
	if token == "" {
		return "", http.StatusUnauthorized, "missing bearer token"
	}
	// Checked before the cache, so a cached token never skips it. Only trusted
	// together with userinfo below, which is what proves the token is real.
	if !slices.Contains(audiences(token), audience) {
		return "", http.StatusUnauthorized, "token was not issued to " + audience
	}
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])

	v.mu.Lock()
	hit, ok := v.cache[key]
	v.mu.Unlock()
	if !ok || time.Now().After(hit.until) {
		email, err := v.userinfo(ctx, token)
		switch {
		case errors.Is(err, errDexNoEmail):
			return "", http.StatusForbidden, "this account has no verified email"
		case errors.Is(err, errDexRejected):
			return "", http.StatusUnauthorized, err.Error()
		case err != nil:
			log.Printf("[auth] dex: %v", err)
			return "", http.StatusServiceUnavailable, "can't reach Dex to check the token"
		}
		now := time.Now()
		hit = cachedUser{email, now.Add(authCacheTTL)}
		v.mu.Lock()
		v.cache[key] = hit
		for k, c := range v.cache {
			if now.After(c.until) {
				delete(v.cache, k)
			}
		}
		v.mu.Unlock()
	}
	if !slices.Contains(v.allowed, hit.email) {
		return "", http.StatusForbidden, hit.email + " is not allowed"
	}
	return hit.email, 0, ""
}

// userinfo asks Dex whose token this is, returning the lower-case email.
func (v *dexVerifier) userinfo(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.issuer+"/userinfo", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := v.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w (%d)", errDexRejected, res.StatusCode)
	}
	var info struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("%w: unreadable userinfo response", errDexRejected)
	}
	if info.Email == "" || info.EmailVerified != nil && !*info.EmailVerified {
		return "", errDexNoEmail
	}
	return strings.ToLower(info.Email), nil
}

// audiences reads a JWT's aud claim. Not a signature check: use it only on a token
// userinfo vouches for.
func audiences(token string) []string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		return []string{one}
	}
	var many []string
	json.Unmarshal(claims.Aud, &many)
	return many
}
