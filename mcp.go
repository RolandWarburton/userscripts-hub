package main

// MCP server for claude.ai at /mcp (list_scripts, get_script, put_script), off unless
// MCP_ENABLED=true. Callers sign in through Dex and must be in MCP_ALLOWED_EMAILS.

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
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCP for claude.ai:
//
//	GET  /.well-known/oauth-protected-resource[/mcp]   tells claude.ai to sign in with Dex
//	POST /mcp                                          MCP Streamable HTTP, stateless, Dex token required
//
// Enabled by MCP_ENABLED=true, which also needs MCP_RESOURCE_URL (the public URL of /mcp),
// MCP_ALLOWED_EMAILS, MCP_OIDC_ISSUER (the Dex URL) and BASE_URL. MCP_OIDC_AUDIENCE
// (the Dex client) defaults to userscripts-mcp. ADMIN_TOKEN is never accepted here.

// userHeader carries the Dex-verified email from requireDex to the tool handlers, which see
// the request's headers but not its context. requireDex always overwrites it.
const userHeader = "X-Userscripts-Mcp-User"

var mcpEnabled = os.Getenv("MCP_ENABLED") == "true"

// mcpInstructions is completed with BASE_URL, which MCP requires.
const mcpInstructions = "Read, write and publish Tampermonkey userscripts served from %s. " +
	"list_scripts shows what exists; get_script returns a script's source. To create or change a script, " +
	"send the complete source to put_script: it must have a // ==UserScript== block with @name and @version, " +
	"and @version must be greater than the stored one. Leave out @updateURL and @downloadURL: the server adds them. " +
	"After every successful put_script, give the user the install_url it returns as a link: Tampermonkey only " +
	"checks for updates occasionally, so opening that link is how they install the new version."

type nameArgs struct {
	Name string `json:"name" jsonschema:"Script name: letters, digits, _ and - only (the file is <name>.user.js)"`
}

type putArgs struct {
	Name   string `json:"name" jsonschema:"Script name: letters, digits, _ and - only (the file is <name>.user.js)"`
	Source string `json:"source" jsonschema:"The complete userscript source, including its // ==UserScript== block"`
}

func toolText(s string, isErr bool) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}, IsError: isErr}
}

// toolResult reports v as compact JSON, or err as a tool error the model can act on.
func toolResult(v any, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		return toolText(err.Error(), true), nil, nil
	}
	b, err := json.Marshal(v) // compact: indentation only costs the model tokens
	if err != nil {
		return nil, nil, err
	}
	return toolText(string(b), false), nil, nil
}

func newMCPServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "userscripts", Version: "1.0.0"},
		&mcp.ServerOptions{Instructions: fmt.Sprintf(mcpInstructions, baseURL)})
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_scripts",
		Title:       "List userscripts",
		Description: "List every stored userscript with its @version and install URL.",
		Annotations: readOnly,
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return toolResult(listScripts(baseURL))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_script",
		Title:       "Read userscript",
		Description: "Return a stored userscript's source, parsed metadata, version and install URL.",
		Annotations: readOnly,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in nameArgs) (*mcp.CallToolResult, any, error) {
		return toolResult(getScript(baseURL, in.Name))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:  "put_script",
		Title: "Publish userscript",
		Description: "Create or replace a userscript and publish it: Tampermonkey installs that have it will " +
			"pick up the new version. Send the complete source. @version must be greater than the stored " +
			"version (get_script shows it), or the update is rejected. Returns the install URL to give the user.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(false)},
	}, func(_ context.Context, req *mcp.CallToolRequest, in putArgs) (*mcp.CallToolResult, any, error) {
		h := req.Extra.Header
		who := "user=" + h.Get(userHeader) + " ip=" + clientIP(h, "")
		info, _, err := putScript(baseURL, in.Name, who, []byte(in.Source))
		return toolResult(info, err)
	})

	return server
}

// mcpRoutes registers the MCP routes: the real ones when MCP is enabled, 404s otherwise.
// /mcp is registered per method because a bare "/mcp" would conflict with "GET /{file}".
func mcpRoutes(mux *http.ServeMux) {
	paths := []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"}
	mcpPatterns := []string{"GET /mcp", "POST /mcp", "DELETE /mcp"}
	if !mcpEnabled {
		for _, p := range append(paths, mcpPatterns...) {
			mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { notFound(w) })
		}
		return
	}
	if baseURL == "" {
		log.Fatalf("BASE_URL must be set when MCP_ENABLED is")
	}
	auth, err := newDexAuth(os.Getenv("MCP_RESOURCE_URL"), os.Getenv("MCP_OIDC_ISSUER"),
		os.Getenv("MCP_OIDC_AUDIENCE"), os.Getenv("MCP_ALLOWED_EMAILS"))
	if err != nil {
		log.Fatal(err)
	}
	server := newMCPServer()
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	for _, p := range paths {
		mux.HandleFunc("GET "+p, func(w http.ResponseWriter, r *http.Request) { sendJSON(w, http.StatusOK, auth.metadata()) })
	}
	for _, p := range mcpPatterns {
		mux.Handle(p, auth.require(handler))
	}
	log.Printf("MCP enabled at %s for %s", auth.resourceURL, strings.Join(auth.allowed, ", "))
}

// dexAuth: claude.ai signs in through Dex and sends the
// access token; Dex's userinfo endpoint vouches for it, the token must have been issued to
// this server's Dex client, and the email must be allowed.
type dexAuth struct {
	resourceURL, issuer, audience string
	allowed                       []string
	client                        *http.Client

	mu    sync.Mutex
	cache map[string]cachedUser // sha256(token) -> caller
}

type cachedUser struct {
	email string
	until time.Time
}

// userinfo answers are reused briefly so a burst of tool calls costs one Dex round trip.
const authCacheTTL = time.Minute

var (
	bearerRE       = regexp.MustCompile(`(?i)^Bearer\s+(\S+)$`)
	errDexRejected = errors.New("Dex rejected the token")
	errDexNoEmail  = errors.New("no verified email")
)

func newDexAuth(resourceURL, issuer, audience, allowed string) (*dexAuth, error) {
	if resourceURL == "" {
		return nil, errors.New("MCP_RESOURCE_URL must be set when MCP_ENABLED is (the public URL of /mcp)")
	}
	if u, err := url.Parse(resourceURL); err != nil || u.Host == "" {
		return nil, fmt.Errorf("MCP_RESOURCE_URL %q is not an absolute URL", resourceURL)
	}
	if issuer == "" {
		return nil, errors.New("MCP_OIDC_ISSUER must be set when MCP_ENABLED is (the Dex URL)")
	}
	if audience == "" {
		audience = "userscripts-mcp"
	}
	var emails []string
	for _, e := range strings.Split(allowed, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			emails = append(emails, e)
		}
	}
	if len(emails) == 0 {
		return nil, errors.New("MCP_ALLOWED_EMAILS must list who may use the MCP server")
	}
	return &dexAuth{
		resourceURL: resourceURL, issuer: strings.TrimRight(issuer, "/"), audience: audience, allowed: emails,
		client: &http.Client{Timeout: 10 * time.Second}, cache: map[string]cachedUser{},
	}, nil
}

func (a *dexAuth) require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, status, reason := a.check(r.Context(), r.Header.Get("Authorization"))
		if status != 0 {
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", a.challenge(reason))
			}
			apiError(w, status, "%s", reason)
			return
		}
		r.Header.Set(userHeader, email)
		next.ServeHTTP(w, r)
	})
}

// check returns the caller's email, or an HTTP status and reason.
func (a *dexAuth) check(ctx context.Context, header string) (string, int, string) {
	m := bearerRE.FindStringSubmatch(header)
	if m == nil {
		return "", http.StatusUnauthorized, "missing bearer token"
	}
	token := m[1]
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])

	a.mu.Lock()
	hit, ok := a.cache[key]
	a.mu.Unlock()
	if ok && time.Now().Before(hit.until) {
		return hit.email, 0, ""
	}

	email, err := a.userinfo(ctx, token)
	switch {
	case errors.Is(err, errDexNoEmail):
		return "", http.StatusForbidden, "this account has no verified email"
	case errors.Is(err, errDexRejected):
		return "", http.StatusUnauthorized, err.Error()
	case err != nil:
		log.Printf("[mcp] dex: %v", err)
		return "", http.StatusServiceUnavailable, "can't reach Dex to check the token"
	}
	// Only tokens issued to this server's Dex client, so one meant for another app can't be replayed here.
	if !slices.Contains(audiences(token), a.audience) {
		return "", http.StatusUnauthorized, "token was not issued to " + a.audience
	}
	if !slices.Contains(a.allowed, email) {
		return "", http.StatusForbidden, email + " is not allowed"
	}

	now := time.Now()
	a.mu.Lock()
	a.cache[key] = cachedUser{email, now.Add(authCacheTTL)}
	for k, v := range a.cache {
		if now.After(v.until) {
			delete(a.cache, k)
		}
	}
	a.mu.Unlock()
	return email, 0, ""
}

// userinfo asks Dex whose token this is, returning the lower-case email.
func (a *dexAuth) userinfo(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.issuer+"/userinfo", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := a.client.Do(req)
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
// userinfo has already vouched for.
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

// metadata is the RFC 9728 protected resource metadata pointing claude.ai at Dex.
func (a *dexAuth) metadata() any {
	return map[string]any{
		"resource":                 a.resourceURL,
		"authorization_servers":    []string{a.issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"openid", "email", "profile", "offline_access"},
	}
}

func (a *dexAuth) challenge(reason string) string {
	u, _ := url.Parse(a.resourceURL)
	meta := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource"
	return fmt.Sprintf(`Bearer resource_metadata="%s", error="invalid_token", error_description="%s"`,
		meta, strings.ReplaceAll(reason, `"`, "'"))
}
