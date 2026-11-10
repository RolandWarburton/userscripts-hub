package main

// MCP server for claude.ai at /mcp (list_scripts, get_script, put_script, delete_script),
// off unless MCP_ENABLED=true. Callers sign in through Dex and must be in MCP_ALLOWED_EMAILS.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCP for claude.ai:
//
//	GET  /.well-known/oauth-protected-resource[/mcp]   tells claude.ai to sign in with Dex
//	POST /mcp                                          MCP Streamable HTTP, stateless, Dex token required
//
// Enabled by MCP_ENABLED=true, which also needs MCP_RESOURCE_URL (the public URL of /mcp).
// Only tokens issued to the Dex client MCP_OIDC_AUDIENCE (default userscripts-mcp) are
// accepted here; the dashboard's tokens are not.

var mcpEnabled = os.Getenv("MCP_ENABLED") == "true"

// mcpInstructions is completed with BASE_URL.
const mcpInstructions = "Read, write and publish Tampermonkey userscripts served from %s. " +
	"list_scripts shows what exists; get_script returns a script's source. To create or change a script, " +
	"send the complete source to put_script: it must have a // ==UserScript== block with @name and @version, " +
	"and @version must be greater than the stored one. Leave out @updateURL and @downloadURL: the server adds them. " +
	"After every successful put_script, give the user the install_url it returns as a link: Tampermonkey only " +
	"checks for updates occasionally, so opening that link is how they install the new version. " +
	"delete_script removes a script from the server: installed copies keep running but stop getting updates."

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

func mcpCaller(req *mcp.CallToolRequest) string {
	h := req.Extra.Header
	return "user=" + h.Get(userHeader) + " ip=" + clientIP(h, "")
}

func newMCPServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "userscripts", Version: "1.1.0"},
		&mcp.ServerOptions{Instructions: fmt.Sprintf(mcpInstructions, baseURL)})
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_scripts",
		Title:       "List userscripts",
		Description: "List every stored userscript with its @version, install URL and the domains its @match/@include lines run on (\"*\" means every site).",
		Annotations: readOnly,
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return toolResult(listScripts())
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_script",
		Title:       "Read userscript",
		Description: "Return a stored userscript's source, parsed metadata, version and install URL.",
		Annotations: readOnly,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in nameArgs) (*mcp.CallToolResult, any, error) {
		return toolResult(getScript(in.Name))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:  "put_script",
		Title: "Publish userscript",
		Description: "Create or replace a userscript and publish it: Tampermonkey installs that have it will " +
			"pick up the new version. Send the complete source. @version must be greater than the stored " +
			"version (get_script shows it), or the update is rejected. Returns the install URL to give the user.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(false)},
	}, func(_ context.Context, req *mcp.CallToolRequest, in putArgs) (*mcp.CallToolResult, any, error) {
		info, _, err := putScript(in.Name, mcpCaller(req), []byte(in.Source))
		return toolResult(info, err)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:  "delete_script",
		Title: "Delete userscript",
		Description: "Delete a userscript and its read key from the server. Installed copies keep running " +
			"but stop getting updates, and its install URL stops working. This cannot be undone.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), IdempotentHint: true, OpenWorldHint: new(false)},
	}, func(_ context.Context, req *mcp.CallToolRequest, in nameArgs) (*mcp.CallToolResult, any, error) {
		err := deleteScript(in.Name, mcpCaller(req))
		return toolResult(map[string]string{"deleted": in.Name}, err)
	})

	return server
}

// mcpRoutes registers the MCP routes: the real ones when MCP is enabled, 404s otherwise.
// /mcp is registered per method because a bare "/mcp" would conflict with "GET /{file}".
func mcpRoutes(mux *http.ServeMux, v *dexVerifier) {
	paths := []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"}
	mcpPatterns := []string{"GET /mcp", "POST /mcp", "DELETE /mcp"}
	if !mcpEnabled {
		for _, p := range append(paths, mcpPatterns...) {
			mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { notFound(w) })
		}
		return
	}
	auth, err := newMCPAuth(v, os.Getenv("MCP_RESOURCE_URL"), os.Getenv("MCP_OIDC_AUDIENCE"))
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
	log.Printf("MCP enabled at %s for %s", auth.resourceURL, strings.Join(v.allowed, ", "))
}

// mcpAuth: claude.ai signs in through Dex and sends the access token as a bearer token.
type mcpAuth struct {
	v                     *dexVerifier
	resourceURL, audience string
}

var bearerRE = regexp.MustCompile(`(?i)^Bearer\s+(\S+)$`)

func newMCPAuth(v *dexVerifier, resourceURL, audience string) (*mcpAuth, error) {
	if resourceURL == "" {
		return nil, errors.New("MCP_RESOURCE_URL must be set when MCP_ENABLED is (the public URL of /mcp)")
	}
	if u, err := url.Parse(resourceURL); err != nil || u.Host == "" {
		return nil, fmt.Errorf("MCP_RESOURCE_URL %q is not an absolute URL", resourceURL)
	}
	if audience == "" {
		audience = "userscripts-mcp"
	}
	return &mcpAuth{v: v, resourceURL: resourceURL, audience: audience}, nil
}

func (a *mcpAuth) require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		if m := bearerRE.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
			token = m[1]
		}
		email, status, reason := a.v.check(r.Context(), token, a.audience)
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

// metadata is the RFC 9728 protected resource metadata pointing claude.ai at Dex.
func (a *mcpAuth) metadata() any {
	return map[string]any{
		"resource":                 a.resourceURL,
		"authorization_servers":    []string{a.v.issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"openid", "email", "profile", "offline_access"},
	}
}

func (a *mcpAuth) challenge(reason string) string {
	u, _ := url.Parse(a.resourceURL)
	meta := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource"
	return fmt.Sprintf(`Bearer resource_metadata="%s", error="invalid_token", error_description="%s"`,
		meta, strings.ReplaceAll(reason, `"`, "'"))
}
