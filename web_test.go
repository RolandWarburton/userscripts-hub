package main

// Tests for the dashboard host in web.go and the Dex checks in auth.go, against a fake Dex.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const adminHost = "admin.test"

// fakeToken is JWT-shaped, with the aud claim the audience check reads.
func fakeToken(aud, who string) string {
	payload, _ := json.Marshal(map[string]string{"aud": aud, "sub": who})
	return "h." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// newTestServer starts a fake Dex whose userinfo knows the tokens in users (token -> email),
// and returns the server's mux with the dashboard on adminHost.
func newTestServer(t *testing.T, users map[string]string) *http.ServeMux {
	t.Helper()
	dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if r.URL.Path != "/userinfo" || !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"email": email, "email_verified": true})
	}))
	t.Cleanup(dex.Close)

	scriptsDir, keysDir, baseURL = t.TempDir(), t.TempDir(), "https://scripts.test"
	v, err := newDexVerifier(dex.URL, "me@example.net")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{file}", servePublic)
	mcpRoutes(mux, v) // MCP_ENABLED is unset in tests: registers 404s
	webRoutes(mux, adminHost, &webGuard{v: v, audience: "userscripts-web"})
	return mux
}

func do(mux *http.ServeMux, method, host, path, token, body string, write bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	if token != "" {
		r.Header.Set(accessTokenHeader, token)
	}
	if write {
		r.Header.Set("X-Requested-With", "fetch")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestDashboardAccess(t *testing.T) {
	good := fakeToken("userscripts-web", "me")
	mcpToken := fakeToken("userscripts-mcp", "me")
	other := fakeToken("userscripts-web", "someone")
	mux := newTestServer(t, map[string]string{
		good: "me@example.net", mcpToken: "me@example.net", other: "someone@example.net",
	})

	for _, c := range []struct {
		name, host, path, token string
		want                    int
	}{
		{"page with a dashboard token", adminHost, "/", good, 200},
		{"deep link", adminHost, "/scripts/x", good, 200},
		{"static file", adminHost, "/static/app.js", good, 200},
		{"no token", adminHost, "/", "", 401},
		{"MCP token on the dashboard", adminHost, "/api/scripts", mcpToken, 401},
		{"forged token Dex doesn't know", adminHost, "/api/scripts", fakeToken("userscripts-web", "x"), 401},
		{"allowed by Dex, not on the list", adminHost, "/api/scripts", other, 403},
		{"API list", adminHost, "/api/scripts", good, 200},
		{"public scripts are not on the dashboard host", adminHost, "/x.user.js", good, 404},
		{"no dashboard API on the public host", "scripts.test", "/api/scripts", good, 404},
		{"no dashboard page on the public host", "scripts.test", "/", good, 404},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := do(mux, "GET", c.host, c.path, c.token, "", false)
			if w.Code != c.want {
				t.Fatalf("got %d, want %d: %s", w.Code, c.want, w.Body)
			}
			if c.host == adminHost && w.Header().Get("Content-Security-Policy") != adminCSP {
				t.Errorf("missing CSP on %s", c.path)
			}
		})
	}
}

func TestDashboardWrites(t *testing.T) {
	good := fakeToken("userscripts-web", "me")
	mux := newTestServer(t, map[string]string{good: "me@example.net"})
	src := "// ==UserScript==\n// @name x\n// @version 1.0\n// ==/UserScript==\nalert(1)\n"

	if w := do(mux, "PUT", adminHost, "/api/scripts/x", good, src, false); w.Code != 403 {
		t.Fatalf("PUT without X-Requested-With: got %d, want 403", w.Code)
	}
	if w := do(mux, "PUT", adminHost, "/api/scripts/x", good, src, true); w.Code != 201 {
		t.Fatalf("create: got %d: %s", w.Code, w.Body)
	}
	if w := do(mux, "PUT", adminHost, "/api/scripts/x", good, src, true); w.Code != 409 {
		t.Fatalf("same version again: got %d, want 409", w.Code)
	}

	w := do(mux, "GET", adminHost, "/api/scripts", good, "", false)
	var list []scriptInfo
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Modified == nil || list[0].Size == 0 ||
		!strings.HasPrefix(list[0].InstallURL, "https://scripts.test/x.user.js?auth=") {
		t.Fatalf("list: %s", w.Body)
	}

	if w := do(mux, "DELETE", adminHost, "/api/scripts/x", good, "", false); w.Code != 403 {
		t.Fatalf("DELETE without X-Requested-With: got %d, want 403", w.Code)
	}
	if w := do(mux, "DELETE", adminHost, "/api/scripts/x", good, "", true); w.Code != 200 {
		t.Fatalf("delete: got %d: %s", w.Code, w.Body)
	}
	if w := do(mux, "DELETE", adminHost, "/api/scripts/x", good, "", true); w.Code != 404 {
		t.Fatalf("delete again: got %d, want 404", w.Code)
	}
}

func TestMCPAudience(t *testing.T) {
	webToken := fakeToken("userscripts-web", "me")
	// The audience is checked before Dex is asked, so no Dex is needed here.
	v, _ := newDexVerifier("http://unused.invalid", "me@example.net")
	a, _ := newMCPAuth(v, "https://scripts.test/mcp", "")
	if _, status, _ := a.v.check(t.Context(), webToken, a.audience); status != http.StatusUnauthorized {
		t.Fatalf("dashboard token accepted by the MCP check: status %d", status)
	}
}
