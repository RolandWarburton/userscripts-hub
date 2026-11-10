package main

// The dashboard on ADMIN_DOMAIN: the page under web/ and the admin API, reached only through
// oauth2-proxy. oauth2-proxy signs the browser in with Dex and forwards its access token in
// X-Forwarded-Access-Token; every request here is checked against Dex again (audience
// WEB_OIDC_CLIENT_ID, email in MCP_ALLOWED_EMAILS), so a forged header from another
// container on the network gets nowhere. Nothing on ADMIN_DOMAIN is served without it.

import (
	"embed"
	"html"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strings"
)

//go:embed web
var webFiles embed.FS

// accessTokenHeader is where oauth2-proxy (OAUTH2_PROXY_PASS_ACCESS_TOKEN) puts the token.
const accessTokenHeader = "X-Forwarded-Access-Token"

// The page has no inline script or style and loads nothing from elsewhere.
const adminCSP = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"

func setAdminHeaders(h http.Header) {
	h.Set("Content-Security-Policy", adminCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
}

type webGuard struct {
	v        *dexVerifier
	audience string
}

// wrap serves next only for an allowed Dex user. Writes must also carry X-Requested-With,
// which another site can't add without a CORS preflight this server never answers; the
// session cookie is SameSite=Strict as well, so this is the second lock on that door.
func (g *webGuard) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setAdminHeaders(w.Header())
		email, status, reason := g.v.check(r.Context(), r.Header.Get(accessTokenHeader), g.audience)
		if status != 0 {
			refuse(w, r, status, reason)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Requested-With") == "" {
			refuse(w, r, http.StatusForbidden, "writes need an X-Requested-With header")
			return
		}
		r.Header.Set(userHeader, email)
		next(w, r)
	}
}

// refuse answers the API in JSON and a page load with a minimal page.
func refuse(w http.ResponseWriter, r *http.Request, status int, reason string) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		apiError(w, status, "%s", reason)
		return
	}
	body := "<!doctype html><meta charset=utf-8><title>userscripts</title><p>" + html.EscapeString(reason) +
		`.</p><p><a href="/oauth2/sign_out">Sign out</a></p>`
	send(w, status, "text/html", []byte(body))
}

// webRoutes registers everything on host. A pattern with a host wins over the host-less
// public ones, so the catch-all keeps scripts and /mcp off the dashboard host.
func webRoutes(mux *http.ServeMux, host string, g *webGuard) {
	index, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		log.Fatal(err)
	}
	page := func(w http.ResponseWriter, r *http.Request) { send(w, http.StatusOK, "text/html", index) }
	static, _ := fs.Sub(webFiles, "web/static")

	mux.HandleFunc("GET "+host+"/{$}", g.wrap(page))
	mux.HandleFunc("GET "+host+"/new", g.wrap(page))
	mux.HandleFunc("GET "+host+"/scripts/{name}", g.wrap(page))
	mux.HandleFunc("GET "+host+"/static/{file}", g.wrap(func(w http.ResponseWriter, r *http.Request) {
		file := r.PathValue("file")
		b, err := fs.ReadFile(static, file)
		if err != nil {
			notFound(w)
			return
		}
		types := map[string]string{".css": "text/css", ".js": "text/javascript"}
		ct, ok := types[path.Ext(file)]
		if !ok {
			notFound(w)
			return
		}
		send(w, http.StatusOK, ct, b)
	}))
	mux.HandleFunc("GET "+host+"/api/me", g.wrap(func(w http.ResponseWriter, r *http.Request) {
		sendJSON(w, http.StatusOK, map[string]string{"email": r.Header.Get(userHeader)})
	}))
	mux.HandleFunc("GET "+host+"/api/scripts", g.wrap(apiList))
	mux.HandleFunc("GET "+host+"/api/scripts/{name}", g.wrap(apiGet))
	mux.HandleFunc("PUT "+host+"/api/scripts/{name}", g.wrap(apiPut))
	mux.HandleFunc("DELETE "+host+"/api/scripts/{name}", g.wrap(apiDelete))
	mux.HandleFunc(host+"/", g.wrap(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiError(w, http.StatusNotFound, "no such endpoint: %s %s", r.Method, r.URL.Path)
			return
		}
		notFound(w)
	}))
}
