package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	scriptExt = ".user.js"
	metaExt   = ".meta.js"
	maxUpload = 1 << 20
)

var (
	scriptsDir = env("SCRIPTS_DIR", "/scripts")
	keysDir    = env("KEYS_DIR", "/keys")
	port       = env("PORT", "8080")
	baseURL    = strings.TrimSuffix(os.Getenv("BASE_URL"), "/") // the public script host, e.g. https://userscripts.example.net
	ntfyURL    = os.Getenv("NTFY_URL")
	ntfyToken  = os.Getenv("NTFY_TOKEN")

	nameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`) // also prevents path traversal
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func scriptPath(name string) string { return filepath.Join(scriptsDir, name+scriptExt) }
func keyPath(name string) string    { return filepath.Join(keysDir, name) }

// healthcheck is run by the container healthcheck, since the scratch image has no wget/curl.
func healthcheck() {
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
	}

	if baseURL == "" {
		log.Fatalf("BASE_URL must be set (the public URL scripts are served from)")
	}
	adminDomain := os.Getenv("ADMIN_DOMAIN")
	if adminDomain == "" || strings.ContainsAny(adminDomain, "/:") {
		log.Fatalf("ADMIN_DOMAIN must be set to the dashboard's host name, e.g. userscripts-admin.example.net")
	}
	verifier, err := newDexVerifier(os.Getenv("MCP_OIDC_ISSUER"), os.Getenv("MCP_ALLOWED_EMAILS"))
	if err != nil {
		log.Fatal(err)
	}
	webAudience := env("WEB_OIDC_CLIENT_ID", "userscripts-web")
	if ntfyURL == "" {
		log.Printf("NTFY_URL not set: API writes will only be logged")
	} else if ntfyToken == "" {
		log.Fatalf("NTFY_TOKEN must be set when NTFY_URL is")
	}

	scan()
	go func() {
		for range time.Tick(30 * time.Second) {
			scan()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		send(w, http.StatusOK, "text/plain", []byte("ok"))
	})
	mux.HandleFunc("GET /{file}", servePublic) // GET patterns also match HEAD
	mcpRoutes(mux, verifier)
	webRoutes(mux, adminDomain, &webGuard{v: verifier, audience: webAudience})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("serving %s (keys in %s) on :%s; dashboard on %s for %s", scriptsDir, keysDir, port,
		adminDomain, strings.Join(verifier.allowed, ", "))
	log.Fatal(srv.ListenAndServe())
}
