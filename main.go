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
	minToken  = 32
)

var (
	scriptsDir = env("SCRIPTS_DIR", "/scripts")
	keysDir    = env("KEYS_DIR", "/keys")
	port       = env("PORT", "8080")
	baseURL    = strings.TrimSuffix(os.Getenv("BASE_URL"), "/") // derived from the request if unset
	adminToken = os.Getenv("ADMIN_TOKEN")
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

	if len(adminToken) < minToken {
		log.Fatalf("ADMIN_TOKEN must be set and at least %d characters (openssl rand -base64 32)", minToken)
	}
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
	mux.HandleFunc("PUT /api/scripts/{name}", requireAdmin(apiPut))
	mux.HandleFunc("GET /api/scripts", requireAdmin(apiList))
	mux.HandleFunc("GET /api/scripts/{name}", requireAdmin(apiGet))
	mux.HandleFunc("DELETE /api/scripts/{name}", requireAdmin(apiDelete))
	mcpRoutes(mux)
	mux.HandleFunc("/api/", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "no such endpoint: %s %s", r.Method, r.URL.Path)
	}))

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("serving %s (keys in %s) on :%s", scriptsDir, keysDir, port)
	log.Fatal(srv.ListenAndServe())
}
