package main

// Script downloads for Tampermonkey: no admin token or sign-in, but each script
// needs its own read key in ?auth=. Also holds the response helpers the other files share.

import (
	"errors"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func send(w http.ResponseWriter, status int, contentType string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentType+"; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(body) // dropped automatically for HEAD
}

func notFound(w http.ResponseWriter) {
	send(w, http.StatusNotFound, "text/plain", []byte("not found"))
}

func scriptURL(base, name, ext, key string) string {
	return base + "/" + name + ext + "?auth=" + url.QueryEscape(key)
}

// servePublic handles GET /<name>.user.js?auth=KEY and GET /<name>.meta.js?auth=KEY.
// Every failure is the same 404, so names can't be probed.
func servePublic(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	name, full := strings.CutSuffix(file, scriptExt)
	if !full {
		var ok bool
		if name, ok = strings.CutSuffix(file, metaExt); !ok {
			notFound(w)
			return
		}
	}
	if !nameRE.MatchString(name) {
		notFound(w)
		return
	}

	// Read the script before touching the key, so unknown names never get one
	src, err := os.ReadFile(scriptPath(name))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Printf("[req] %s: %v", name, err)
		}
		notFound(w)
		return
	}
	key, err := ensureKey(name)
	if err != nil {
		log.Printf("[req] %s: %v", name, err)
		notFound(w)
		return
	}
	if !tokensMatch(r.URL.Query().Get("auth"), key) {
		notFound(w)
		return
	}

	lines := strings.Split(string(src), "\n")
	m := parseMeta(lines)
	if m == nil {
		// hand-copied script without a metadata block: serve it as-is, but there's no meta to give
		if !full {
			notFound(w)
			return
		}
		send(w, http.StatusOK, "application/javascript", src)
		return
	}
	extra := []string{
		"// @updateURL    " + scriptURL(baseURL, name, metaExt, key),
		"// @downloadURL  " + scriptURL(baseURL, name, scriptExt, key),
	}
	from, to := 0, len(lines)
	if !full {
		from, to = m.start, m.end+1
	}
	send(w, http.StatusOK, "application/javascript", []byte(rewriteMeta(lines, m, from, to, extra)))
}
