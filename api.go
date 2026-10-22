package main

// Admin API under /api/, every route behind the ADMIN_TOKEN bearer token:
// GET /api/scripts, GET/PUT/DELETE /api/scripts/{name}. The putScript,
// listScripts and getScript helpers here are also what the MCP tools call.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var writeMu sync.Mutex // serialises API writes so the version check can't race

func sendJSON(w http.ResponseWriter, status int, v any) {
	body, _ := json.Marshal(v)
	send(w, status, "application/json", append(body, '\n'))
}

func apiError(w http.ResponseWriter, status int, format string, args ...any) {
	sendJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}

// scriptError is a failure the caller can be told about, with the HTTP status that fits it.
// Internal errors are logged where they happen and reported only as a generic message.
type scriptError struct {
	status int
	msg    string
}

func (e *scriptError) Error() string { return e.msg }

func fail(status int, format string, args ...any) error {
	return &scriptError{status, fmt.Sprintf(format, args...)}
}

func sendError(w http.ResponseWriter, err error) {
	var se *scriptError
	if !errors.As(err, &se) {
		se = &scriptError{http.StatusInternalServerError, "internal error"}
	}
	apiError(w, se.status, "%s", se.msg)
}

// requireAdmin accepts only "Authorization: Bearer <ADMIN_TOKEN>".
func requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !tokensMatch(token, adminToken) {
			apiError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r)
	}
}

type scriptInfo struct {
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	InstallURL string              `json:"install_url"`
	Key        string              `json:"key,omitempty"`
	SHA256     string              `json:"sha256,omitempty"`
	Size       int                 `json:"size,omitempty"`
	Modified   *time.Time          `json:"modified,omitempty"`
	Metadata   map[string][]string `json:"metadata,omitempty"`
	Source     string              `json:"source,omitempty"`
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// storedVersion returns the stored script's @version, or "" if there's no script or no version.
func storedVersion(name string) (string, bool, error) {
	src, err := os.ReadFile(scriptPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if m := parseMeta(strings.Split(string(src), "\n")); m != nil {
		return m.get("version"), true, nil
	}
	return "", true, nil
}

// writeAtomic writes via a temp file and rename so a reader never sees half a script.
func writeAtomic(p string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".tmp-*") // dotfiles are skipped by scan
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op once renamed
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

func checkName(name string) error {
	if !nameRE.MatchString(name) {
		return fail(http.StatusBadRequest, "name must match %s", nameRE)
	}
	return nil
}

// putScript stores src as the script name, provided its @version is greater than the
// stored one. who identifies the caller in the audit log. It reports whether the script is new.
func putScript(base, name, who string, src []byte) (scriptInfo, bool, error) {
	if err := checkName(name); err != nil {
		return scriptInfo{}, false, err
	}
	if len(src) > maxUpload {
		return scriptInfo{}, false, fail(http.StatusRequestEntityTooLarge, "script exceeds %d bytes", maxUpload)
	}

	lines := strings.Split(string(src), "\n")
	m := parseMeta(lines)
	switch {
	case m == nil:
		return scriptInfo{}, false, fail(http.StatusBadRequest, "missing // ==UserScript== ... // ==/UserScript== block")
	case m.get("name") == "":
		return scriptInfo{}, false, fail(http.StatusBadRequest, "missing @name")
	case m.get("version") == "":
		return scriptInfo{}, false, fail(http.StatusBadRequest, "missing @version")
	}
	version := m.get("version")
	// keys never live in stored source; they're injected when served
	src = []byte(rewriteMeta(lines, m, 0, len(lines), nil))

	writeMu.Lock()
	defer writeMu.Unlock()

	oldVer, exists, err := storedVersion(name)
	if err != nil {
		log.Printf("[api] %s: %v", name, err)
		return scriptInfo{}, false, fail(http.StatusInternalServerError, "reading stored script failed")
	}
	if exists && compareVersions(version, oldVer) <= 0 {
		return scriptInfo{}, false, fail(http.StatusConflict, "@version %s is not greater than stored %s; Tampermonkey would ignore the update", version, oldVer)
	}
	key, err := ensureKey(name)
	if err == nil {
		err = writeAtomic(scriptPath(name), src)
	}
	if err != nil {
		log.Printf("[api] %s: %v", name, err)
		return scriptInfo{}, false, fail(http.StatusInternalServerError, "writing script failed")
	}

	sum := sha(src)
	audit(who, "put", name, oldVer, version, sum)
	return scriptInfo{
		Name:       name,
		Version:    version,
		InstallURL: scriptURL(base, name, scriptExt, key),
		Key:        key,
		SHA256:     sum,
		Size:       len(src),
	}, !exists, nil
}

// listScripts returns every stored script's name, version and install URL.
func listScripts(base string) ([]scriptInfo, error) {
	entries, err := os.ReadDir(scriptsDir)
	if err != nil {
		log.Printf("[api] %v", err)
		return nil, fail(http.StatusInternalServerError, "listing scripts failed")
	}
	list := []scriptInfo{}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), scriptExt)
		if !ok || e.IsDir() || !nameRE.MatchString(name) {
			continue
		}
		version, _, err := storedVersion(name)
		if err != nil {
			log.Printf("[api] %s: %v", name, err)
			continue
		}
		key, err := ensureKey(name)
		if err != nil {
			log.Printf("[api] %s: %v", name, err)
			continue
		}
		list = append(list, scriptInfo{Name: name, Version: version, InstallURL: scriptURL(base, name, scriptExt, key)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

// getScript returns a stored script with its source and metadata.
func getScript(base, name string) (scriptInfo, error) {
	if err := checkName(name); err != nil {
		return scriptInfo{}, err
	}
	p := scriptPath(name)
	src, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return scriptInfo{}, fail(http.StatusNotFound, "no script %q", name)
	}
	var st fs.FileInfo
	if err == nil {
		st, err = os.Stat(p)
	}
	var key string
	if err == nil {
		key, err = ensureKey(name)
	}
	if err != nil {
		log.Printf("[api] %s: %v", name, err)
		return scriptInfo{}, fail(http.StatusInternalServerError, "reading script failed")
	}

	info := scriptInfo{
		Name:       name,
		InstallURL: scriptURL(base, name, scriptExt, key),
		Key:        key,
		SHA256:     sha(src),
		Size:       len(src),
		Source:     string(src),
	}
	mod := st.ModTime().UTC()
	info.Modified = &mod
	if m := parseMeta(strings.Split(string(src), "\n")); m != nil {
		info.Version = m.get("version")
		info.Metadata = m.fields
	}
	return info, nil
}

// apiPut handles PUT /api/scripts/<name> with the raw script as the body.
func apiPut(w http.ResponseWriter, r *http.Request) {
	src, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxUpload))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			apiError(w, http.StatusRequestEntityTooLarge, "script exceeds %d bytes", maxUpload)
			return
		}
		apiError(w, http.StatusBadRequest, "reading body: %v", err)
		return
	}
	info, created, err := putScript(base(r), r.PathValue("name"), "ip="+clientIP(r.Header, r.RemoteAddr), src)
	if err != nil {
		sendError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	sendJSON(w, status, info)
}

// apiList handles GET /api/scripts.
func apiList(w http.ResponseWriter, r *http.Request) {
	list, err := listScripts(base(r))
	if err != nil {
		sendError(w, err)
		return
	}
	sendJSON(w, http.StatusOK, list)
}

// apiGet handles GET /api/scripts/<name>.
func apiGet(w http.ResponseWriter, r *http.Request) {
	info, err := getScript(base(r), r.PathValue("name"))
	if err != nil {
		sendError(w, err)
		return
	}
	sendJSON(w, http.StatusOK, info)
}

// apiDelete handles DELETE /api/scripts/<name>, removing the script and its key.
func apiDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nameRE.MatchString(name) {
		apiError(w, http.StatusBadRequest, "name must match %s", nameRE)
		return
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	oldVer, exists, err := storedVersion(name)
	if err == nil && exists {
		err = os.Remove(scriptPath(name))
	}
	// remove the key even if the script was already gone, so no orphan is left behind
	if kerr := os.Remove(keyPath(name)); err == nil && !errors.Is(kerr, fs.ErrNotExist) {
		err = kerr
	}
	if err != nil {
		log.Printf("[api] %s: %v", name, err)
		apiError(w, http.StatusInternalServerError, "deleting script failed")
		return
	}
	if !exists {
		apiError(w, http.StatusNotFound, "no script %q", name)
		return
	}
	audit("ip="+clientIP(r.Header, r.RemoteAddr), "delete", name, oldVer, "", "")
	sendJSON(w, http.StatusOK, map[string]string{"deleted": name})
}
