package main

// Per-script read keys in KEYS_DIR, which public downloads need in ?auth=, plus the
// constant-time comparison used for those keys.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io/fs"
	"log"
	"os"
	"strings"
)

func readKey(name string) (string, error) {
	b, err := os.ReadFile(keyPath(name))
	return strings.TrimSpace(string(b)), err
}

// ensureKey returns the script's read key, creating it if it doesn't exist.
func ensureKey(name string) (string, error) {
	key, err := readKey(name)
	if !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}

	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key = base64.RawURLEncoding.EncodeToString(buf)

	// O_EXCL fails if another request created the file first
	f, err := os.OpenFile(keyPath(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return readKey(name)
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(key + "\n"); err != nil {
		return "", err
	}
	log.Printf("[keygen] %s: %s", name, key)
	return key, nil
}

// tokensMatch compares in constant time; hashing first makes the lengths match.
func tokensMatch(given, expected string) bool {
	if given == "" || expected == "" {
		return false
	}
	a := sha256.Sum256([]byte(given))
	b := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
