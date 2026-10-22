package main

// Runs at startup and every 30s: creates keys for scripts copied into SCRIPTS_DIR by hand
// and logs, once each, badly named files and keys with no script.

import (
	"log"
	"os"
	"strings"
)

// warned remembers what scan already complained about, so each problem is logged once.
var warned = map[string]bool{}

func warnOnce(seen map[string]bool, id, format string, args ...any) {
	seen[id] = true
	if !warned[id] {
		log.Printf("[scan] "+format, args...)
	}
}

// scan creates keys for scripts copied in by hand and warns about files it can't serve.
func scan() {
	seen := map[string]bool{}
	defer func() { warned = seen }() // a fixed problem can warn again if it comes back

	scripts := map[string]bool{}
	entries, err := os.ReadDir(scriptsDir)
	if err != nil {
		log.Printf("[scan] %v", err)
		return
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, ".") {
			continue
		}
		name, ok := strings.CutSuffix(n, scriptExt)
		if !ok || e.IsDir() || !nameRE.MatchString(name) {
			warnOnce(seen, "bad:"+n, "ignoring %s: scripts must be files named <name>%s, name matching %s", n, scriptExt, nameRE)
			continue
		}
		scripts[name] = true
		if _, err := ensureKey(name); err != nil {
			warnOnce(seen, "key:"+name, "%s: %v", name, err)
		}
	}

	keys, err := os.ReadDir(keysDir)
	if err != nil {
		log.Printf("[scan] %v", err)
		return
	}
	for _, e := range keys {
		if n := e.Name(); !strings.HasPrefix(n, ".") && !scripts[n] {
			warnOnce(seen, "orphan:"+n, "key %s has no script %s%s", n, n, scriptExt)
		}
	}
}
