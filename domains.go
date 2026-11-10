package main

// Works out which sites a script runs on from its @match and @include lines, so the
// script list can be tagged and filtered by domain. Read from the script on every list,
// never stored.

import (
	"sort"
	"strings"
)

// allSites tags a script that runs everywhere (<all_urls>, *://*/*, a bare *).
const allSites = "*"

// siteDomains returns the sorted, de-duplicated domains in m's @match and @include lines.
// For example:
//
//	@match   https://*.github.com/*   → github.com
//	@include http*://www.reddit.com/* → reddit.com
//	@match   *://*/*                  → *
//
// Regex @includes (/…/) and file:// patterns have no single domain and are skipped.
func siteDomains(m *meta) []string {
	seen := map[string]bool{}
	for _, k := range []string{"match", "include"} {
		for _, p := range m.fields[k] {
			if d, ok := patternDomain(p); ok {
				seen[d] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func patternDomain(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" || len(p) > 1 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
		return "", false // regex
	}
	if p == "*" || p == "<all_urls>" {
		return allSites, true
	}
	_, rest, ok := strings.Cut(p, "://")
	if !ok {
		return "", false
	}
	host, _, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimLeft(host, "*.")
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		if strings.HasPrefix(rest, "/") {
			return "", false // file:///…
		}
		return allSites, true
	}
	return host, true
}
