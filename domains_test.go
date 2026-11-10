package main

import (
	"slices"
	"strings"
	"testing"
)

func TestSiteDomains(t *testing.T) {
	src := `// ==UserScript==
// @name     x
// @version  1
// @match    https://*.github.com/*
// @match    https://github.com/foo/*
// @include  http*://www.reddit.com/*
// @include  /^https?://example\.org/.*$/
// @match    file:///home/*
// @match    https://localhost:8080/*
// @include  *://*.example.*/*
// @exclude  https://evil.com/*
// ==/UserScript==`
	got := siteDomains(parseMeta(strings.Split(src, "\n")))
	want := []string{"example.*", "github.com", "localhost", "reddit.com"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	for _, p := range []string{"*", "<all_urls>", "*://*/*", "https://*/*"} {
		if d, ok := patternDomain(p); !ok || d != allSites {
			t.Errorf("%q: got %q %v, want %q", p, d, ok, allSites)
		}
	}
}
