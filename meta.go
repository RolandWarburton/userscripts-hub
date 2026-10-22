package main

// Parses a script's ==UserScript== block and rewrites it, swapping in this server's
// @updateURL/@downloadURL on both upload and download.

import (
	"regexp"
	"strings"
)

var fieldRE = regexp.MustCompile(`^//\s*@(\S+)(?:\s+(.*?))?\s*$`)

type meta struct {
	start, end int // line indices of the ==UserScript== and ==/UserScript== markers
	fields     map[string][]string
}

func (m *meta) get(k string) string {
	if v := m.fields[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// parseMeta finds the ==UserScript== block, or returns nil if there isn't a complete one.
func parseMeta(lines []string) *meta {
	m := &meta{start: -1, fields: map[string][]string{}}
	for i, l := range lines {
		l = strings.TrimSpace(l)
		switch {
		case m.start < 0:
			if strings.HasPrefix(l, "// ==UserScript==") {
				m.start = i
			}
		case strings.HasPrefix(l, "// ==/UserScript=="):
			m.end = i
			return m
		default:
			if f := fieldRE.FindStringSubmatch(l); f != nil {
				m.fields[f[1]] = append(m.fields[f[1]], f[2])
			}
		}
	}
	return nil
}

func isURLField(l string) bool {
	f := fieldRE.FindStringSubmatch(strings.TrimSpace(l))
	return f != nil && (f[1] == "updateURL" || f[1] == "downloadURL")
}

// rewriteMeta returns lines[from:to] with @updateURL/@downloadURL dropped from the
// metadata block and extra inserted before its closing marker. For example, with
// extra = []string{"// @updateURL    https://…/x.meta.js?auth=KEY"}:
//
//	// ==UserScript==                    // ==UserScript==
//	// @name     x                       // @name     x
//	// @version  1.2                 →   // @version  1.2
//	// @updateURL https://old/x.js       // @updateURL    https://…/x.meta.js?auth=KEY
//	// ==/UserScript==                   // ==/UserScript==
func rewriteMeta(lines []string, m *meta, from, to int, extra []string) string {
	var b strings.Builder
	for i := from; i < to; i++ {
		if i == m.end {
			for _, e := range extra {
				b.WriteString(e)
				b.WriteByte('\n')
			}
		}
		if i > m.start && i < m.end && isURLField(lines[i]) {
			continue
		}
		b.WriteString(lines[i])
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
