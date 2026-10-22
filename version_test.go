package main

// Tests for compareVersions in version.go.

import "testing"

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.10", "1.9", 1},
		{"2", "1.9.9", 1},
		{"1.0", "1", 0},
		{"1.0", "1.0b", 1},
		{"1.0b", "1.0a", 1},
		{"1.01", "1.1", 0},
		{"2026.10.22", "2026.10.3", 1},
		{"99999999999999999999", "9", 1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := compareVersions(c.b, c.a); got != -c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
