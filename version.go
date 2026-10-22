package main

// Compares @version strings the way Tampermonkey does, so the server's "must be newer"
// check agrees with when Tampermonkey will actually update.

import "strings"

// compareVersions orders versions the way Tampermonkey does: dot-separated parts,
// numeric prefix first, and a bare number above the same number with a suffix (1.0 > 1.0b).
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		x, y := "0", "0"
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if c := comparePart(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func comparePart(x, y string) int {
	nx, rx := splitDigits(x)
	ny, ry := splitDigits(y)
	// compare numbers as strings so long ones can't overflow
	nx, ny = strings.TrimLeft(nx, "0"), strings.TrimLeft(ny, "0")
	if len(nx) != len(ny) {
		return cmpInt(len(nx), len(ny))
	}
	if c := strings.Compare(nx, ny); c != 0 {
		return c
	}
	switch {
	case rx == ry:
		return 0
	case rx == "":
		return 1
	case ry == "":
		return -1
	}
	return strings.Compare(rx, ry)
}

func splitDigits(s string) (string, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	return 1
}
