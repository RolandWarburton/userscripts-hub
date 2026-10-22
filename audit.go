package main

// Records every script write: a log line per put or delete, also pushed to ntfy when
// NTFY_URL is set. Log output only, so the trail lasts as long as the container's log.

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func clientIP(h http.Header, remoteAddr string) string {
	if ip := h.Get("X-Real-Ip"); ip != "" { // set by Traefik, the only thing that can reach us
		return ip
	}
	host, _, _ := net.SplitHostPort(remoteAddr)
	return host
}

// audit logs a write and pushes it to ntfy without making the request wait.
// who identifies the caller, e.g. "ip=1.2.3.4" or "user=a@b.c ip=1.2.3.4".
func audit(who, action, name, oldVer, newVer, sum string) {
	msg := fmt.Sprintf("%s %s %s old=%q new=%q sha256=%s", action, name, who, oldVer, newVer, sum)
	log.Printf("[audit] %s", msg)
	if ntfyURL == "" {
		return
	}
	go func() {
		req, err := http.NewRequest(http.MethodPost, ntfyURL, strings.NewReader(msg))
		if err != nil {
			log.Printf("[ntfy] %v", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+ntfyToken)
		req.Header.Set("Title", "userscripts: "+action+" "+name)
		req.Header.Set("Tags", "warning")
		c := http.Client{Timeout: 10 * time.Second}
		resp, err := c.Do(req)
		if err != nil {
			log.Printf("[ntfy] %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("[ntfy] %s", resp.Status)
		}
	}()
}
