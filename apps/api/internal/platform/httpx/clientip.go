package httpx

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	proxyKeyHeader      = "X-Swastik-Proxy-Key"
	proxyClientIPHeader = "X-Swastik-Client-IP"
)

// ClientIP returns the caller's IP address as a bare string.
//
// When the request carries an X-Swastik-Proxy-Key equal to one of proxySecrets (every entry is
// compared in constant time) and exactly one X-Swastik-Client-IP holding a bare valid IP address,
// that address is the answer. In every other case both headers are ignored: with hops <= 0 only
// RemoteAddr is used, otherwise the X-Forwarded-For entry hops from the end is used (entries before
// it are client-controlled and never trusted). Anything missing or not a valid IP falls back to the
// RemoteAddr host.
func ClientIP(r *http.Request, hops int, proxySecrets ...string) string {
	if ip, ok := trustedProxyIP(r, proxySecrets); ok {
		return ip
	}
	peer := remoteHost(r.RemoteAddr)
	if hops <= 0 {
		return peer
	}
	var entries []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		entries = append(entries, strings.Split(line, ",")...)
	}
	if len(entries) < hops {
		return peer
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(entries[len(entries)-hops]))
	if err != nil {
		return peer
	}
	return addr.String()
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// trustedProxyIP returns the proxy-supplied client address when the proxy key header matches.
func trustedProxyIP(r *http.Request, secrets []string) (string, bool) {
	keys, ips := r.Header.Values(proxyKeyHeader), r.Header.Values(proxyClientIPHeader)
	if len(secrets) == 0 || len(keys) != 1 || len(ips) != 1 || keys[0] == "" {
		return "", false
	}
	if !matchesAny(keys[0], secrets) {
		return "", false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ips[0]))
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	return addr.String(), true
}

// matchesAny compares key with every secret in constant time; empty secrets never match.
func matchesAny(key string, secrets []string) bool {
	k := sha256.Sum256([]byte(key))
	matched := 0
	for _, s := range secrets {
		if s == "" {
			continue
		}
		h := sha256.Sum256([]byte(s))
		matched |= subtle.ConstantTimeCompare(k[:], h[:])
	}
	return matched == 1
}
