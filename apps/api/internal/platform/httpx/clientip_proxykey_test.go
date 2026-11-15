// Review-fix tests for httpx.ClientIP with the proxy key (feature 003; owner decision
// 2026-11-15_proxy_key).
//
// API assumption: ClientIP gains trailing variadic secrets, so the existing two-argument calls keep
// compiling:
//
//	ClientIP(r *http.Request, hops int, proxySecrets ...string) string
//
// Rules: the X-Swastik-Client-IP header is trusted only when X-Swastik-Proxy-Key equals one of
// proxySecrets (compared in constant time; empty secrets and an empty header never match). A
// trusted header holding a bare, valid IP address (v4 or v6, no port, no list, no zone) is the
// answer. In every other case (no secrets, no key, wrong key, malformed address) both headers are
// ignored and the answer is the X-Forwarded-For hops logic of clientip_test.go, so a caller that
// reaches the API directly cannot choose the address that is audited and rate limited.
package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

const (
	pkPeer    = "198.51.100.9"
	pkKeyA    = "proxy-secret-A-0123456789abcdefABCDEF"
	pkKeyB    = "proxy-secret-B-0123456789abcdefABCDEF"
	pkRealIP  = "203.0.113.50"
	pkForged  = "6.6.6.6"
	pkXFFLast = "203.0.113.7"
)

type pkReq struct {
	remote string
	xff    []string
	key    []string // each element is one X-Swastik-Proxy-Key header line
	ip     []string // each element is one X-Swastik-Client-IP header line
}

func (p pkReq) build() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = p.remote
	if r.RemoteAddr == "" {
		r.RemoteAddr = pkPeer + ":4321"
	}
	for _, v := range p.xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	for _, v := range p.key {
		r.Header.Add("X-Swastik-Proxy-Key", v)
	}
	for _, v := range p.ip {
		r.Header.Add("X-Swastik-Client-IP", v)
	}
	return r
}

func TestClientIP_ProxyKey_TrustedHeaderWinsWithAMatchingKey(t *testing.T) {
	tests := []struct {
		name    string
		req     pkReq
		hops    int
		secrets []string
		want    string
	}{
		{"first secret, hops 0", pkReq{key: []string{pkKeyA}, ip: []string{pkRealIP}}, 0, []string{pkKeyA, pkKeyB}, pkRealIP},
		{"second secret (rotation), hops 0", pkReq{key: []string{pkKeyB}, ip: []string{pkRealIP}}, 0, []string{pkKeyA, pkKeyB}, pkRealIP},
		{"only the new secret configured", pkReq{key: []string{pkKeyB}, ip: []string{pkRealIP}}, 1, []string{pkKeyB}, pkRealIP},
		{"wins over XFF with hops 1", pkReq{xff: []string{pkForged + ", " + pkXFFLast}, key: []string{pkKeyA}, ip: []string{pkRealIP}}, 1, []string{pkKeyA}, pkRealIP},
		{"wins over RemoteAddr", pkReq{remote: "192.0.2.1:99", key: []string{pkKeyA}, ip: []string{pkRealIP}}, 0, []string{pkKeyA}, pkRealIP},
		{"ipv6 address", pkReq{key: []string{pkKeyA}, ip: []string{"2001:db8::1"}}, 1, []string{pkKeyA}, "2001:db8::1"},
		{"surrounding whitespace is trimmed", pkReq{key: []string{pkKeyA}, ip: []string{"  " + pkRealIP + " "}}, 1, []string{pkKeyA}, pkRealIP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpx.ClientIP(tt.req.build(), tt.hops, tt.secrets...); got != tt.want {
				t.Errorf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIP_ProxyKey_UntrustedHeaderIsIgnoredAndTheXFFLogicApplies(t *testing.T) {
	tests := []struct {
		name    string
		req     pkReq
		hops    int
		secrets []string
		want    string
	}{
		{"wrong key, hops 1", pkReq{xff: []string{pkXFFLast}, key: []string{"wrong-key-0123456789abcdefABCDEFGH"}, ip: []string{pkForged}}, 1, []string{pkKeyA, pkKeyB}, pkXFFLast},
		{"key differing in the last character", pkReq{xff: []string{pkXFFLast}, key: []string{pkKeyA[:len(pkKeyA)-1] + "x"}, ip: []string{pkForged}}, 1, []string{pkKeyA}, pkXFFLast},
		{"key that is a prefix of a secret", pkReq{xff: []string{pkXFFLast}, key: []string{pkKeyA[:20]}, ip: []string{pkForged}}, 1, []string{pkKeyA}, pkXFFLast},
		{"key that extends a secret", pkReq{xff: []string{pkXFFLast}, key: []string{pkKeyA + "x"}, ip: []string{pkForged}}, 1, []string{pkKeyA}, pkXFFLast},
		{"key differing only in case", pkReq{xff: []string{pkXFFLast}, key: []string{strings.ToUpper(pkKeyA)}, ip: []string{pkForged}}, 1, []string{pkKeyA}, pkXFFLast},
		{"no key header, hops 1", pkReq{xff: []string{pkXFFLast}, ip: []string{pkForged}}, 1, []string{pkKeyA}, pkXFFLast},
		{"client ip without a key, hops 0 is RemoteAddr", pkReq{ip: []string{pkForged}}, 0, []string{pkKeyA}, pkPeer},
		{"wrong key, hops 0 is RemoteAddr", pkReq{key: []string{"nope"}, ip: []string{pkForged}}, 0, []string{pkKeyA}, pkPeer},
		{"no secrets configured, even with a key header", pkReq{xff: []string{pkXFFLast}, key: []string{pkKeyA}, ip: []string{pkForged}}, 1, nil, pkXFFLast},
		{"no secrets configured and an empty key header", pkReq{key: []string{""}, ip: []string{pkForged}}, 0, nil, pkPeer},
		{"an empty configured secret never matches an empty key", pkReq{key: []string{""}, ip: []string{pkForged}}, 0, []string{""}, pkPeer},
		{"an empty configured secret among real ones never matches", pkReq{key: []string{""}, ip: []string{pkForged}}, 0, []string{"", pkKeyA}, pkPeer},
		{"key only, no client ip", pkReq{xff: []string{pkXFFLast}, key: []string{pkKeyA}}, 1, []string{pkKeyA}, pkXFFLast},
		{"a key header line with a comma list is not a match", pkReq{key: []string{pkKeyA + "," + pkKeyB}, ip: []string{pkForged}}, 0, []string{pkKeyA, pkKeyB}, pkPeer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpx.ClientIP(tt.req.build(), tt.hops, tt.secrets...); got != tt.want {
				t.Errorf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

// A direct caller (not behind the proxy) forging both headers and a long XFF with hops=1 gets only
// the last XFF entry (what the platform load balancer appended), never a value it chose.
func TestClientIP_ProxyKey_DirectCallerForgingHeadersCannotChangeTheResult(t *testing.T) {
	secrets := []string{pkKeyA, pkKeyB}
	base := pkReq{xff: []string{pkXFFLast}}
	want := httpx.ClientIP(base.build(), 1, secrets...)
	if want != pkXFFLast {
		t.Fatalf("baseline = %q, want the last XFF entry %q", want, pkXFFLast)
	}
	forgeries := map[string]pkReq{
		"forged client ip and wrong key":             {xff: []string{pkXFFLast}, key: []string{"guess"}, ip: []string{pkForged}},
		"forged client ip and no key":                {xff: []string{pkXFFLast}, ip: []string{pkForged}},
		"forged leading XFF entries":                 {xff: []string{pkForged + ", 7.7.7.7, " + pkXFFLast}},
		"forged XFF lines before the real one":       {xff: []string{pkForged, "7.7.7.7", pkXFFLast}},
		"all forged together with a wrong key":       {xff: []string{pkForged + ", 8.8.8.8, " + pkXFFLast}, key: []string{"guess"}, ip: []string{"9.9.9.9"}},
		"forged ip repeated in several header lines": {xff: []string{pkXFFLast}, key: []string{"guess", "guess2"}, ip: []string{pkForged, "9.9.9.9"}},
	}
	for name, f := range forgeries {
		t.Run(name, func(t *testing.T) {
			if got := httpx.ClientIP(f.build(), 1, secrets...); got != want {
				t.Errorf("ClientIP = %q, want %q (unchanged by forged headers)", got, want)
			}
		})
	}
}

func TestClientIP_ProxyKey_MalformedClientIPIsRejectedEvenWithAValidKey(t *testing.T) {
	malformed := []string{
		"", "   ", "not-an-ip", "1.2.3", "256.1.1.1", "1.2.3.4:8080", "[2001:db8::1]:443", "[2001:db8::1]",
		"203.0.113.50, 6.6.6.6", "203.0.113.50,", "fe80::1%eth0", "2001:db8::g", "203.0.113.50/32",
		"<script>alert(1)</script>", "203.0.113.50\r\nX-Evil: 1", "0x7f.0.0.1", "203.0.113.050",
	}
	for _, bad := range malformed {
		t.Run(bad, func(t *testing.T) {
			req := pkReq{xff: []string{pkXFFLast}, key: []string{pkKeyA}, ip: []string{bad}}
			if got := httpx.ClientIP(req.build(), 1, pkKeyA); got != pkXFFLast {
				t.Errorf("ClientIP = %q for client ip %q, want the XFF fallback %q", got, bad, pkXFFLast)
			}
			req.xff = nil
			if got := httpx.ClientIP(req.build(), 0, pkKeyA); got != pkPeer {
				t.Errorf("ClientIP = %q for client ip %q with hops 0, want RemoteAddr %q", got, bad, pkPeer)
			}
		})
	}
}

func TestClientIP_ProxyKey_SeveralClientIPHeaderLinesAreAmbiguousAndRejected(t *testing.T) {
	req := pkReq{xff: []string{pkXFFLast}, key: []string{pkKeyA}, ip: []string{pkRealIP, pkForged}}
	if got := httpx.ClientIP(req.build(), 1, pkKeyA); got != pkXFFLast {
		t.Errorf("ClientIP = %q with two X-Swastik-Client-IP lines, want the XFF fallback %q", got, pkXFFLast)
	}
}

func TestClientIP_ProxyKey_ResultIsAlwaysABareIPOrTheRemoteHost(t *testing.T) {
	req := pkReq{key: []string{pkKeyA}, ip: []string{"2001:DB8:0:0:0:0:0:1"}}
	if got := httpx.ClientIP(req.build(), 0, pkKeyA); got != "2001:db8::1" {
		t.Errorf("ClientIP = %q, want the canonical form 2001:db8::1", got)
	}
}
