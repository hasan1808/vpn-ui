package service

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The IP validator.
//
// The table is the one from ssl_ip_valid_v4 / _v6 in vpn-ui.sh:289-346, so the
// panel and the installer cannot drift apart on what is worth spending a
// validation attempt on.
// ---------------------------------------------------------------------------

func TestSSLIPValidIPv4(t *testing.T) {
	cases := []struct {
		ip    string
		valid bool
		why   string
	}{
		// Public, and the whole point of the exercise.
		{"8.8.8.8", true, ""},
		{"1.1.1.1", true, ""},
		{"65.109.217.240", true, ""},
		{"223.255.255.255", true, ""},
		// Documentation range: deliberately NOT rejected. It is what every example
		// in the docs uses, and an operator testing the flow against one should get
		// the CA's answer rather than ours.
		{"203.0.113.5", true, ""},

		// 0.0.0.0/8 this-network.
		{"0.0.0.0", false, "routable"},
		{"0.1.2.3", false, "routable"},
		// RFC 1918.
		{"10.0.0.1", false, "private"},
		{"10.255.255.255", false, "private"},
		{"172.16.0.1", false, "private"},
		{"172.31.255.254", false, "private"},
		{"192.168.1.1", false, "private"},
		// Loopback.
		{"127.0.0.1", false, "loopback"},
		{"127.255.255.254", false, "loopback"},
		// Link-local.
		{"169.254.1.1", false, "link-local"},
		// Carrier-grade NAT.
		{"100.64.0.1", false, "carrier-grade NAT"},
		{"100.127.255.254", false, "carrier-grade NAT"},
		// Multicast and reserved.
		{"224.0.0.1", false, "multicast"},
		{"239.1.2.3", false, "multicast"},
		{"255.255.255.255", false, "multicast"},

		// Just outside each private range, so the boundaries are not off by one.
		{"9.255.255.255", true, ""},
		{"11.0.0.1", true, ""},
		{"172.15.255.255", true, ""},
		{"172.32.0.1", true, ""},
		{"192.167.255.255", true, ""},
		{"192.169.0.1", true, ""},
		{"100.63.255.255", true, ""},
		{"100.128.0.1", true, ""},
		{"126.255.255.255", true, ""},
		{"128.0.0.1", true, ""},
		{"223.255.255.254", true, ""},

		// Malformed. A leading zero is rejected rather than normalised: the string
		// reaches acme.sh verbatim, and rewriting 08.8.8.8 to 8.8.8.8 would request
		// a certificate for an address the operator never named.
		{"08.8.8.8", false, "not a valid"},
		{"1.2.3.04", false, "not a valid"},
		{"256.1.1.1", false, "not a valid"},
		{"1.2.3", false, "not a valid"},
		{"1.2.3.4.5", false, "not a valid"},
		{"", false, "not a valid"},
		{"abc", false, "not a valid"},
		{"1.2.3.-4", false, "not a valid"},
		{"1.2.3.4 ", false, "not a valid"},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := sslIPValid(tc.ip)
			if got != tc.valid {
				t.Fatalf("sslIPValid(%q) = %v, want %v (reason %q)", tc.ip, got, tc.valid, sslIPUnroutableReason(tc.ip))
			}
			if !tc.valid && tc.why != "" {
				if reason := sslIPUnroutableReason(tc.ip); !strings.Contains(reason, tc.why) {
					t.Errorf("reason for %q = %q, want it to mention %q", tc.ip, reason, tc.why)
				}
			}
		})
	}
}

func TestSSLIPValidIPv6(t *testing.T) {
	cases := []struct {
		ip    string
		valid bool
	}{
		// 2000::/3 global unicast.
		{"2001:4860:4860::8888", true},
		{"2606:4700:4700::1111", true},
		{"2a01:4f8:1:2::3", true},
		{"2000::1", true},
		{"3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		// Documentation prefix, deliberately accepted for the same reason as
		// 203.0.113.0/24.
		{"2001:db8::1", true},
		{"2001:DB8::1", true},

		// Outside 2000::/3, which is the single test that stands in for loopback,
		// link-local, unique-local and multicast all at once.
		{"1fff::1", false},
		{"4000::1", false},
		{"fe80::1", false},        // link-local
		{"fd00::1", false},        // unique-local
		{"fc00::1", false},        // unique-local
		{"ff02::1", false},        // multicast
		{"::1", false},            // loopback
		{"::", false},             // unspecified
		{"::ffff:1.2.3.4", false}, // IPv4-mapped: an IPv4 address in v6 clothing
		{"64:ff9b::1.2.3.4", false},

		// Malformed.
		{"fe80::1%eth0", false},    // zone id
		{"2001:db8::12345", false}, // group longer than four hex digits
		{"2001:::1", false},
		{"2001:db8:1:2:3:4:5", false},     // too few groups, no ::
		{"2001:db8:1:2:3:4:5:6:7", false}, // too many groups
		{":1:2:3:4:5:6:7", false},         // single leading colon
		{"gggg::1", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			if got := sslIPValid(tc.ip); got != tc.valid {
				t.Errorf("sslIPValid(%q) = %v, want %v (reason %q)", tc.ip, got, tc.valid, sslIPUnroutableReason(tc.ip))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The preflight checks.
//
// Every host probe is injected, so none of this touches the network, needs root,
// or binds a real port.
// ---------------------------------------------------------------------------

func testPreflightDeps(now time.Time) sslPreflightDeps {
	return sslPreflightDeps{
		now: func() time.Time { return now },
		lookupIP: func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.5")}, nil
		},
		localIPs:  func() ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.5")}, nil },
		publicIP:  func() string { return "203.0.113.5" },
		portFree:  func(int) error { return nil },
		ntpSynced: func() (bool, bool) { return true, true },
		// Defaults to STANDALONE, not to "unknown". An unknown default would skip
		// every challenge-dependent check and make the renewal tests below pass
		// without exercising anything, which is exactly how the first version of
		// this fix looked complete while wildcard renewal was still broken.
		renewChallenge: func(string) sslEffectiveChallenge {
			return sslEffectiveChallenge{Known: true, NeedsPort80: true, NeedsResolve: true, Source: "standalone HTTP-01"}
		},
		// A host where the document root is writable and the webserver publishes
		// it. Injected rather than performed, because the real probe's writability
		// half is a genuine write as root, and a test that made a directory
		// unwritable with chmod would prove nothing wherever the tests also run as
		// root.
		webrootProbe: func(string, string) sslWebrootProbeResult {
			return sslWebrootProbeResult{Served: true, Detail: "served"}
		},
	}
}

// dnsRenewDeps is a host where acme.sh recorded DNS-01 for this certificate, and
// where the two HTTP-01 preconditions are genuinely absent: the wildcard label does
// not resolve (holding a wildcard certificate implies no wildcard A record) and
// something already holds port 80. A DNS-01 renewal needs neither.
func dnsRenewDeps(now time.Time) sslPreflightDeps {
	d := testPreflightDeps(now)
	d.lookupIP = func(host string) ([]net.IP, error) {
		if strings.HasPrefix(host, "*.") {
			return nil, errors.New("no such host")
		}
		return []net.IP{net.ParseIP("203.0.113.5")}, nil
	}
	d.portFree = func(int) error { return errors.New("bind: address already in use") }
	d.renewChallenge = func(string) sslEffectiveChallenge {
		return sslEffectiveChallenge{Known: true, Source: "Cloudflare DNS-01 (recorded by acme.sh at issue time)"}
	}
	return d
}

func findStep(steps []ProvisionStep, name string) (ProvisionStep, bool) {
	for _, s := range steps {
		if strings.HasPrefix(s.Name, name) {
			return s, true
		}
	}
	return ProvisionStep{}, false
}

func TestSSLPreflightRefusesWhenCertificateIsStillFresh(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	active := &SSLCertInfo{
		Identifiers: []string{"example.com"},
		NotBefore:   now.Add(-24 * time.Hour),
		NotAfter:    now.Add(60 * 24 * time.Hour),
		Lifetime:    90 * 24 * time.Hour,
		Remaining:   60 * 24 * time.Hour,
		RenewalDue:  false,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)

	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"example.com"},
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpIssue,
	}, active, nil, testPreflightDeps(now))

	if !res.Blocked {
		t.Fatal("a certificate that is nowhere near expiry must not be reissued")
	}
	// The exact expiry has to be in the message, or "not due yet" just gets
	// clicked through.
	if !strings.Contains(res.Reason, "2026-10-03") && !strings.Contains(res.Reason, "valid until") {
		t.Errorf("the refusal should give the exact expiry, got %q", res.Reason)
	}
	if !strings.Contains(res.Reason, "Re-apply") {
		t.Errorf("the refusal should point at the free action, got %q", res.Reason)
	}
}

func TestSSLPreflightAllowsRenewalWhenDue(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	active := &SSLCertInfo{
		Identifiers: []string{"example.com"},
		NotBefore:   now.Add(-110 * time.Hour),
		NotAfter:    now.Add(50 * time.Hour),
		Lifetime:    160 * time.Hour,
		Remaining:   50 * time.Hour,
		RenewalDue:  true,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)

	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"example.com"},
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpRenew,
	}, active, nil, testPreflightDeps(now))
	if res.Blocked {
		t.Fatalf("a due renewal must be allowed, got %q", res.Reason)
	}
}

func TestSSLPreflightRefusesEarlyRenewal(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	// A 160-hour certificate three hours old. acme.sh could be talked into this
	// with a bad --days; the independent floor is what stops it.
	active := &SSLCertInfo{
		Identifiers: []string{"example.com"},
		NotBefore:   now.Add(-3 * time.Hour),
		NotAfter:    now.Add(157 * time.Hour),
		Lifetime:    160 * time.Hour,
		Remaining:   157 * time.Hour,
		RenewalDue:  true, // even if something claims renewal is due
	}
	active.RenewalDueAt = now
	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"example.com"},
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpRenew,
	}, active, nil, testPreflightDeps(now))

	if !res.Blocked {
		t.Fatal("a three-hour-old certificate must not be renewed")
	}
	if !strings.Contains(res.Reason, "only 3h old") {
		t.Errorf("the refusal should name the age, got %q", res.Reason)
	}
}

func TestSSLPreflightShapeChecks(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		ids       []string
		challenge string
		wantBlock string
	}{
		{"wildcard needs DNS-01", []string{"*.example.com"}, SSLChallengeStandaloneDomain, "wildcard"},
		{"wildcard is fine over DNS-01", []string{"*.example.com"}, SSLChallengeCloudflareDNS, ""},
		{"IP challenge with a name", []string{"example.com"}, SSLChallengeStandaloneIP, "not an IP address"},
		{"domain challenge with an IP", []string{"203.0.113.5"}, SSLChallengeStandaloneDomain, "IP certificate needs the IP challenge"},
		{"no identifiers", nil, SSLChallengeStandaloneDomain, "has to name something"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := sslRunPreflight(SSLPreflightRequest{
				Identifiers: tc.ids, Challenge: tc.challenge, Op: SSLOpIssue,
			}, nil, nil, testPreflightDeps(now))
			if tc.wantBlock == "" {
				if res.Blocked {
					t.Fatalf("unexpected refusal: %q", res.Reason)
				}
				return
			}
			if !res.Blocked {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(res.Reason, tc.wantBlock) {
				t.Errorf("reason = %q, want it to mention %q", res.Reason, tc.wantBlock)
			}
		})
	}
}

// The shape checks are ISSUE-only, and this pair of tests is what keeps that
// correct in both directions.
//
// RenewIfDue picks the challenge from the certificate's own SANs: a wildcard has
// DNS names, so it lands on standalone-domain, and the wildcard rule used to refuse
// the operation. Automatic renewal of a wildcard then silently never ran. It is a
// false refusal because renewArgs never sends the challenge to acme.sh at all
// (`--home --config-home --server --renew -d <primary>`); acme.sh reads it from the
// per-domain conf.
func TestSSLPreflightWildcardRenewalIsNotBlocked(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	active := &SSLCertInfo{
		Identifiers: []string{"*.example.com", "example.com"},
		DNSNames:    []string{"*.example.com", "example.com"},
		NotBefore:   now.Add(-70 * 24 * time.Hour),
		NotAfter:    now.Add(20 * 24 * time.Hour),
		Lifetime:    90 * 24 * time.Hour,
		Remaining:   20 * 24 * time.Hour,
		RenewalDue:  true,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)

	// Exactly the request RenewIfDue constructs for this certificate, against a
	// host where NEITHER HTTP-01 precondition holds: the wildcard label does not
	// resolve and port 80 is taken. A DNS-01 renewal needs neither, and all three
	// checks (shape, reachability, port 80) must let it through.
	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: active.Identifiers,
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpRenew,
	}, active, nil, dnsRenewDeps(now))

	if res.Blocked {
		t.Fatalf("a wildcard renewal must not be refused: %q", res.Reason)
	}
	for _, name := range []string{"request shape", "identifier points here", "port 80 free"} {
		step, ok := findStep(res.Steps, name)
		if !ok {
			t.Fatalf("expected a %q step", name)
		}
		if !step.OK {
			t.Fatalf("step %q refused a DNS-01 renewal: %q", name, step.Msg)
		}
	}

	// The same is true for a renewal of an IP certificate, where the heuristic
	// picks standalone-ip: nothing about the challenge is ours to check here.
	ipActive := &SSLCertInfo{
		Identifiers: []string{"203.0.113.5"},
		IPAddresses: []string{"203.0.113.5"},
		NotBefore:   now.Add(-110 * time.Hour),
		NotAfter:    now.Add(50 * time.Hour),
		Lifetime:    160 * time.Hour,
		Remaining:   50 * time.Hour,
		RenewalDue:  true,
	}
	ipActive.RenewalDueAt = ipActive.NotAfter.Add(-ipActive.Lifetime / 3)
	if res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: ipActive.Identifiers,
		Challenge:   SSLChallengeStandaloneIP,
		Op:          SSLOpRenew,
	}, ipActive, nil, testPreflightDeps(now)); res.Blocked {
		t.Fatalf("an IP renewal must not be refused on request shape: %q", res.Reason)
	}
}

// The mirror, so the fix above cannot silently delete the real guard. At ISSUE
// time we DO choose the challenge, and a wildcard over HTTP-01 is a request Let's
// Encrypt cannot satisfy: it has to be refused locally rather than spending one of
// five validation attempts per hour proving it.
func TestSSLPreflightWildcardIssueIsStillBlocked(t *testing.T) {
	now := time.Now()
	for _, challenge := range []string{SSLChallengeStandaloneDomain, SSLChallengeStandaloneIP} {
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"*.example.com"},
			Challenge:   challenge,
			Op:          SSLOpIssue,
		}, nil, nil, testPreflightDeps(now))
		if !res.Blocked {
			t.Fatalf("challenge %s: a wildcard ISSUE must still be refused", challenge)
		}
	}
	// And the guard must name the wildcard, not merely refuse.
	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"*.example.com"},
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpIssue,
	}, nil, nil, testPreflightDeps(now))
	if !strings.Contains(res.Reason, "wildcard") {
		t.Errorf("reason = %q, want it to name the wildcard", res.Reason)
	}

	// The IP/name mix-ups are issue-time guards too, and must survive the fix.
	if res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"example.com"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
	}, nil, nil, testPreflightDeps(now)); !res.Blocked {
		t.Error("a name issued under the IP challenge must still be refused")
	}
	if res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpIssue,
	}, nil, nil, testPreflightDeps(now)); !res.Blocked {
		t.Error("an IP issued under the domain challenge must still be refused")
	}
}

// The PORT 80 half, isolated in its own function on purpose.
//
// In the wildcard test above, reachability refuses first and returns, so it
// short-circuits the port check: a regression there would be invisible while that
// test failed for the other reason. A plain (non-wildcard) name issued over DNS-01
// resolves normally, so reachability passes and port 80 is the only thing left
// that can refuse. DNS-01 does not start a listener, so a busy port is irrelevant
// to it.
func TestSSLPreflightDNSRenewalIgnoresBusyPort80(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	active := &SSLCertInfo{
		Identifiers: []string{"panel.example.com"},
		DNSNames:    []string{"panel.example.com"},
		NotBefore:   now.Add(-70 * 24 * time.Hour),
		NotAfter:    now.Add(20 * 24 * time.Hour),
		Lifetime:    90 * 24 * time.Hour,
		Remaining:   20 * 24 * time.Hour,
		RenewalDue:  true,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)

	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: active.Identifiers,
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpRenew,
	}, active, nil, dnsRenewDeps(now))

	if res.Blocked {
		t.Fatalf("a DNS-01 renewal must not be refused for a busy port 80: %q", res.Reason)
	}
	step, ok := findStep(res.Steps, "port 80 free")
	if !ok || !step.OK {
		t.Fatalf("expected a passing port-80 step, got %+v", step)
	}
	// And it should say WHY it did not check, rather than implying it passed.
	if !strings.Contains(step.Msg, "Not required") {
		t.Errorf("the skip should explain itself, got %q", step.Msg)
	}
}

// THE MIRROR THAT MATTERS MOST. The fix must not degenerate into "skip these
// checks on any renew". A standalone renewal, which is the common unattended case
// that deploy.sh produces, still has to be told that its name stopped resolving or
// that something took port 80. Losing that would remove protection from the one
// operation that runs with nobody watching.
func TestSSLPreflightStandaloneRenewalStillChecked(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	active := &SSLCertInfo{
		Identifiers: []string{"panel.example.com"},
		DNSNames:    []string{"panel.example.com"},
		NotBefore:   now.Add(-70 * 24 * time.Hour),
		NotAfter:    now.Add(20 * 24 * time.Hour),
		Lifetime:    90 * 24 * time.Hour,
		Remaining:   20 * 24 * time.Hour,
		RenewalDue:  true,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)
	req := SSLPreflightRequest{
		Identifiers: active.Identifiers,
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpRenew,
	}

	t.Run("a name that stopped resolving is still caught", func(t *testing.T) {
		d := testPreflightDeps(now) // renewChallenge defaults to standalone
		d.lookupIP = func(string) ([]net.IP, error) { return nil, errors.New("no such host") }
		res := sslRunPreflight(req, active, nil, d)
		if !res.Blocked {
			t.Fatal("a standalone renewal whose name does not resolve must still be refused")
		}
		if !strings.Contains(res.Reason, "does not resolve") {
			t.Errorf("reason = %q", res.Reason)
		}
	})

	t.Run("an occupied port 80 is still caught", func(t *testing.T) {
		d := testPreflightDeps(now)
		d.portFree = func(int) error { return errors.New("bind: address already in use") }
		res := sslRunPreflight(req, active, nil, d)
		if !res.Blocked {
			t.Fatal("a standalone renewal with port 80 taken must still be refused")
		}
		if !strings.Contains(res.Reason, "address already in use") {
			t.Errorf("reason = %q", res.Reason)
		}
	})
}

// When acme.sh has no record, guessing would be the only alternative, and a wrong
// guess refuses a renewal that would have worked. Skipping is the safe direction:
// it can only cost a warning.
func TestSSLPreflightUnknownRenewChallengeSkipsRatherThanGuesses(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	active := &SSLCertInfo{
		Identifiers: []string{"panel.example.com"},
		DNSNames:    []string{"panel.example.com"},
		NotBefore:   now.Add(-70 * 24 * time.Hour),
		NotAfter:    now.Add(20 * 24 * time.Hour),
		Lifetime:    90 * 24 * time.Hour,
		Remaining:   20 * 24 * time.Hour,
		RenewalDue:  true,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)

	d := testPreflightDeps(now)
	d.lookupIP = func(string) ([]net.IP, error) { return nil, errors.New("no such host") }
	d.portFree = func(int) error { return errors.New("bind: address already in use") }
	d.renewChallenge = func(string) sslEffectiveChallenge { return sslEffectiveChallenge{} }

	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: active.Identifiers,
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpRenew,
	}, active, nil, d)
	if res.Blocked {
		t.Fatalf("an undeterminable challenge must skip the dependent checks, not refuse: %q", res.Reason)
	}
	step, _ := findStep(res.Steps, "identifier points here")
	if !strings.Contains(step.Msg, "Skipped") {
		t.Errorf("the skip should say why, got %q", step.Msg)
	}
}

// ---------------------------------------------------------------------------
// The webroot challenge.
//
// It exists for one host shape: something else already owns port 80. Every test
// below is written so that it FAILS if the port-80 check leaks back in, because a
// preflight that refuses a busy port 80 here would refuse the exact configuration
// the challenge was added to serve.
// ---------------------------------------------------------------------------

// webrootDeps is a host running nginx: port 80 is taken, the name resolves here,
// and /var/www/html is real and writable.
func webrootDeps(t *testing.T, now time.Time) (sslPreflightDeps, string) {
	t.Helper()
	d := testPreflightDeps(now)
	d.portFree = func(int) error { return errors.New("bind: address already in use") }
	return d, t.TempDir()
}

func TestSSLPreflightWebrootIgnoresBusyPort80(t *testing.T) {
	now := time.Now()
	deps, root := webrootDeps(t, now)

	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"panel.example.com"},
		Challenge:   SSLChallengeWebroot,
		Op:          SSLOpIssue,
		WebrootPath: root,
	}, nil, nil, deps)

	if res.Blocked {
		t.Fatalf("webroot exists BECAUSE port 80 is taken; refusing on it defeats the feature: %q", res.Reason)
	}
	step, ok := findStep(res.Steps, "port 80 free")
	if !ok || !step.OK {
		t.Fatalf("expected a passing port-80 step, got %+v", step)
	}
	// And it has to say why it did not check, or the operator reads a green tick
	// as "the port is free" and goes looking for the wrong thing later.
	if !strings.Contains(step.Msg, "Not required") {
		t.Errorf("the skip should explain itself, got %q", step.Msg)
	}
	// Named with the path, not the bare prefix: "webroot is served" shares that
	// prefix, and matching it here would assert on the wrong step.
	if w, ok := findStep(res.Steps, "webroot "+root); !ok || !w.OK {
		t.Fatalf("expected a passing webroot step, got %+v", w)
	}
}

// HTTP-01 is still HTTP-01. Let's Encrypt fetches the token from outside, so a
// name that does not resolve here fails validation and spends one of five
// attempts per hour, whoever serves the file.
func TestSSLPreflightWebrootStillNeedsTheNameToResolve(t *testing.T) {
	now := time.Now()
	deps, root := webrootDeps(t, now)
	deps.lookupIP = func(string) ([]net.IP, error) { return nil, errors.New("no such host") }

	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"panel.example.com"},
		Challenge:   SSLChallengeWebroot,
		Op:          SSLOpIssue,
		WebrootPath: root,
	}, nil, nil, deps)
	if !res.Blocked {
		t.Fatal("a webroot issuance whose name does not resolve must be refused")
	}
	if !strings.Contains(res.Reason, "does not resolve") {
		t.Errorf("reason = %q", res.Reason)
	}
}

// The three filesystem answers, each of which has to name WHICH one it is: they
// have completely different fixes, and the CA reports all three identically.
func TestSSLPreflightWebrootPathChecks(t *testing.T) {
	now := time.Now()
	existing := t.TempDir()
	aFile := filepath.Join(existing, "index.html")
	if err := os.WriteFile(aFile, []byte("<html>"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		path      string
		probe     func(string, string) sslWebrootProbeResult
		wantBlock string
	}{
		{"missing", filepath.Join(existing, "nope"), nil, "does not exist"},
		{"a file, not a directory", aFile, nil, "is a file, not a directory"},
		{"relative", "www", nil, "not an absolute path"},
		{"empty", "", nil, "needs the directory the webserver already serves"},
		{"not writable", existing, func(string, string) sslWebrootProbeResult {
			return sslWebrootProbeResult{WriteErr: errors.New("permission denied")}
		}, "cannot be written"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, _ := webrootDeps(t, now)
			if tc.probe != nil {
				deps.webrootProbe = tc.probe
			}
			res := sslRunPreflight(SSLPreflightRequest{
				Identifiers: []string{"panel.example.com"},
				Challenge:   SSLChallengeWebroot,
				Op:          SSLOpIssue,
				WebrootPath: tc.path,
			}, nil, nil, deps)
			if !res.Blocked {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(res.Reason, tc.wantBlock) {
				t.Errorf("reason = %q, want it to name %q", res.Reason, tc.wantBlock)
			}
		})
	}
}

// The serve probe WARNS, it never refuses. A negative answer over loopback has
// innocent causes (a webserver bound to the public address only, an IP-selected
// vhost, a 301 to https that Let's Encrypt follows quite happily), and refusing on
// any of them would block an issuance that would have worked.
func TestSSLPreflightWebrootServeProbeOnlyWarns(t *testing.T) {
	now := time.Now()
	deps, root := webrootDeps(t, now)
	deps.webrootProbe = func(string, string) sslWebrootProbeResult {
		return sslWebrootProbeResult{Served: false, Detail: "it answered 404"}
	}

	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"panel.example.com"},
		Challenge:   SSLChallengeWebroot,
		Op:          SSLOpIssue,
		WebrootPath: root,
	}, nil, nil, deps)
	if res.Blocked {
		t.Fatalf("a local 404 must not refuse the issuance: %q", res.Reason)
	}
	step, ok := findStep(res.Steps, "webroot is served")
	if !ok || !step.Warn {
		t.Fatalf("expected a warning step, got %+v", step)
	}
	// The warning is only worth anything if it carries what the server said.
	if !strings.Contains(step.Msg, "404") {
		t.Errorf("the warning should quote what the local server answered, got %q", step.Msg)
	}

	// And the confirmed case is a clean pass, not a permanent warning, or the
	// warning becomes wallpaper nobody reads.
	served, _ := webrootDeps(t, now)
	ok2 := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"panel.example.com"},
		Challenge:   SSLChallengeWebroot,
		Op:          SSLOpIssue,
		WebrootPath: root,
	}, nil, nil, served)
	step2, _ := findStep(ok2.Steps, "webroot is served")
	if step2.Warn || !step2.OK {
		t.Errorf("a served probe should pass without a warning, got %+v", step2)
	}
}

// The real probe, whose MODES are the thing that could make this check the cause
// of the failure it prevents.
//
// acme.sh creates the challenge tree under `umask ugo+rx` and chmods the token a+r
// (acme.sh:5586-5600), because the webserver reads it as www-data and not as root.
// A probe that got there first and created .well-known/ mode 0700 would leave a
// directory acme.sh's own `mkdir -p` then silently skips, and nginx could not
// traverse into it: the preflight would have broken the issuance it was checking.
func TestSSLWebrootProbeLeavesATraversableTree(t *testing.T) {
	root := t.TempDir()
	res := sslWebrootProbe(root, "panel.example.com")
	if res.WriteErr != nil {
		t.Fatalf("a fresh temp directory must be writable: %v", res.WriteErr)
	}
	// Served is deliberately not asserted: whether anything answers port 80 on the
	// machine running the tests is not this function's business.

	for _, dir := range []string{
		filepath.Join(root, ".well-known"),
		filepath.Join(root, ".well-known", "acme-challenge"),
	} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if perm := fi.Mode().Perm(); perm&0o055 != 0o055 {
			t.Errorf("%s is mode %04o: the webserver's user has to be able to traverse and read it", dir, perm)
		}
	}

	// Nothing left behind. A preflight runs as often as the UI cares to call it and
	// has no business littering the operator's document root.
	entries, err := os.ReadDir(filepath.Join(root, ".well-known", "acme-challenge"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the probe file was not removed: %v", entries)
	}
}

// A directory the operator already set up is left exactly as they set it. Their
// permissions may be deliberate (a group the webserver is in, a setgid bit), and
// silently rewriting them would be meddling with a live document root.
func TestSSLWebrootProbeDoesNotRepermissionExistingDirectories(t *testing.T) {
	root := t.TempDir()
	wellKnown := filepath.Join(root, ".well-known")
	if err := os.Mkdir(wellKnown, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wellKnown, 0o750); err != nil {
		t.Fatal(err)
	}
	if res := sslWebrootProbe(root, "panel.example.com"); res.WriteErr != nil {
		t.Fatalf("write: %v", res.WriteErr)
	}
	fi, err := os.Stat(wellKnown)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o750 {
		t.Errorf(".well-known is now mode %04o, want the operator's own 0750", perm)
	}
}

// Webroot is HTTP-01, and Let's Encrypt validates a wildcard over DNS-01 alone. It
// does not matter who serves the token.
func TestSSLPreflightWebrootStillRefusesAWildcard(t *testing.T) {
	now := time.Now()
	deps, root := webrootDeps(t, now)
	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"*.example.com"},
		Challenge:   SSLChallengeWebroot,
		Op:          SSLOpIssue,
		WebrootPath: root,
	}, nil, nil, deps)
	if !res.Blocked {
		t.Fatal("a wildcard over webroot must be refused")
	}
	if !strings.Contains(res.Reason, "wildcard") {
		t.Errorf("reason = %q, want it to name the wildcard", res.Reason)
	}
}

// An IP forces the shortlived profile onto the WHOLE certificate, so mixing one in
// beside a name would quietly turn a 90-day certificate into a six-day one.
func TestSSLPreflightWebrootRefusesMixedNameAndIP(t *testing.T) {
	now := time.Now()
	deps, root := webrootDeps(t, now)
	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"panel.example.com", "203.0.113.5"},
		Challenge:   SSLChallengeWebroot,
		Op:          SSLOpIssue,
		WebrootPath: root,
	}, nil, nil, deps)
	if !res.Blocked {
		t.Fatal("a webroot set mixing a name and an address must be refused")
	}
	if !strings.Contains(res.Reason, "six days") {
		t.Errorf("the refusal should name the consequence, got %q", res.Reason)
	}

	// An all-IP set is fine: it gets the shortlived profile, and webroot is the
	// better home for a certificate that renews every few days than a challenge
	// that would stop the webserver each time.
	if res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"203.0.113.5"},
		Challenge:   SSLChallengeWebroot,
		Op:          SSLOpIssue,
		WebrootPath: root,
	}, nil, nil, deps); res.Blocked {
		t.Fatalf("an IP over webroot must not be refused: %q", res.Reason)
	}
}

// THE RENEWAL, end to end through the real conf parser rather than an injected
// verdict. A webroot certificate renews on a host where port 80 is permanently
// taken, and the only thing that knows this is the Le_Webroot marker acme.sh wrote
// at issue time.
func TestSSLPreflightWebrootRenewalIgnoresBusyPort80(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	acmeHome := t.TempDir()
	webroot := t.TempDir()

	dir := filepath.Join(acmeHome, "panel.example.com")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "panel.example.com.conf"),
		[]byte("Le_Domain='panel.example.com'\nLe_Webroot='"+webroot+"'\nLe_Keylength='2048'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	active := &SSLCertInfo{
		Identifiers: []string{"panel.example.com"},
		DNSNames:    []string{"panel.example.com"},
		NotBefore:   now.Add(-70 * 24 * time.Hour),
		NotAfter:    now.Add(20 * 24 * time.Hour),
		Lifetime:    90 * 24 * time.Hour,
		Remaining:   20 * 24 * time.Hour,
		RenewalDue:  true,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)

	deps := testPreflightDeps(now)
	deps.portFree = func(int) error { return errors.New("bind: address already in use") }
	// The real resolver, reading the real file. Injecting a verdict here would test
	// the test.
	deps.renewChallenge = func(primary string) sslEffectiveChallenge {
		return sslResolveRenewChallenge(acmeHome, primary)
	}

	// Exactly the request RenewIfDue builds: its Challenge is standalone-domain and
	// is INERT, because renewArgs never sends a challenge and acme.sh replays what
	// it recorded. Checking against that guess would refuse this renewal forever.
	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: active.Identifiers,
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpRenew,
	}, active, nil, deps)

	if res.Blocked {
		t.Fatalf("a webroot renewal must not be refused for a busy port 80: %q", res.Reason)
	}
	step, ok := findStep(res.Steps, "port 80 free")
	if !ok || !step.OK || !strings.Contains(step.Msg, "Not required") {
		t.Fatalf("expected the port-80 check to be skipped with a reason, got %+v", step)
	}
	// And the recorded path is checked, which is the other half of what the marker
	// bought us: a document root deleted since issue time fails validation exactly
	// like a fresh one.
	w, ok := findStep(res.Steps, "webroot "+webroot)
	if !ok || !w.OK {
		t.Fatalf("the renewal should check the recorded webroot, got %+v (%v)", w, ok)
	}
}

// The mirror: a webroot renewal whose recorded directory has since been deleted is
// still refused, so the skip above cannot degenerate into "webroot renewals are
// never checked".
func TestSSLPreflightWebrootRenewalCatchesADeletedRoot(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	acmeHome := t.TempDir()
	gone := filepath.Join(t.TempDir(), "deleted-by-the-operator")

	dir := filepath.Join(acmeHome, "panel.example.com")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "panel.example.com.conf"),
		[]byte("Le_Domain='panel.example.com'\nLe_Webroot='"+gone+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	active := &SSLCertInfo{
		Identifiers: []string{"panel.example.com"},
		DNSNames:    []string{"panel.example.com"},
		NotBefore:   now.Add(-70 * 24 * time.Hour),
		NotAfter:    now.Add(20 * 24 * time.Hour),
		Lifetime:    90 * 24 * time.Hour,
		Remaining:   20 * 24 * time.Hour,
		RenewalDue:  true,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)

	deps := testPreflightDeps(now)
	deps.renewChallenge = func(primary string) sslEffectiveChallenge {
		return sslResolveRenewChallenge(acmeHome, primary)
	}
	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: active.Identifiers,
		Challenge:   SSLChallengeStandaloneDomain,
		Op:          SSLOpRenew,
	}, active, nil, deps)
	if !res.Blocked {
		t.Fatal("a renewal whose recorded document root is gone must be refused")
	}
	if !strings.Contains(res.Reason, "does not exist") {
		t.Errorf("reason = %q", res.Reason)
	}
}

// A challenge the panel does not know must ERROR rather than fall through. Without
// this the run reaches "contacting Let's Encrypt", takes the acme home lock and
// then dies in issueArgs with no context; a silent default would be worse still,
// since it would spend metered budget on a method nobody chose.
func TestSSLPreflightRefusesAnUnknownChallenge(t *testing.T) {
	now := time.Now()
	for _, challenge := range []string{"", "tls-alpn", "nginx", "webroot "} {
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"panel.example.com"},
			Challenge:   challenge,
			Op:          SSLOpIssue,
		}, nil, nil, testPreflightDeps(now))
		if !res.Blocked {
			t.Errorf("challenge %q must be refused", challenge)
			continue
		}
		if !strings.Contains(res.Reason, "not a validation method") {
			t.Errorf("challenge %q: reason = %q", challenge, res.Reason)
		}
	}
	// And a RENEW is untouched by it: the challenge on a renew never reaches
	// acme.sh at all, so validating it there would refuse an operation on a field
	// that does nothing.
	active := &SSLCertInfo{
		Identifiers: []string{"panel.example.com"},
		DNSNames:    []string{"panel.example.com"},
		NotBefore:   now.Add(-70 * 24 * time.Hour),
		NotAfter:    now.Add(20 * 24 * time.Hour),
		Lifetime:    90 * 24 * time.Hour,
		Remaining:   20 * 24 * time.Hour,
		RenewalDue:  true,
	}
	active.RenewalDueAt = active.NotAfter.Add(-active.Lifetime / 3)
	if res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: active.Identifiers, Challenge: "nonsense", Op: SSLOpRenew,
	}, active, nil, testPreflightDeps(now)); res.Blocked {
		t.Errorf("a renew must not be refused on an inert challenge field: %q", res.Reason)
	}
}

// The parser, against files in acme.sh's real on-disk format.
func TestSSLResolveRenewChallenge(t *testing.T) {
	cases := []struct {
		name        string
		conf        string
		dir         string
		wantKnown   bool
		wantPort80  bool
		wantResolve bool
		wantWebroot string
	}{
		{"standalone binds port 80 here", "Le_Webroot='no'\n", "example.com", true, true, true, ""},
		{"cloudflare dns-01 needs neither", "Le_Webroot='dns_cf'\n", "example.com", true, false, false, ""},
		{"manual dns-01 needs neither", "Le_Webroot='dns'\n", "example.com", true, false, false, ""},
		// A webroot means some OTHER server answers the token, so the name must
		// resolve but we bind nothing. The PATH comes back too, so a renewal can
		// check that the directory is still there and still writable.
		{"webroot resolves but binds nothing", "Le_Webroot='/var/www/html'\n", "example.com", true, false, true, "/var/www/html"},
		{"alpn uses port 443", "Le_Webroot='alpn'\n", "example.com", true, false, true, ""},
		// apache, nginx and stateless land in the same branch as a path but are
		// MODES, not directories. Stat-ing "apache" would report a missing webroot
		// and refuse a renewal that never had one.
		{"the apache mode is not a directory", "Le_Webroot='apache'\n", "example.com", true, false, true, ""},
		{"the nginx mode is not a directory", "Le_Webroot='nginx:example.com'\n", "example.com", true, false, true, ""},
		// Union across a mixed certificate.
		{"mixed dns plus standalone needs port 80", "Le_Webroot='dns_cf,no'\n", "example.com", true, true, true, ""},
		{"mixed webroot plus standalone keeps both", "Le_Webroot='/srv/www,no'\n", "example.com", true, true, true, "/srv/www"},
		{"the _ecc directory is found too", "Le_Webroot='dns_cf'\n", "example.com_ecc", true, false, false, ""},
		// Every failure path must be Known false, never a guess.
		{"missing key", "Le_Domain='example.com'\n", "example.com", false, false, false, ""},
		{"empty value", "Le_Webroot=''\n", "example.com", false, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, tc.dir)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			// acme.sh always names the conf after the primary, even inside _ecc.
			if err := os.WriteFile(filepath.Join(dir, "example.com.conf"),
				[]byte("Le_Domain='example.com'\n"+tc.conf+"Le_Keylength='2048'\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			got := sslResolveRenewChallenge(home, "example.com")
			if got.Known != tc.wantKnown {
				t.Fatalf("Known = %v, want %v (%+v)", got.Known, tc.wantKnown, got)
			}
			if got.NeedsPort80 != tc.wantPort80 {
				t.Errorf("NeedsPort80 = %v, want %v", got.NeedsPort80, tc.wantPort80)
			}
			if got.NeedsResolve != tc.wantResolve {
				t.Errorf("NeedsResolve = %v, want %v", got.NeedsResolve, tc.wantResolve)
			}
			if got.WebrootPath != tc.wantWebroot {
				t.Errorf("WebrootPath = %q, want %q", got.WebrootPath, tc.wantWebroot)
			}
			if got.Known && got.Source == "" {
				t.Error("a known challenge should say how it was determined")
			}
		})
	}

	t.Run("no acme state at all", func(t *testing.T) {
		if got := sslResolveRenewChallenge(t.TempDir(), "example.com"); got.Known {
			t.Errorf("a missing conf must be unknown, got %+v", got)
		}
	})
	t.Run("empty inputs", func(t *testing.T) {
		if got := sslResolveRenewChallenge("", "example.com"); got.Known {
			t.Error("an empty home must be unknown")
		}
		if got := sslResolveRenewChallenge(t.TempDir(), ""); got.Known {
			t.Error("an empty primary must be unknown")
		}
	})
}

func TestSSLPreflightReachability(t *testing.T) {
	now := time.Now()

	t.Run("a private IP is refused before the CA sees it", func(t *testing.T) {
		deps := testPreflightDeps(now)
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"192.168.1.10"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
		}, nil, nil, deps)
		if !res.Blocked {
			t.Fatal("a private address must be refused locally")
		}
		if !strings.Contains(res.Reason, "private") || !strings.Contains(res.Reason, "five validation attempts") {
			t.Errorf("reason = %q, want it to name the range and the cost", res.Reason)
		}
	})

	t.Run("an IP that is not ours is refused", func(t *testing.T) {
		deps := testPreflightDeps(now)
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"198.51.100.7"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
		}, nil, nil, deps)
		if !res.Blocked {
			t.Fatal("an address belonging to another machine must be refused")
		}
		if !strings.Contains(res.Reason, "203.0.113.5") {
			t.Errorf("the refusal should name this host's actual address, got %q", res.Reason)
		}
	})

	t.Run("1:1 NAT warns rather than refusing", func(t *testing.T) {
		deps := testPreflightDeps(now)
		// The AWS/GCP shape: a private address on the interface, a public one at
		// the edge. Refusing here would block a perfectly good issuance.
		deps.localIPs = func() ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.1.5")}, nil }
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
		}, nil, nil, deps)
		if res.Blocked {
			t.Fatalf("a NATted public address must not be refused: %q", res.Reason)
		}
		step, ok := findStep(res.Steps, "identifier points here")
		if !ok || !step.Warn {
			t.Fatalf("expected a warning step, got %+v", step)
		}
		if !strings.Contains(step.Msg, "NAT") {
			t.Errorf("the warning should mention NAT, got %q", step.Msg)
		}
	})

	t.Run("a name that does not resolve is refused", func(t *testing.T) {
		deps := testPreflightDeps(now)
		deps.lookupIP = func(string) ([]net.IP, error) { return nil, errors.New("no such host") }
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"nope.example"}, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpIssue,
		}, nil, nil, deps)
		if !res.Blocked {
			t.Fatal("a name with no A record must be refused")
		}
		if !strings.Contains(res.Reason, "does not resolve") {
			t.Errorf("reason = %q", res.Reason)
		}
	})

	t.Run("a name resolving only to a private address is refused", func(t *testing.T) {
		deps := testPreflightDeps(now)
		deps.lookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil }
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"internal.example"}, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpIssue,
		}, nil, nil, deps)
		if !res.Blocked {
			t.Fatal("a name pointing only at a private address must be refused")
		}
		if !strings.Contains(res.Reason, "internet cannot reach") {
			t.Errorf("reason = %q", res.Reason)
		}
	})

	t.Run("DNS-01 does not require the name to resolve here", func(t *testing.T) {
		deps := testPreflightDeps(now)
		deps.lookupIP = func(string) ([]net.IP, error) { return nil, errors.New("no such host") }
		// It must not need port 80 either, so make binding fail to prove the check
		// is skipped rather than merely passing.
		deps.portFree = func(int) error { return errors.New("address already in use") }
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"example.com", "*.example.com"}, Challenge: SSLChallengeCloudflareDNS, Op: SSLOpIssue,
		}, nil, nil, deps)
		if res.Blocked {
			t.Fatalf("DNS-01 needs neither resolution nor port 80: %q", res.Reason)
		}
	})
}

func TestSSLPreflightPort80(t *testing.T) {
	now := time.Now()
	deps := testPreflightDeps(now)
	deps.portFree = func(int) error { return errors.New("listen tcp :80: bind: address already in use") }

	res := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
	}, nil, nil, deps)
	if !res.Blocked {
		t.Fatal("an occupied port 80 must refuse a standalone challenge")
	}
	if !strings.Contains(res.Reason, "address already in use") {
		t.Errorf("the refusal should quote the bind error, got %q", res.Reason)
	}
	// For an IP identifier there is no DNS-01 fallback, and the message has to say
	// so or the operator goes looking for one.
	if !strings.Contains(res.Reason, "cannot use DNS-01") {
		t.Errorf("the IP case should say there is no DNS-01 fallback, got %q", res.Reason)
	}

	// A free port is reported honestly: free here is not the same as reachable
	// from the internet, and we deliberately contact no third-party prober.
	ok := sslRunPreflight(SSLPreflightRequest{
		Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
	}, nil, nil, testPreflightDeps(now))
	step, found := findStep(ok.Steps, "port 80 free")
	if !found || !step.Warn {
		t.Fatalf("a free port should still warn about inbound reachability, got %+v", step)
	}
}

func TestSSLPreflightClock(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	t.Run("a clock behind the certificate it holds", func(t *testing.T) {
		active := &SSLCertInfo{
			Identifiers: []string{"203.0.113.5"},
			// Issued in our future, which can only mean the clock went backwards.
			NotBefore:  now.Add(48 * time.Hour),
			NotAfter:   now.Add(200 * time.Hour),
			Lifetime:   160 * time.Hour,
			RenewalDue: true,
		}
		active.RenewalDueAt = now.Add(-time.Hour)
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
		}, active, nil, testPreflightDeps(now))
		step, ok := findStep(res.Steps, "clock")
		if !ok || !step.Warn {
			t.Fatalf("expected a clock warning, got %+v", step)
		}
		if !strings.Contains(step.Msg, "BEFORE") {
			t.Errorf("the warning should say the clock is behind, got %q", step.Msg)
		}
	})

	t.Run("unsynchronised NTP warns", func(t *testing.T) {
		deps := testPreflightDeps(now)
		deps.ntpSynced = func() (bool, bool) { return false, true }
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
		}, nil, nil, deps)
		step, ok := findStep(res.Steps, "clock")
		if !ok || !step.Warn {
			t.Fatalf("expected a clock warning, got %+v", step)
		}
		if !strings.Contains(step.Msg, "NTP") {
			t.Errorf("the warning should name NTP, got %q", step.Msg)
		}
	})

	t.Run("a host with no timedatectl is not a host with a bad clock", func(t *testing.T) {
		deps := testPreflightDeps(now)
		deps.ntpSynced = func() (bool, bool) { return false, false }
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
		}, nil, nil, deps)
		step, _ := findStep(res.Steps, "clock")
		if step.Warn {
			t.Errorf("an undeterminable NTP state must not warn, got %q", step.Msg)
		}
	})
}

// The preflight has to enforce the ledger, not merely report it.
func TestSSLPreflightEnforcesLedger(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}

	t.Run("a drained exact-set budget refuses an issue", func(t *testing.T) {
		l := newTestLedger(t, now)
		for i := 0; i < 5; i++ {
			recordAt(t, l, now.Add(-time.Duration(i+1)*time.Hour), ids, sslCAProduction, SSLOpIssue, false, true)
		}
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: ids, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpIssue,
		}, nil, l, testPreflightDeps(now))
		if !res.Blocked {
			t.Fatal("a drained budget must refuse a new certificate")
		}
		if !strings.Contains(res.Reason, "no override form") {
			t.Errorf("reason = %q", res.Reason)
		}
	})

	t.Run("a drained budget does NOT refuse a renew", func(t *testing.T) {
		l := newTestLedger(t, now)
		for i := 0; i < 5; i++ {
			recordAt(t, l, now.Add(-time.Duration(i+1)*time.Hour), ids, sslCAProduction, SSLOpIssue, false, true)
		}
		// The renew path carries the ARI "replaces" field and is exempt from every
		// limit, so gating it here would refuse the free operation and push the
		// operator towards the expensive one.
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: ids, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpRenew,
		}, nil, l, testPreflightDeps(now))
		if res.Blocked {
			t.Fatalf("an exempt renewal must not be refused on budget: %q", res.Reason)
		}
	})

	t.Run("the failure cooldown refuses", func(t *testing.T) {
		l := newTestLedger(t, now)
		for i := 0; i < sslFailureHardStop; i++ {
			recordAt(t, l, now.Add(-time.Duration(i+1)*time.Minute), ids, sslCAProduction, SSLOpIssue, false, false)
		}
		res := sslRunPreflight(SSLPreflightRequest{
			Identifiers: ids, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpIssue,
		}, nil, l, testPreflightDeps(now))
		if !res.Blocked {
			t.Fatal("four failures in an hour must refuse")
		}
		if !strings.Contains(res.Reason, "validation failures") {
			t.Errorf("reason = %q", res.Reason)
		}
	})
}
