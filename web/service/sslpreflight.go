package service

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Local preflight: every check that can turn a would-be Let's Encrypt
// authorization failure into a free local error.
//
// The economics are the whole point. A failed validation costs one of five slots
// per identifier per hour and takes 12 minutes to come back. Every check in this
// file costs nothing and takes milliseconds, so any of them that catches a real
// problem has paid for the whole feature. The messages are written to name the
// thing to fix, because "authorization failed" from the CA names nothing.

// The vocabulary shared by the preflight, the acme.sh driver and the ledger.
const (
	// SSLOpIssue asks the CA for a certificate for a set of identifiers it has no
	// predecessor for. It CONSUMES exact-set budget (5 per 7 days, no override).
	SSLOpIssue = "issue"

	// SSLOpRenew replaces an existing certificate through acme.sh's --renew path,
	// which is the ONLY path on which the bundled 3.1.4 sends the RFC 9773
	// "replaces" field (acme.sh:5155 gates it on _ACME_IS_RENEW=1 and says in so
	// many words that --issue, even with --force, is not a renewal). An
	// ARI-coordinated renewal is exempt from every Let's Encrypt rate limit, so
	// this operation is FREE and is the one the UI should steer people to.
	SSLOpRenew = "renew"

	// SSLOpReapply re-runs --install-cert and the consumer fan-out against the
	// certificate already on disk. It never contacts a CA and can never fail a
	// rate limit, which is why it is the PRIMARY action: almost every "my
	// certificate is not working" turns out to be a consumer holding a stale copy,
	// not a certificate that needs reissuing.
	SSLOpReapply = "reapply"
)

const (
	// SSLChallengeCloudflareDNS is DNS-01 through the Cloudflare API. The only
	// wildcard-capable path, and the only one that needs neither a resolving name
	// nor a free port 80.
	SSLChallengeCloudflareDNS = "cloudflare-dns"

	// SSLChallengeStandaloneDomain is HTTP-01 for a DNS name, served by acme.sh's
	// own listener on port 80.
	SSLChallengeStandaloneDomain = "standalone-domain"

	// SSLChallengeStandaloneIP is HTTP-01 for a bare IP address. An IP identifier
	// has NO DNS-01 escape hatch (there is nothing to put a TXT record on) and
	// tls-alpn-01 wants port 443, so port 80 is not one option among several here,
	// it is the only one.
	SSLChallengeStandaloneIP = "standalone-ip"

	// SSLChallengeWebroot is HTTP-01 where acme.sh writes the token into a
	// document root an EXISTING webserver already publishes, and binds nothing
	// itself.
	//
	// It exists because both standalone challenges BIND PORT 80, so on a host
	// already running nginx or apache they cannot work at all: acme.sh's listener
	// never starts. Without this the only remaining option is Cloudflare DNS-01,
	// which is no option whatsoever for an operator who does not use Cloudflare.
	//
	// What it costs: the webserver has to actually serve the directory for the
	// name being validated. That is one more thing to get wrong, and the two ways
	// to get it wrong (a path we cannot write, a vhost whose root is somewhere
	// else) both surface at the CA as the same "authorization failed" that spends
	// one of five validation attempts per hour. sslCheckWebroot exists to turn
	// both into free local errors.
	SSLChallengeWebroot = "webroot"
)

// SSLPreflightRequest is what the operator is asking for.
type SSLPreflightRequest struct {
	Identifiers []string `json:"identifiers"`
	Challenge   string   `json:"challenge"`
	Op          string   `json:"op"`
	Staging     bool     `json:"staging"`

	// WebrootPath is the document root for SSLChallengeWebroot, and it has to be
	// here rather than only on SSLIssueRequest: checking that we can write the
	// challenge file is the single most valuable thing this preflight does for
	// that challenge, and it cannot check a path it was not told.
	WebrootPath string `json:"webrootPath"`
}

// SSLPreflightResult is the verdict plus every check that produced it, in
// ProvisionStep form so the existing setup-console component renders it unchanged.
type SSLPreflightResult struct {
	Steps   []ProvisionStep `json:"steps"`
	OK      bool            `json:"ok"`
	Blocked bool            `json:"blocked"`
	Reason  string          `json:"reason,omitempty"`
}

// sslEffectiveChallenge is what the operation will ACTUALLY do to prove control,
// as opposed to what the caller put in the request.
//
// The distinction exists because on a RENEW we do not choose the challenge at all.
// renewArgs sends only `--home --config-home --server --renew -d <primary>`, so
// acme.sh replays whatever it recorded at issue time. A caller that guesses a
// challenge for a renew is supplying a value that never reaches the CA, and every
// check keyed on that guess is asking a question about a thing that will not
// happen.
//
// Getting this wrong is not theoretical: RenewIfDue picks standalone-domain for
// any certificate with DNS names, so a WILDCARD renewal was being tested for a
// resolvable `*.example.com` A record and for a free port 80, neither of which a
// DNS-01 renewal needs. Both refusals fired, and wildcard auto-renewal silently
// never ran.
type sslEffectiveChallenge struct {
	// Known false means we could not determine what acme.sh will do. Every
	// challenge-dependent check is then SKIPPED rather than guessed. That is the
	// safe direction: a missed warning costs nothing, while a false refusal stops
	// a renewal that would have succeeded.
	Known bool

	// NeedsPort80 is true only when acme.sh will bind port 80 on this host
	// itself, i.e. the standalone server. A webroot or tls-alpn challenge does
	// not, so testing the bind there would refuse on an irrelevant condition.
	NeedsPort80 bool

	// NeedsResolve is true for any HTTP-01 form, where the CA reaches the
	// identifier over the network and so it has to resolve to this host. False
	// for DNS-01, which proves control through a TXT record and needs no A
	// record at all.
	NeedsResolve bool

	// WebrootPath is the document root acme.sh will write the token into, empty
	// for every other method. Carried here rather than read from the request
	// because a RENEWAL has one too: acme.sh recorded it at issue time, and a
	// directory that has since been deleted or remounted read-only fails
	// validation exactly like a fresh one does.
	WebrootPath string

	// Source is how this was determined, for the step message.
	Source string
}

// sslPreflightDeps are the host probes, injected so the whole preflight is
// testable without a network, without root, without a real port 80 and without a
// real acme.sh state directory.
type sslPreflightDeps struct {
	now       func() time.Time
	lookupIP  func(host string) ([]net.IP, error)
	localIPs  func() ([]net.IP, error)
	publicIP  func() string
	portFree  func(port int) error
	ntpSynced func() (bool, bool) // (synced, determinable)

	// renewChallenge reports what acme.sh recorded for an already-issued
	// certificate. Consulted only for operations that are not an issue.
	renewChallenge func(primary string) sslEffectiveChallenge

	// webrootProbe writes the challenge file the way acme.sh will and then asks
	// the local webserver for it. Injected whole, because both halves need the
	// real filesystem and the real loopback interface, and because the panel runs
	// as root: a test that made a directory unwritable with chmod would prove
	// nothing on a host where the tests also run as root.
	webrootProbe func(root, identifier string) sslWebrootProbeResult
}

func defaultSSLPreflightDeps(storeRoot string) sslPreflightDeps {
	return sslPreflightDeps{
		now:          time.Now,
		lookupIP:     net.LookupIP,
		localIPs:     sslLocalIPs,
		publicIP:     GetServerIPv4,
		portFree:     sslPortFree,
		ntpSynced:    sslNTPSynced,
		webrootProbe: sslWebrootProbe,
		renewChallenge: func(primary string) sslEffectiveChallenge {
			return sslResolveRenewChallenge(SSLAcmeHome(storeRoot), primary)
		},
	}
}

// sslChallengeEffect maps a challenge WE are about to select onto what it will do.
// Issue-time only; for a renew see sslResolveRenewChallenge.
func sslChallengeEffect(req SSLPreflightRequest) sslEffectiveChallenge {
	switch req.Challenge {
	case SSLChallengeCloudflareDNS:
		return sslEffectiveChallenge{Known: true, Source: "Cloudflare DNS-01"}
	case SSLChallengeStandaloneDomain, SSLChallengeStandaloneIP:
		return sslEffectiveChallenge{Known: true, NeedsPort80: true, NeedsResolve: true, Source: "standalone HTTP-01"}
	case SSLChallengeWebroot:
		// NeedsPort80 is deliberately FALSE, and it is the entire feature. Something
		// else is supposed to be holding port 80 here; testing whether we can bind it
		// would refuse the exact configuration this challenge exists to serve.
		// NeedsResolve stays true, because HTTP-01 is still HTTP-01: Let's Encrypt
		// fetches the token from outside and has to arrive at this host to do it.
		return sslEffectiveChallenge{
			Known:        true,
			NeedsResolve: true,
			WebrootPath:  strings.TrimSpace(req.WebrootPath),
			Source:       "HTTP-01 through an existing webserver's document root",
		}
	default:
		return sslEffectiveChallenge{}
	}
}

// sslResolveRenewChallenge reads what acme.sh recorded for this certificate, so a
// renewal is checked against what will really happen rather than against a guess.
//
// The source of truth is Le_Webroot in <home>/<domain>[_ecc]/<domain>.conf, written
// at issue time (acme.sh:4972). The file is `key='value'` per line (_save_conf ->
// _setopt), and the values are markers rather than free text (acme.sh:71-78 and the
// argument handlers at :8631, :8639, :8680):
//
//	no        --standalone: acme.sh binds port 80 HERE
//	alpn      --alpn: binds port 443, so port 80 is irrelevant
//	dns       --dns with no hook, i.e. manual DNS-01
//	dns_cf …  --dns dns_cf, an automated DNS-01 hook
//	<path>    --webroot: some other server serves the token, we bind nothing
//
// Comma-separated when one certificate mixes methods, so the answer is the union:
// port 80 matters if ANY field is standalone, and resolution matters if ANY field
// is not a DNS method.
//
// Every failure path returns Known false, which skips the dependent checks. A bug
// in this parser can therefore only ever cost a warning, never cause a refusal.
func sslResolveRenewChallenge(acmeHome, primary string) sslEffectiveChallenge {
	primary = strings.TrimSpace(primary)
	if acmeHome == "" || primary == "" {
		return sslEffectiveChallenge{}
	}
	var webroot string
	var found bool
	for _, dir := range []string{primary, primary + "_ecc"} {
		conf := filepath.Join(acmeHome, dir, primary+".conf")
		data, err := os.ReadFile(conf)
		if err != nil {
			continue
		}
		if v, ok := sslConfValue(string(data), "Le_Webroot"); ok {
			webroot, found = v, true
			break
		}
	}
	if !found || strings.TrimSpace(webroot) == "" {
		return sslEffectiveChallenge{}
	}

	eff := sslEffectiveChallenge{Known: true}
	var kinds []string
	for _, field := range strings.Split(webroot, ",") {
		f := strings.TrimSpace(field)
		if f == "" {
			continue
		}
		switch {
		case f == "dns" || strings.HasPrefix(f, "dns_") || strings.HasPrefix(f, "dns-"):
			kinds = append(kinds, "DNS-01")
		case f == "no":
			eff.NeedsPort80 = true
			eff.NeedsResolve = true
			kinds = append(kinds, "standalone HTTP-01")
		case f == "alpn":
			// tls-alpn-01 wants port 443, which is not what sslCheckPort80 tests,
			// and the name still has to resolve for the CA to connect.
			eff.NeedsResolve = true
			kinds = append(kinds, "TLS-ALPN-01")
		default:
			// A webroot path, or apache/nginx/stateless: some other server answers
			// the token, so the name must resolve but we bind nothing.
			eff.NeedsResolve = true
			kinds = append(kinds, "HTTP-01 via "+f)
			// Only an ABSOLUTE path is a webroot. The other markers that land in
			// this branch (apache, nginx, stateless) are modes, not directories, and
			// stat-ing "apache" would report a missing webroot and refuse a renewal
			// that never had one. First one wins on a mixed certificate: they are
			// separate document roots for separate names, and checking one of them
			// is what is on offer.
			if eff.WebrootPath == "" && strings.HasPrefix(f, "/") {
				eff.WebrootPath = f
			}
		}
	}
	if len(kinds) == 0 {
		return sslEffectiveChallenge{}
	}
	eff.Source = strings.Join(kinds, " + ") + " (recorded by acme.sh at issue time)"
	return eff
}

// sslConfValue pulls key='value' out of an acme.sh conf file.
func sslConfValue(conf, key string) (string, bool) {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, key+"=") {
			continue
		}
		v := strings.TrimPrefix(line, key+"=")
		v = strings.TrimSpace(v)
		// _save_conf always single-quotes, but tolerate either form rather than
		// failing closed on a hand-edited file.
		v = strings.Trim(v, "'\"")
		return v, true
	}
	return "", false
}

// sslRunPreflight executes the checks in order of how cheaply they refuse: the
// ones that need no I/O first, so an operator repeat-clicking Issue gets an
// instant answer rather than a DNS timeout.
func sslRunPreflight(req SSLPreflightRequest, active *SSLCertInfo, ledger *SSLLedger, deps sslPreflightDeps) SSLPreflightResult {
	res := SSLPreflightResult{OK: true}
	block := func(step ProvisionStep) {
		res.Steps = append(res.Steps, step)
		if !res.Blocked {
			res.Blocked = true
			res.OK = false
			res.Reason = step.Msg
		}
	}
	pass := func(step ProvisionStep) { res.Steps = append(res.Steps, step) }

	ids := NormalizeSSLIdentifiers(req.Identifiers)
	if len(ids) == 0 {
		block(ProvisionStep{Name: "identifiers", Msg: "No domain or IP address given. A certificate has to name something."})
		return res
	}

	// 1. Shape. A wildcard can only ever be validated over DNS-01, so pairing it
	// with a standalone challenge is not a runtime failure to discover, it is a
	// request that cannot be satisfied.
	if s := sslCheckShape(ids, req); !s.OK {
		block(s)
		return res
	} else {
		pass(s)
	}

	ca := sslCAProduction
	if req.Staging {
		ca = sslCAStaging
	}

	// 2. The certificate already on disk. This one check kills most repeat
	// clicking, and it is free.
	if s, blocked := sslCheckExisting(req, active, deps.now()); blocked {
		block(s)
		return res
	} else if s.Name != "" {
		pass(s)
	}

	// 3. Local budget, before anything dials out.
	if ledger != nil {
		setKey := SSLIdentifierSetKey(ids)
		if cd := ledger.Cooldown(ids, ca); cd.Blocked {
			block(ProvisionStep{Name: "recent failures", Msg: cd.Reason})
			return res
		} else if cd.ConsecutiveFailures > 0 {
			pass(ProvisionStep{Name: "recent failures", OK: true, Warn: true, Msg: fmt.Sprintf(
				"%s since the last success for %s. The next failure lengthens the wait before a retry.",
				sslPluralAttempts(cd.ConsecutiveFailures)+" failed", cd.Identifier)})
		} else {
			pass(ProvisionStep{Name: "recent failures", OK: true, Msg: "No recent validation failures for these names."})
		}

		// Only --issue spends exact-set budget. A --renew carries the ARI
		// "replaces" field and is exempt, so gating it here would refuse a free
		// operation and push the operator towards the expensive one.
		if req.Op == SSLOpIssue {
			b := ledger.Budget(setKey, ca)
			switch {
			case b.Blocked:
				block(ProvisionStep{Name: "new-certificate budget", Msg: b.Reason})
				return res
			case b.Warn:
				pass(ProvisionStep{Name: "new-certificate budget", OK: true, Warn: true, Msg: b.Reason})
			default:
				pass(ProvisionStep{Name: "new-certificate budget", OK: true, Msg: fmt.Sprintf(
					"%d of %d new certificates for this exact set of names used in the last 7 days.", b.Used, b.Limit)})
			}
		} else {
			pass(ProvisionStep{Name: "new-certificate budget", OK: true, Msg: "Renewal through the --renew path is exempt from Let's Encrypt rate limits, so no budget is spent."})
		}
	}

	// What validation will ACTUALLY involve. For an issue we are choosing it, so
	// the request is the truth. For anything else acme.sh replays what it recorded
	// and our Challenge field is inert, so asking acme.sh is the only honest
	// answer and a guess would refuse on conditions that do not apply.
	eff := sslChallengeEffect(req)
	if req.Op != SSLOpIssue && deps.renewChallenge != nil {
		eff = deps.renewChallenge(sslPrimaryOf(req.Identifiers))
	}

	// 4. The webroot, whenever one is involved. Local filesystem, so it refuses
	// before anything dials out.
	//
	// It runs on a RENEWAL too, and that is the point of carrying the path on
	// sslEffectiveChallenge: acme.sh recorded a directory months ago, and a
	// document root that has since been deleted, replaced by a file or remounted
	// read-only fails validation exactly like a fresh issuance would. Nothing
	// about it involves port 80, so a webroot renewal never reaches check 6.
	if eff.Known && eff.WebrootPath != "" && deps.webrootProbe != nil {
		for _, s := range sslCheckWebroot(eff.WebrootPath, sslPrimaryOf(req.Identifiers), deps) {
			if !s.OK {
				block(s)
				return res
			}
			pass(s)
		}
	}

	// 5. Does the identifier actually point at this host. Skipped for DNS-01,
	// which proves control through a TXT record and needs no A record here.
	switch {
	case !eff.Known:
		pass(ProvisionStep{Name: "identifier points here", OK: true, Msg: "Skipped: acme.sh has no record of how this certificate was validated, so this check would be a guess. The renewal replays whatever it recorded."})
	case !eff.NeedsResolve:
		pass(ProvisionStep{Name: "identifier points here", OK: true, Msg: fmt.Sprintf(
			"Not required: validation is %s, which proves control through a DNS record rather than by connecting to this host.", eff.Source)})
	default:
		for _, s := range sslCheckReachability(ids, req.Challenge, deps) {
			if !s.OK {
				block(s)
				return res
			}
			pass(s)
		}
	}

	// 6. Port 80, only when acme.sh will bind it here.
	if eff.Known && eff.NeedsPort80 {
		s := sslCheckPort80(req.Challenge, deps)
		if !s.OK {
			block(s)
			return res
		}
		pass(s)
	} else if eff.Known {
		pass(ProvisionStep{Name: "port 80 free", OK: true, Msg: fmt.Sprintf(
			"Not required: validation is %s, which does not start a listener on this host.", eff.Source)})
	}

	// 7. Clock. Skew shows up as a JWS signature rejection, which reads as an
	// account problem and sends people to re-register rather than to their clock.
	pass(sslCheckClock(active, ledger, deps))
	return res
}

// sslCheckShape rejects combinations that cannot work, before any I/O.
//
// ISSUE ONLY, and that restriction is the fix for a real defect rather than a
// convenience. These checks all ask one question: "can the challenge we are about
// to select validate these names". On the renew path we do not select a challenge
// at all. renewArgs sends `--home --config-home --server --renew -d <primary>` and
// nothing else, so acme.sh reads the challenge, the SAN list and the profile from
// the per-domain conf it wrote at issue time. The Challenge field on a renew is
// preflight metadata that never reaches the CA.
//
// Applying the issue-time constraint anyway made RenewIfDue unable to renew a
// WILDCARD certificate: it has DNS names, so the challenge heuristic picks
// standalone-domain, and the wildcard rule below then refused the operation. The
// renewal simply never happened, and the only trace was a step in a run log nobody
// watches. Gating on the operation fixes the cause; making RenewIfDue guess
// cloudflare-dns instead would have papered over it and dragged a Cloudflare token
// requirement in behind it, for a flag that is never sent.
func sslCheckShape(ids []string, req SSLPreflightRequest) ProvisionStep {
	challenge, op := req.Challenge, req.Op
	if op != SSLOpIssue {
		return ProvisionStep{Name: "request shape", OK: true, Msg: fmt.Sprintf(
			"%d identifier(s). Renewal reuses the challenge acme.sh recorded when the certificate was first issued.", len(ids))}
	}

	// An unknown challenge errors HERE rather than four steps later in issueArgs.
	// It would still fail there, so this changes no outcome, only how soon and how
	// clearly: without it the run reaches "contacting Let's Encrypt", takes the
	// acme.sh home lock and reports a bare `unknown challenge "x"` with none of the
	// preflight's context. Never a silent default: whatever a defaulted challenge
	// picked would be a metered CA request for a method the operator did not ask
	// for.
	switch challenge {
	case SSLChallengeCloudflareDNS, SSLChallengeStandaloneDomain, SSLChallengeStandaloneIP, SSLChallengeWebroot:
	default:
		return ProvisionStep{Name: "request shape", Msg: fmt.Sprintf(
			"%q is not a validation method this panel knows. Choose one of: %s, %s, %s, %s.",
			challenge, SSLChallengeStandaloneDomain, SSLChallengeWebroot, SSLChallengeCloudflareDNS, SSLChallengeStandaloneIP)}
	}

	var wildcards []string
	for _, id := range ids {
		if strings.HasPrefix(id, "*.") {
			wildcards = append(wildcards, id)
		}
	}
	// Webroot is HTTP-01, so the wildcard rule catches it through this same
	// condition: Let's Encrypt validates a wildcard over DNS-01 and nothing else,
	// no matter who serves the token.
	if len(wildcards) > 0 && challenge != SSLChallengeCloudflareDNS {
		return ProvisionStep{Name: "request shape", Msg: fmt.Sprintf(
			"%s is a wildcard, and Let's Encrypt validates a wildcard only over DNS-01. Choose the Cloudflare DNS challenge, or drop the wildcard.",
			wildcards[0])}
	}
	if challenge == SSLChallengeWebroot {
		if strings.TrimSpace(req.WebrootPath) == "" {
			return ProvisionStep{Name: "request shape", Msg: "The webroot challenge needs the directory the webserver already serves, because that is where acme.sh writes the challenge file. It is `root` in the nginx server block or `DocumentRoot` in the apache vhost, commonly /var/www/html."}
		}
		// A MIXED set is refused, for the same reason the standalone challenges
		// refuse one: an IP identifier forces the shortlived profile, which applies
		// to the WHOLE certificate. Allowing the mix would quietly turn a 90-day
		// certificate for a name into a 160-hour one because an IP was typed in
		// beside it. Two certificates is the honest answer.
		var names, addrs []string
		for _, id := range ids {
			if net.ParseIP(id) != nil {
				addrs = append(addrs, id)
			} else {
				names = append(names, id)
			}
		}
		if len(names) > 0 && len(addrs) > 0 {
			return ProvisionStep{Name: "request shape", Msg: fmt.Sprintf(
				"This mixes a name (%s) with an IP address (%s). Let's Encrypt issues for an IP only under the shortlived profile, which would make the whole certificate last about six days. Issue two certificates instead.",
				names[0], addrs[0])}
		}
	}
	if challenge == SSLChallengeStandaloneIP {
		for _, id := range ids {
			if net.ParseIP(id) == nil {
				return ProvisionStep{Name: "request shape", Msg: fmt.Sprintf(
					"%q is not an IP address, but the IP challenge was selected. Use the domain challenge for a name.", id)}
			}
		}
	}
	if challenge == SSLChallengeStandaloneDomain {
		for _, id := range ids {
			if net.ParseIP(id) != nil {
				return ProvisionStep{Name: "request shape", Msg: fmt.Sprintf(
					"%s is an IP address, but the domain challenge was selected. An IP certificate needs the IP challenge (Let's Encrypt issues it only under the shortlived profile).", id)}
			}
		}
	}
	return ProvisionStep{Name: "request shape", OK: true, Msg: fmt.Sprintf("%d identifier(s), %s challenge.", len(ids), challenge)}
}

// sslCheckExisting refuses when the certificate on disk is still comfortably
// valid. Reported with the exact expiry, because "not due yet" without a date is
// the kind of answer that gets clicked through.
func sslCheckExisting(req SSLPreflightRequest, active *SSLCertInfo, now time.Time) (ProvisionStep, bool) {
	if active == nil {
		return ProvisionStep{Name: "existing certificate", OK: true, Msg: "No managed certificate yet."}, false
	}
	// Only relevant when the request is for the SAME names. Asking for a
	// different set is a new certificate, not an early renewal.
	if SSLIdentifierSetKey(active.Identifiers) != SSLIdentifierSetKey(req.Identifiers) {
		return ProvisionStep{Name: "existing certificate", OK: true, Msg: fmt.Sprintf(
			"The active certificate covers a different set of names (%s), so this is a new certificate rather than a renewal.",
			strings.Join(active.Identifiers, ", "))}, false
	}

	// The independent floor. Deliberately checked even when acme.sh would be
	// happy to renew, because a wrong --days or an over-firing cron is exactly
	// the case where acme.sh's own opinion is the thing that is broken.
	if req.Op == SSLOpRenew {
		if err := sslCheckMinAge(active, now); err != nil {
			return ProvisionStep{Name: "existing certificate", Msg: err.Error()}, true
		}
	}

	if !active.RenewalDue {
		return ProvisionStep{Name: "existing certificate", Msg: fmt.Sprintf(
			"The active certificate for %s is valid until %s (%s left) and renewal is not due until %s. Nothing needs to be issued. Use Re-apply if a service is serving a stale copy.",
			strings.Join(active.Identifiers, ", "),
			sslFormatTime(active.NotAfter), sslFormatDuration(active.Remaining),
			sslFormatTime(active.RenewalDueAt))}, true
	}

	return ProvisionStep{Name: "existing certificate", OK: true, Msg: fmt.Sprintf(
		"The active certificate expires %s (%s left), so renewal is due.",
		sslFormatTime(active.NotAfter), sslFormatDuration(active.Remaining))}, false
}

// sslCheckReachability answers "will the CA find this host at this identifier".
//
// Note what it does NOT do: refuse on a mismatch it cannot explain. A cloud VM
// behind 1:1 NAT (AWS, GCP) has a private address on its interface and a public
// one at the edge, and from inside the box that is indistinguishable from a DNS
// record pointing somewhere else entirely. Refusing there would block a perfectly
// good issuance, so an unexplained mismatch warns and names both addresses.
func sslCheckReachability(ids []string, challenge string, deps sslPreflightDeps) []ProvisionStep {
	if challenge == SSLChallengeCloudflareDNS {
		return []ProvisionStep{{Name: "identifier points here", OK: true,
			Msg: "DNS-01 proves control through a TXT record, so the name does not have to resolve to this host."}}
	}

	local, _ := deps.localIPs()
	public := strings.TrimSpace(deps.publicIP())
	if public == "N/A" {
		public = ""
	}

	var steps []ProvisionStep
	for _, id := range ids {
		if ip := net.ParseIP(id); ip != nil {
			steps = append(steps, sslCheckIPIdentifier(id, ip, local, public))
			continue
		}
		steps = append(steps, sslCheckNameIdentifier(id, local, public, deps))
	}
	return steps
}

func sslCheckIPIdentifier(id string, ip net.IP, local []net.IP, public string) ProvisionStep {
	if reason := sslIPUnroutableReason(id); reason != "" {
		return ProvisionStep{Name: "identifier points here: " + id, Msg: fmt.Sprintf(
			"%s is %s. Let's Encrypt will not issue for it, and asking spends one of five validation attempts per hour. Use this host's public address, or a domain name.",
			id, reason)}
	}
	if sslIPBoundLocally(ip, local) {
		return ProvisionStep{Name: "identifier points here: " + id, OK: true,
			Msg: fmt.Sprintf("%s is configured on a local interface.", id)}
	}
	if public != "" && public == ip.String() {
		return ProvisionStep{Name: "identifier points here: " + id, OK: true, Warn: true, Msg: fmt.Sprintf(
			"%s is this host's detected public address but is not on a local interface, which is normal behind 1:1 NAT. Let's Encrypt connects to it directly, so the NAT must forward TCP port 80 here.", id)}
	}
	if public == "" {
		return ProvisionStep{Name: "identifier points here: " + id, OK: true, Warn: true, Msg: fmt.Sprintf(
			"%s is not on a local interface and this host's public address could not be detected, so this could not be verified. Let's Encrypt connects to %s itself on TCP port 80, so it has to be this machine's own address.", id, id)}
	}
	return ProvisionStep{Name: "identifier points here: " + id, Msg: fmt.Sprintf(
		"%s is neither configured on a local interface nor this host's detected public address (%s). Let's Encrypt validates an IP certificate by connecting to %s itself, so it would reach a different machine. Issue for %s instead.",
		id, public, id, public)}
}

func sslCheckNameIdentifier(id string, local []net.IP, public string, deps sslPreflightDeps) ProvisionStep {
	addrs, err := deps.lookupIP(id)
	if err != nil || len(addrs) == 0 {
		return ProvisionStep{Name: "identifier points here: " + id, Msg: fmt.Sprintf(
			"%s does not resolve from this host. Let's Encrypt resolves it the same way and will fail, spending one of five validation attempts per hour. Add a public A or AAAA record first.", id)}
	}

	var routable []net.IP
	for _, a := range addrs {
		if sslIPUnroutableReason(a.String()) == "" {
			routable = append(routable, a)
		}
	}
	if len(routable) == 0 {
		return ProvisionStep{Name: "identifier points here: " + id, Msg: fmt.Sprintf(
			"%s resolves only to addresses the internet cannot reach (%s). Let's Encrypt has to connect from outside, so the record has to be a public address.",
			id, sslJoinIPs(addrs))}
	}
	for _, a := range routable {
		if sslIPBoundLocally(a, local) || (public != "" && a.String() == public) {
			return ProvisionStep{Name: "identifier points here: " + id, OK: true, Msg: fmt.Sprintf(
				"%s resolves to %s, which is this host.", id, a.String())}
		}
	}
	hostAddr := public
	if hostAddr == "" {
		hostAddr = "this host's address could not be detected"
	}
	return ProvisionStep{Name: "identifier points here: " + id, OK: true, Warn: true, Msg: fmt.Sprintf(
		"%s resolves to %s, which does not match this host (%s). That is expected behind 1:1 NAT or a load balancer, but if the record points at a different machine or at a CDN, HTTP-01 validation will fail.",
		id, sslJoinIPs(routable), hostAddr)}
}

// sslCheckPort80 is the single most valuable check here: a blocked or occupied
// port 80 is the most common cause of the authorization failure that drains the
// hourly bucket, and for an IP identifier there is no DNS-01 to fall back on.
func sslCheckPort80(challenge string, deps sslPreflightDeps) ProvisionStep {
	if err := deps.portFree(80); err != nil {
		extra := ""
		if challenge == SSLChallengeStandaloneIP {
			extra = " An IP certificate cannot use DNS-01 instead, so port 80 has to be free for the duration of the issuance."
		}
		return ProvisionStep{Name: "port 80 free", Msg: fmt.Sprintf(
			"TCP port 80 cannot be bound (%v), so acme.sh's standalone server will not start. Stop whatever holds it (a web server, or a previous acme.sh that did not exit) and retry.%s", err, extra)}
	}
	// Honest about the limit. Proving INBOUND reachability needs something
	// outside this host to connect back, and this panel deliberately contacts no
	// third-party prober: the first thing to connect to port 80 should be the CA.
	return ProvisionStep{Name: "port 80 free", OK: true, Warn: true, Msg: "TCP port 80 is free on this host. Whether Let's Encrypt can REACH it from the internet cannot be determined from here: check that no cloud firewall or security group blocks inbound TCP 80."}
}

// ---------------------------------------------------------------------------
// The webroot checks
// ---------------------------------------------------------------------------

// sslWebrootProbeResult is what the write-and-fetch probe found.
type sslWebrootProbeResult struct {
	// WriteErr is non-nil when the challenge file could not be written. This is
	// the operator error this whole check exists for, and the only one here that
	// refuses.
	WriteErr error

	// Served is true only when the local webserver returned our exact probe body,
	// which is the one answer that proves the document root is actually published
	// for this name.
	Served bool

	// Detail is a phrase naming what the local fetch found, for the step message.
	Detail string
}

// sslCheckWebroot is where the webroot challenge earns its place.
//
// The three ways a document root can be wrong all reach the CA as the same
// "authorization failed", which names nothing and costs one of five validation
// attempts per hour. Every check below costs a syscall.
//
// Blocks on the filesystem answers, which are unambiguous: a path that does not
// exist, is a file, or cannot be written CANNOT produce a token for the CA to
// fetch, whatever else is true about the host. Does NOT block on the serve probe:
// see sslCheckWebrootServed.
func sslCheckWebroot(root, identifier string, deps sslPreflightDeps) []ProvisionStep {
	root = strings.TrimSpace(root)
	// The path is in the step name, matching "identifier points here: <id>": the
	// operator is looking at several of these and needs to know which one failed.
	name := "webroot " + root

	// Relative, and therefore resolved against whatever directory acme.sh happens
	// to be started from. Refused rather than joined to something of our choosing,
	// because a guess here writes the token somewhere nobody serves.
	if !filepath.IsAbs(root) {
		return []ProvisionStep{{Name: name, Msg: fmt.Sprintf(
			"%q is not an absolute path. acme.sh resolves a relative webroot against whatever directory it was started from, which is not something to guess at. Give the full path, for example /var/www/html.", root)}}
	}

	fi, err := os.Stat(root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return []ProvisionStep{{Name: name, Msg: fmt.Sprintf(
			"The webroot %s does not exist. It has to be the directory the webserver serves for %s, which is `root` in the nginx server block or `DocumentRoot` in the apache vhost.", root, identifier)}}
	case err != nil:
		return []ProvisionStep{{Name: name, Msg: fmt.Sprintf("The webroot %s cannot be read (%v).", root, err)}}
	case !fi.IsDir():
		return []ProvisionStep{{Name: name, Msg: fmt.Sprintf(
			"The webroot %s is a file, not a directory. It has to be the directory the webserver serves, not a file inside it.", root)}}
	}

	res := deps.webrootProbe(root, identifier)
	if res.WriteErr != nil {
		return []ProvisionStep{{Name: name, Msg: fmt.Sprintf(
			"The challenge file cannot be written under %s (%v). acme.sh writes the token to %s/.well-known/acme-challenge/, so a webroot it cannot write into fails validation and spends one of five attempts per hour proving it.",
			root, res.WriteErr, root)}}
	}

	return []ProvisionStep{
		{Name: name, OK: true, Msg: fmt.Sprintf(
			"%s exists and the challenge file can be written to %s/.well-known/acme-challenge/. acme.sh binds no port for this challenge, so whatever is already serving port 80 keeps running.", root, root)},
		sslCheckWebrootServed(root, identifier, res),
	}
}

// sslCheckWebrootServed reports whether the webserver on THIS host actually
// published the file we just wrote, which is the second most likely operator
// error: the right directory, but a vhost whose root is somewhere else.
//
// It contacts nothing but 127.0.0.1. The panel deliberately does not call out to a
// third-party prober, and it does not need one: the file, the server and the
// answer are all on this machine.
//
// IT WARNS, IT NEVER REFUSES, and that is not timidity. A negative answer over
// loopback has at least three innocent causes, and each of them describes a host
// where real validation succeeds:
//   - the webserver listens on the public address only, so 127.0.0.1 is refused;
//   - a vhost selected by listen-address rather than by name answers differently
//     over loopback than it does at the edge;
//   - port 80 answers 301 to https, which Let's Encrypt follows and validates
//     through quite happily.
//
// A refusal on any of those would block an issuance that would have worked, which
// is the one outcome worse than the failure being prevented. The warning names
// what the local server said, which is what an operator with a wrong vhost root
// needs to see.
func sslCheckWebrootServed(root, identifier string, res sslWebrootProbeResult) ProvisionStep {
	name := "webroot is served"
	if res.Served {
		return ProvisionStep{Name: name, OK: true, Msg: fmt.Sprintf(
			"The webserver on this host served the challenge file for %s out of %s, which is exactly what Let's Encrypt will fetch.", identifier, root)}
	}
	return ProvisionStep{Name: name, OK: true, Warn: true, Msg: fmt.Sprintf(
		"Could not confirm from this host that the webserver publishes %s for %s: %s. If it answers 404, the vhost for that name has a different root and validation will fail; a redirect or a refused connection on 127.0.0.1 is usually harmless, because Let's Encrypt follows redirects and connects to the public address.",
		root, identifier, res.Detail)}
}

// sslWebrootProbeFile is the name of the file the probe writes. Distinctive on
// purpose: it lands in a directory an operator may go looking at, and a stray one
// left behind by a killed process should say what wrote it.
const sslWebrootProbeFile = "vpn-ui-preflight-"

// sslWebrootProbe performs EXACTLY the write acme.sh performs, then fetches the
// result over loopback.
//
// The write rather than access(2), because the panel runs as root and access(2)
// answers yes for root on a directory nothing can actually be written to (a
// read-only mount, an immutable attribute). The only honest test of "can we write
// here" is writing here.
//
// THE MODES ARE LOAD-BEARING, and getting them wrong would make this check the
// cause of the failure it exists to prevent. acme.sh creates the tree under
// `umask ugo+rx` and then chmods the token a+r (acme.sh:5586-5600), because the
// file is read by the webserver's user, not by root. A probe that created
// .well-known/ mode 0700 would leave a directory acme.sh's own `mkdir -p` then
// silently skips, and nginx running as www-data could not traverse into it.
// Directories that already exist are left exactly as the operator set them.
func sslWebrootProbe(root, identifier string) sslWebrootProbeResult {
	dir := root
	for _, part := range []string{".well-known", "acme-challenge"} {
		dir = filepath.Join(dir, part)
		if _, err := os.Stat(dir); err == nil {
			continue
		}
		if err := os.Mkdir(dir, 0o755); err != nil {
			return sslWebrootProbeResult{WriteErr: err}
		}
		// Mkdir applies the process umask, which is why acme.sh overrides it.
		_ = os.Chmod(dir, 0o755)
	}

	token := sslWebrootProbeFile + strconv.FormatInt(time.Now().UnixNano(), 36)
	body := "vpn-ui webroot preflight " + token
	file := filepath.Join(dir, token)
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		return sslWebrootProbeResult{WriteErr: err}
	}
	// Not pointless despite the file being removed a moment later: the fetch below
	// goes through the webserver, which reads it as ITS user. Under a restrictive
	// umask WriteFile would land 0600, nginx would answer 403, and the serve check
	// would report a broken webroot that is perfectly fine.
	_ = os.Chmod(file, 0o644)
	// Removed either way. A preflight is called as often as the UI likes, and it
	// has no business leaving files in the operator's document root.
	defer func() { _ = os.Remove(file) }()

	served, detail := sslWebrootFetchLocal(identifier, token, body)
	return sslWebrootProbeResult{Served: served, Detail: detail}
}

// sslWebrootFetchLocal asks the webserver on this host for the probe file.
func sslWebrootFetchLocal(identifier, token, body string) (bool, string) {
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/.well-known/acme-challenge/"+token, nil)
	if err != nil {
		return false, err.Error()
	}
	// The Host header is the identifier, because a name is the ONLY thing nginx and
	// apache use to pick a vhost. Fetching with Host: 127.0.0.1 would test the
	// default server rather than the one Let's Encrypt will reach.
	req.Host = identifier

	client := &http.Client{
		// Short, because this is loopback and the preflight is interactive.
		Timeout: 3 * time.Second,
		// NOT followed. A 301 from port 80 to https is the single most common
		// nginx configuration there is, Let's Encrypt follows it and validates
		// through it, and following it here would land on this host's own TLS and
		// report a certificate error as though the webroot were broken.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("nothing answered http://127.0.0.1/ (%v)", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return false, fmt.Sprintf("it answered %d and redirected to %q", resp.StatusCode, resp.Header.Get("Location"))
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Sprintf("it answered %d", resp.StatusCode)
	}
	// Capped: this is an unknown server's response body, and only the first line
	// could ever match anyway.
	got, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false, fmt.Sprintf("it answered 200 but the body could not be read (%v)", err)
	}
	if strings.TrimSpace(string(got)) != body {
		return false, "it answered 200 with different content, so something other than the file on disk is answering that path"
	}
	return true, "served"
}

// sslCheckClock looks for skew using only local evidence. A real skew check needs
// a trusted time source, and contacting one is network I/O this panel does not do
// on the operator's behalf. What is free: a certificate we already hold cannot
// have been issued in our future, and the ledger cannot have entries from it
// either. Both catch the gross case (a VM resumed from a snapshot, a host with no
// RTC battery) that produces the confusing JWS failures.
func sslCheckClock(active *SSLCertInfo, ledger *SSLLedger, deps sslPreflightDeps) ProvisionStep {
	now := deps.now()

	if active != nil && now.Before(active.NotBefore) {
		return ProvisionStep{Name: "clock", OK: true, Warn: true, Msg: fmt.Sprintf(
			"This host's clock reads %s, which is BEFORE the certificate it already holds was issued (%s). The clock is wrong, and Let's Encrypt will reject the request's signature with an error that mentions the account, not the time. Fix the clock (enable NTP) first.",
			sslFormatTime(now), sslFormatTime(active.NotBefore))}
	}
	if ledger != nil {
		if attempts := ledger.Attempts(); len(attempts) > 0 && now.Before(attempts[0].At) {
			return ProvisionStep{Name: "clock", OK: true, Warn: true, Msg: fmt.Sprintf(
				"This host's clock reads %s, which is before the most recent recorded attempt (%s). Time has gone backwards, so the rate-limit windows below are unreliable until the clock is fixed.",
				sslFormatTime(now), sslFormatTime(attempts[0].At))}
		}
	}
	if synced, determinable := deps.ntpSynced(); determinable && !synced {
		return ProvisionStep{Name: "clock", OK: true, Warn: true,
			Msg: "This host's clock is not synchronised to a time source. Clock skew makes Let's Encrypt reject the request signature, and the error it returns talks about the account key rather than the time. Enable NTP."}
	}
	return ProvisionStep{Name: "clock", OK: true, Msg: fmt.Sprintf("Host clock reads %s.", sslFormatTime(now))}
}

// sslPortFree reports whether a port can be bound. Binds and immediately closes,
// which is the only answer that is actually true at this instant: asking the
// kernel for a listener list races with anything about to start one.
func sslPortFree(port int) error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	return ln.Close()
}

// sslNTPSynced asks systemd-timedated. Returns (synced, determinable), because a
// host with no timedatectl is not a host with a bad clock.
func sslNTPSynced() (bool, bool) {
	out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").Output()
	if err != nil {
		return false, false
	}
	switch strings.TrimSpace(string(out)) {
	case "yes", "true":
		return true, true
	case "no", "false":
		return false, true
	}
	return false, false
}

func sslIPBoundLocally(ip net.IP, local []net.IP) bool {
	for _, l := range local {
		if l.Equal(ip) {
			return true
		}
	}
	return false
}

func sslJoinIPs(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// The IP validator, ported from ssl_ip_valid / _v4 / _v6 in vpn-ui.sh:289-346.
//
// Ported rather than shelled out to, so the panel and the installer cannot drift
// apart on what counts as an address worth spending a validation attempt on.
// Every rejection here is one that Let's Encrypt would also make, and their
// version of the answer costs a slot out of five per hour.
//
// Deliberately NOT rejected, matching the shell: the documentation ranges
// (203.0.113.0/24, 2001:db8::/32). They are what every example in the docs uses,
// and an operator testing the flow against one should get the CA's answer rather
// than ours.
// ---------------------------------------------------------------------------

// sslIPv4Re forbids a leading zero in an octet on purpose. The string reaches
// acme.sh verbatim, so "08.8.8.8" would go to the CA exactly as typed and be
// refused as malformed. Normalising it to 8.8.8.8 here would instead request a
// certificate for an address the operator never named.
var sslIPv4Re = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$`)

// sslIPv6HexRunRe catches a group longer than four hex digits.
var sslIPv6HexRunRe = regexp.MustCompile(`[0-9A-Fa-f]{5}`)

// sslIPValid reports whether Let's Encrypt would plausibly issue for this IP
// literal. A pure predicate: no I/O, no state, so the challenge chooser can call
// it before anything has been decided.
func sslIPValid(ip string) bool { return sslIPUnroutableReason(ip) == "" }

// sslIPUnroutableReason returns "" when the address is fine, or a human phrase
// naming why it is not, so the caller can build a message that says what is
// actually wrong instead of "invalid IP".
func sslIPUnroutableReason(ip string) string {
	if strings.Contains(ip, ":") {
		return sslIPv6UnroutableReason(ip)
	}
	return sslIPv4UnroutableReason(ip)
}

func sslIPv4UnroutableReason(ip string) string {
	m := sslIPv4Re.FindStringSubmatch(ip)
	if m == nil {
		return "not a valid IPv4 address"
	}
	octets := make([]int, 4)
	for i := 0; i < 4; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil || n > 255 {
			return "not a valid IPv4 address"
		}
		octets[i] = n
	}
	a, b := octets[0], octets[1]
	switch {
	case a == 0:
		return "in 0.0.0.0/8, which is not a routable address"
	case a == 10, a == 172 && b >= 16 && b <= 31, a == 192 && b == 168:
		return "a private address (RFC 1918), not reachable from the internet"
	case a == 127:
		return "a loopback address, reachable only from this machine"
	case a == 169 && b == 254:
		return "a link-local address, not reachable from the internet"
	case a == 100 && b >= 64 && b <= 127:
		return "inside carrier-grade NAT (100.64.0.0/10), so it is not this host's own public address"
	case a >= 224:
		return "in the multicast or reserved range (224.0.0.0/4 and above)"
	}
	return ""
}

func sslIPv6UnroutableReason(ip string) string {
	// Hex and colons only. This is what rejects a zone id ("fe80::1%eth0") and the
	// ::ffff:1.2.3.4 mapped form, which is an IPv4 address in v6 clothing and not
	// something the CA accepts as a v6 identifier.
	for _, r := range ip {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == ':') {
			return "not a valid IPv6 address"
		}
	}
	if ip == "" || strings.Contains(ip, ":::") || sslIPv6HexRunRe.MatchString(ip) {
		return "not a valid IPv6 address"
	}
	// The colon count a real address has: exactly 7 written out, 2 to 7 once "::"
	// has collapsed a run of zeroes. Cheaper and less fragile than expanding the
	// address, and the CA is the final authority on syntax anyway; the job here is
	// only to catch the obviously wrong.
	colons := strings.Count(ip, ":")
	if strings.Contains(ip, "::") {
		if colons < 2 || colons > 7 {
			return "not a valid IPv6 address"
		}
	} else if colons != 7 {
		return "not a valid IPv6 address"
	}
	if strings.HasPrefix(ip, "::") {
		return "not a global unicast address (2000::/3)"
	}
	first, _, _ := strings.Cut(ip, ":")
	// An empty first group means a single leading colon (":1:2:..."), which is
	// malformed. The shell reached the same verdict only by way of an arithmetic
	// error on an empty operand.
	if first == "" {
		return "not a valid IPv6 address"
	}
	v, err := strconv.ParseUint(first, 16, 32)
	if err != nil {
		return "not a valid IPv6 address"
	}
	// 2000::/3 is the only global unicast space IANA has assigned, so every
	// address a server is reachable at from the internet starts there. Testing for
	// that instead of listing loopback, link-local, unique-local and multicast
	// separately is one comparison instead of four.
	if v < 0x2000 || v > 0x3fff {
		return "not a global unicast address (2000::/3), so it is not reachable from the internet"
	}
	return ""
}

// sslPrimaryOf is the identifier acme.sh files a certificate under: the first one
// the operator gave, un-normalised, because that is exactly the string that was
// passed to -d and therefore names the state directory.
func sslPrimaryOf(ids []string) string {
	for _, id := range ids {
		if s := strings.TrimSpace(id); s != "" {
			return s
		}
	}
	return ""
}
