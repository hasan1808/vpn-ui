package service

import (
	"fmt"
	"net"
	"strings"
)

// Choosing the validation method instead of asking for it.
//
// WHY THIS EXISTS. The settings page used to present four validation options and
// ask the operator to pick one. Every input to that decision is something this
// host can determine for itself in a few milliseconds: whether the identifier is a
// name, an IP or a wildcard, and whether anything already holds port 80. Asking
// the operator to pick was asking them to run the probe by hand, in a vocabulary
// (HTTP-01, DNS-01, webroot) that describes the protocol rather than their
// situation.
//
// ADVICE, NOT A GATE. Nothing here refuses an operation. The authority is still
// sslRunPreflight, which runs inside the background run before anything metered
// happens (sslmanager.go). This returns a method and a sentence justifying it, so
// the one confirmation the operator sees before a metered request says what is
// about to happen and why. Blocked here means "no method could work", which is
// worth saying before the run rather than 40 seconds into it, but the run would
// refuse the same case on its own.
//
// WEBROOT IS NEVER SUGGESTED, and that is deliberate. It is the one method that
// needs a fact about the host this panel cannot discover: which directory some
// other webserver publishes for this name. A suggestion that has to be completed
// by hand is not a suggestion. Operators who need it still have it through the
// API; it simply stopped being one of four buttons on a page.

// SSLSuggestion is how the panel proposes to prove the identifiers are yours.
type SSLSuggestion struct {
	// Identifiers is the cleaned set, in the ORDER given. Order is load-bearing:
	// the first one is the name acme.sh files the certificate under and addresses
	// every later renewal by (sslacme.go).
	Identifiers []string `json:"identifiers"`

	// Challenge is the method to send to Start. Empty when Blocked.
	Challenge string `json:"challenge"`

	// Reason is one sentence naming what was found, for the confirmation the
	// operator reads before a metered request. It is the whole justification they
	// get, so it names the finding, not the protocol.
	Reason string `json:"reason"`

	// NeedsToken is true when the chosen method cannot run without a Cloudflare
	// API token, so the confirmation has to ask for one.
	NeedsToken bool `json:"needsToken"`

	// Blocked means no method on this host can validate this set. Reason says why.
	Blocked bool `json:"blocked"`

	// Warnings are findings that do not stop the attempt but are the likeliest
	// reason it will fail. Shown in the confirmation, because a failed validation
	// costs one of five slots per identifier per hour and takes twelve minutes to
	// come back.
	Warnings []string `json:"warnings,omitempty"`

	// Profile is the store this certificate would land in, derived from the first
	// identifier. Returned so the client sends back the same name the suggestion
	// was computed for rather than deriving it a second time in JavaScript.
	Profile string `json:"profile"`
}

// Suggest picks the validation method for a set of identifiers.
func (s *SSLService) Suggest(identifiers []string) SSLSuggestion {
	return sslSuggest(identifiers, defaultSSLPreflightDeps(DefaultSSLStoreRoot()))
}

// sslSuggest is Suggest with the host probes injected, so the decision table is
// testable without a real port 80 and without DNS.
func sslSuggest(identifiers []string, deps sslPreflightDeps) SSLSuggestion {
	ids := sslCleanIdentifiers(identifiers)
	sg := SSLSuggestion{Identifiers: ids}
	if len(ids) == 0 {
		sg.Blocked = true
		sg.Reason = "Type the address people will use to reach this server, then try again."
		return sg
	}
	sg.Profile = SSLProfileNameFor(ids)

	var names, addrs, wildcards []string
	for _, id := range ids {
		switch {
		case strings.HasPrefix(id, "*."):
			wildcards = append(wildcards, id)
			names = append(names, id)
		case net.ParseIP(id) != nil:
			addrs = append(addrs, id)
		default:
			names = append(names, id)
		}
	}

	// A name beside an IP is refused by every method, and not for a reason the
	// operator can work around by choosing differently: Let's Encrypt issues for
	// an IP only under the shortlived profile, and a profile applies to the WHOLE
	// certificate. Allowing it would quietly cut a 90-day certificate for the name
	// down to about six days.
	if len(names) > 0 && len(addrs) > 0 {
		sg.Blocked = true
		sg.Reason = fmt.Sprintf(
			"%s is a name and %s is an IP address. One certificate cannot hold both: an IP forces a six-day certificate, and that would apply to the name as well. Get two certificates instead.",
			names[0], addrs[0])
		return sg
	}

	port80 := deps.portFree(80)

	// A wildcard is validated over DNS-01 and nothing else, whoever serves the
	// token, so port 80 does not enter into it.
	if len(wildcards) > 0 {
		sg.Challenge = SSLChallengeCloudflareDNS
		sg.NeedsToken = true
		sg.Reason = fmt.Sprintf(
			"%s is a wildcard, and a wildcard can only be proved through a DNS record. We will add a temporary record through Cloudflare and remove it afterwards.",
			wildcards[0])
		return sg
	}

	// An IP identifier has NO DNS-01 escape hatch: there is nothing to put a TXT
	// record on. Port 80 is not one option among several here, it is the only one,
	// which is why a busy port 80 blocks instead of falling through to DNS.
	if len(addrs) > 0 {
		sg.Challenge = SSLChallengeStandaloneIP
		if port80 != nil {
			sg.Blocked = true
			sg.Challenge = ""
			sg.Reason = fmt.Sprintf(
				"Something on this server already holds port 80 (%v). An IP address can only be proved over port 80, because there is no DNS record to put a token on. Stop whatever holds it and try again.",
				port80)
			return sg
		}
		sg.Reason = fmt.Sprintf(
			"%s is an IP address, so we will answer the check on port 80 ourselves. Let's Encrypt issues for an IP only as a short-lived certificate, valid about six days, which the panel renews for you.",
			addrs[0])
		sg.Warnings = append(sg.Warnings, sslSuggestReachWarnings(addrs, deps)...)
		return sg
	}

	// Names. Port 80 free is the ordinary case and needs nothing from the
	// operator, so it wins whenever it is available.
	if port80 == nil {
		sg.Challenge = SSLChallengeStandaloneDomain
		sg.Reason = sslSuggestNamesReason(names)
		sg.Warnings = append(sg.Warnings, sslSuggestReachWarnings(names, deps)...)
		return sg
	}

	// Port 80 is taken, which on a host running its own webserver is normal and
	// permanent. DNS-01 is then the only method left that needs nothing stopped.
	sg.Challenge = SSLChallengeCloudflareDNS
	sg.NeedsToken = true
	sg.Reason = fmt.Sprintf(
		"Something on this server already holds port 80 (%v), so the check cannot be answered there. We will prove the name through a temporary Cloudflare DNS record instead, and remove it afterwards.",
		port80)
	return sg
}

// sslSuggestNamesReason states what will happen, in the operator's terms.
func sslSuggestNamesReason(names []string) string {
	if len(names) == 1 {
		return fmt.Sprintf(
			"Port 80 is free on this server, so we will answer the check for %s there ourselves. It is borrowed for about ten seconds.",
			names[0])
	}
	return fmt.Sprintf(
		"Port 80 is free on this server, so we will answer the check for all %d names there ourselves. It is borrowed for about ten seconds.",
		len(names))
}

// sslSuggestReachWarnings reports identifiers that will not validate over HTTP-01
// because the CA would not reach this host at them.
//
// A warning, never a refusal: the check reuses the preflight's own per-identifier
// probe, which is deliberately generous about hosts behind a proxy or a NAT it
// cannot see through. The run's preflight makes the actual call.
//
// Collects the WARN steps as well as the failures, and that is the point of it.
// The preflight marks "resolves somewhere that is not this host" as ok-with-a-warn
// on purpose, because 1:1 NAT and load balancers make it legitimate. It is still
// the single likeliest reason the attempt about to be paid for will fail, so it
// belongs in the confirmation and not only in the console afterwards.
func sslSuggestReachWarnings(ids []string, deps sslPreflightDeps) []string {
	local, err := deps.localIPs()
	if err != nil {
		return nil
	}
	public := deps.publicIP()

	var out []string
	for _, id := range ids {
		// A wildcard has no A record of its own to check, and is not validated
		// over HTTP anyway.
		if strings.HasPrefix(id, "*.") {
			continue
		}
		var step ProvisionStep
		if ip := net.ParseIP(id); ip != nil {
			step = sslCheckIPIdentifier(id, ip, local, public)
		} else {
			step = sslCheckNameIdentifier(id, local, public, deps)
		}
		if !step.OK || step.Warn {
			out = append(out, step.Msg)
		}
	}
	return out
}

// sslCleanIdentifiers trims, lowercases and dedupes WITHOUT sorting.
//
// NormalizeSSLIdentifiers sorts, because it builds the ledger's set key and two
// orderings of the same names are one budget. Here the order is the operator's and
// has to survive: the first identifier becomes the certificate's filename in the
// acme.sh state directory and the name every later renewal is addressed by.
func sslCleanIdentifiers(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.ToLower(strings.TrimSpace(raw))
		id = strings.TrimSuffix(id, ".")
		if id == "" {
			continue
		}
		if ip := net.ParseIP(id); ip != nil {
			id = ip.String()
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
