package service

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"

	"go.uber.org/atomic"
	"gorm.io/gorm"
)

// Speed Limit: publish each account's effective rate to the patched Xray core.
//
// The policy is configured PER INBOUND but enforced PER EMAIL, because email is the
// account identity everywhere downstream (the unique key of client_traffics, the name
// RADIUS authenticates, the selector the per-account routing rules are built from).
// So every account on a limited inbound gets its OWN bucket at that rate: this is not
// a shared pool for the inbound, and an account's K devices share one bucket.
//
// The panel decides, Xray obeys. "Limit After" is resolved HERE against the usage the
// panel already tracks, and the core receives only the already-resolved rate. That
// keeps quota semantics (resets, VPN usage sourced from nft/RADIUS rather than Xray's
// own stats) in the one place that understands them, and keeps the fork patch small
// enough to rebase on every core bump.
//
// IP Limit rides the same sidecar, for the same reason: it is a per-account number the
// core needs at admission time and that changes without an Xray restart. It differs from
// the rates in three ways, all of them below: it is resolved from TWO columns rather than
// one (the inbound's default and the client's override, see resolveIPLimit), it has no
// "Limit After" (a concurrency rule is not a quota, so it applies from the first
// connection), and it is published only for inbounds whose source addresses the core can
// actually see (ipLimitEnforcedInCore).
//
// Its strategy (what to do AT the cap) rides along beside it, and is per inbound rather
// than per client, so an account on two inbounds resolves one strategy the same way it
// resolves one rate: see mergeIPLimitStrategy.
//
// The delivery path is a sidecar file, NOT the Xray config. A rate change must not
// touch anything in the xray.Config graph: Config.Equals would report a change and the
// debounced restart would drop every live connection on the box, and threshold
// crossings happen continuously as users consume data. For the same reason nothing
// here calls SetToNeedRestart.

// speedLimitUser is one account's published limits. Field order is fixed by this struct.
// The rates are BYTES PER SECOND and 0 in a direction means that direction is unlimited;
// ipLimit is a count of concurrent client source addresses and is omitted when 0, which
// the core reads as unlimited. An account that is unlimited in EVERY one of them is
// absent from the file entirely, so the core's common-case hot path is one map miss.
//
// strategy qualifies ipLimit and is omitted when it is the default ("reject"), so the
// core reads an absent strategy exactly as it reads an absent ipLimit: the safe default.
// Omitting the common value is not just brevity, it keeps the compare-then-write quiet:
// every byte that appears in the document is a byte that can differ between ticks.
type speedLimitUser struct {
	Email    string   `json:"email"`
	DownBps  int64    `json:"downBps"`
	UpBps    int64    `json:"upBps"`
	IPLimit  int      `json:"ipLimit,omitempty"`
	Strategy string   `json:"strategy,omitempty"`
	IPs      []string `json:"ips"`
}

// speedLimitDoc is the sidecar's whole schema.
type speedLimitDoc struct {
	Users []speedLimitUser `json:"users"`
}

// speedLimitClient is one account as an inbound carries it: the identity, plus the client's
// own IP cap. That cap is an OVERRIDE of the inbound's default, not the whole answer, so it
// is never read on its own: resolveIPLimit is what turns the pair into a published number.
type speedLimitClient struct {
	email   string
	ipLimit int
}

// speedLimitPolicy pairs one inbound's limiter columns with the clients it covers.
// Splitting this out of the DB read is what lets the resolution below be tested as a
// pure function, with no SQLite and no Settings JSON.
type speedLimitPolicy struct {
	inbound *model.Inbound
	clients []speedLimitClient
}

// bytesPerKB is the ONLY place the 1024-vs-1000 question exists. The UI speaks KB/s,
// every internal value and the sidecar speak bytes/s, and the conversion happens here
// once so no other site has to know which convention it is holding.
const bytesPerKB = 1024

// kbpsToBps converts a UI KB/s rate to bytes/s. Negative rates cannot arrive through
// the panel, but this is the last line of defence for a row that came some other way
// (an imported DB, a hand-edited SQLite file): a negative rate published to the core
// would be a negative token bucket limit, which is not "unlimited", it is "stalled".
func kbpsToBps(kbps int) int64 {
	if kbps <= 0 {
		return 0
	}
	return int64(kbps) * bytesPerKB
}

// inboundSpeedLimitRates resolves one inbound's columns into a candidate (down, up)
// pair in bytes/s, before "Limit After" is considered.
//
// SpeedLimitSeparate false means the single UI box caps EACH direction independently
// at that value, so the down value is mirrored onto up. It does NOT mean a combined
// up+down bucket, and SpeedLimitUp is not read at all in that mode. Mirroring here
// keeps the wire format one shape, so the core never learns the mode exists.
func inboundSpeedLimitRates(inb *model.Inbound) (down, up int64) {
	if inb == nil || !inb.SpeedLimitEnable {
		return 0, 0
	}
	down = kbpsToBps(inb.SpeedLimitDown)
	if inb.SpeedLimitSeparate {
		return down, kbpsToBps(inb.SpeedLimitUp)
	}
	return down, down
}

// speedLimitArmed reports whether an account with the given cumulative usage has
// passed inb's "Limit After" threshold.
//
// This is deliberately STATELESS: it re-derives the answer from the stored counter on
// every run rather than latching a flag. That is what makes the limit re-arm by itself
// whenever up/down are zeroed, no matter which path did the zeroing (the per-client
// reset field, the periodic reset job, an admin's manual reset). A latched flag would
// leave an account throttled after its quota was restored.
func speedLimitArmed(inb *model.Inbound, usage int64) bool {
	// 0 means apply from the very first byte, and is also the column default, so the
	// >= below already covers it. Spelled out because "0 = immediately" is a contract.
	return usage >= inb.SpeedLimitAfter
}

// minNonZero merges two candidate limits of the same kind, most restrictive wins. Used
// for a rate in one direction (bytes/s) and for an IP cap (a count) alike.
//
// The whole subtlety of the feature is here. 0 means UNLIMITED, not "zero bytes per
// second" or "zero addresses allowed", so a plain min() would let an unlimited inbound
// silently unlimit an account that a second inbound limits. 0 must therefore lose to any
// real limit, and win only against another 0.
func minNonZero[T int | int64](a, b T) T {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}

// resolveIPLimit resolves one client's effective cap from the inbound's default and the
// client's own override. 0 from both means unlimited, and the account is then absent from
// the file entirely.
//
// A client-level 0 INHERITS the inbound's default rather than forcing "unlimited". That is
// forced by the storage rather than chosen: LimitIP is a plain int, not a *int, so "never
// set" and "explicitly set to 0" are the same value and NO rule can tell them apart.
// Inheriting is the only reading that lets the inbound default mean anything at all, since
// every client that never touched the field carries 0. It changes existing behaviour only
// for an operator who actually sets a default: while the default is 0 (which is every
// inbound that predates the column) a client-level 0 is still unlimited, exactly as before.
// Pointer semantics would buy a genuine per-client "force unlimited" against a non-zero
// default, at the cost of a nullable column and a migration; nobody has asked for it.
//
// The > 0 guards are also the only defence against a NEGATIVE cap at either level:
// validateInboundConfig rejects negative rates but has no rule for these two columns, so an
// imported or hand-edited DB (or a direct API POST) can carry one. A negative published to
// the core is not "unlimited", it is "refuse every connection", so it is read as absent
// here, exactly as kbpsToBps reads a negative rate.
func resolveIPLimit(inb *model.Inbound, c speedLimitClient) int {
	if c.ipLimit > 0 {
		return c.ipLimit
	}
	if inb != nil && inb.IPLimit > 0 {
		return inb.IPLimit
	}
	return 0
}

// ipLimitEnforcedInCore reports whether an inbound's clients' resolved IP cap is the CORE's
// to enforce, which is the only case the sidecar may carry an ipLimit for.
//
// This is a correctness gate, not an optimisation. Publishing a cap for the excluded
// protocols would not merely be redundant, it would reject real devices:
//
//   - The VPN backends (isVpnProtocol) already enforce K at RADIUS auth, keyed by
//     Calling-Station-Id + NAS-Port, and the source address the core sees for them IS the
//     tunnel address that allocator just handed out, so an in-core cap would either never
//     fire or fight the allocator. wg-c and ikev2 psk/eap-tls are worse than redundant:
//     one account owns a whole CIDR block, so a router behind that single link
//     legitimately presents many source addresses and a cap of K would refuse them.
//   - ssh and mtproto reach Xray over the LOOPBACK (ssh_socks.go dials the socks inbound
//     at 127.0.0.1, and mtproto's socks inbound listens on 127.0.0.1), so the core sees
//     one source address for the entire protocol: a cap there would count every account's
//     devices as a single address, or refuse all of them. The real client address exists
//     only in the relay that terminated the connection, which is exactly where both
//     already cap it (ssh_server.go admit(), telemt's user_max_unique_ips).
//
// isVpnProtocol is reused rather than restated so a new VPN backend is excluded here the
// day it is added, but it deliberately does not cover ssh/mtproto (it answers a different
// question: whether the live add/del inbound API may touch the tag), so those two are
// excluded by name.
func ipLimitEnforcedInCore(inb *model.Inbound) bool {
	if inb == nil {
		return false
	}
	return !isVpnProtocol(inb.Protocol) && inb.Protocol != model.SSH && inb.Protocol != model.MTPROTO
}

// The two IP Limit strategies, spelled once. These are the VPN User Limit's words
// (normUserLimitStrategy) and ssh's (sshManager.admit), because it is one user-facing
// feature with three enforcement points; a fourth spelling would be a fourth feature as
// far as an operator reading the UI is concerned.
const (
	ipLimitStrategyReject = "reject"
	ipLimitStrategyAccept = "accept"
)

// normIPLimitStrategy resolves one inbound's column to a strategy the core can act on.
//
// Anything that is not exactly "accept" is "reject". This is the only validation the value
// gets, deliberately: the column has no validator in validateInboundConfig, so "" (an API
// POST that omits the field binds the zero value, and UpdateInbound copies it verbatim)
// and any typo an imported or hand-edited DB carries both land here. Reading an unknown
// word as reject rather than accept is the direction that matters: reject only refuses a
// newcomer, while accept tears down a session that is already carrying traffic, so a typo
// must never be licence to disconnect anyone.
func normIPLimitStrategy(inb *model.Inbound) string {
	if inb != nil && inb.IPLimitStrategy == ipLimitStrategyAccept {
		return ipLimitStrategyAccept
	}
	return ipLimitStrategyReject
}

// mergeIPLimitStrategy merges two inbounds' strategies for one email, REJECT WINS. The
// empty string means "nothing contributed yet" and loses to both, exactly as 0 does in
// minNonZero.
//
// Same "most restrictive wins" spirit as minNonZero, and reject is the less disruptive of
// the two despite the harsher name: it refuses a newcomer, while accept disconnects a
// session that is already carrying traffic. An account spanning two inbounds cannot have
// its established connection killed by a policy set on the OTHER inbound.
func mergeIPLimitStrategy(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if a == ipLimitStrategyReject || b == ipLimitStrategyReject {
		return ipLimitStrategyReject
	}
	return ipLimitStrategyAccept
}

// normalizeSpeedLimitIP renders one BuildVpnEmailToIPMap value as a CIDR.
//
// That map mixes shapes: the ppp-family paths yield a bare address ("10.2.0.5") while
// the ikev2 psk/eap-tls and wg-c paths yield a block ("10.6.0.0/24"), because those
// two model an account as a whole block rather than K owned addresses. The core indexes
// these into one prefix trie, so widening the bare addresses to host routes here keeps
// the file to a single shape and the trie to a single parse.
func normalizeSpeedLimitIP(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.Contains(v, "/") {
		return v
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return v
	}
	if ip.To4() != nil {
		return v + "/32"
	}
	return v + "/128"
}

// speedLimitIPs returns email's tunnel addresses as a sorted, deduplicated CIDR list.
// Never nil: an account with no addresses must still serialize as an empty JSON array,
// see computeSpeedLimits.
func speedLimitIPs(email string, ipMap map[string][]string) []string {
	raw := ipMap[email]
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, v := range raw {
		v = normalizeSpeedLimitIP(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// computeSpeedLimits resolves every policy into the accounts' published limits.
//
// usage is cumulative up+down per email, and ipMap is BuildVpnEmailToIPMap's output.
// The result is sorted by email, with each user's ips sorted, because the output is
// compared byte-for-byte against the file on disk (see WriteSpeedLimits): map order
// alone would make every tick look like a change.
func computeSpeedLimits(policies []speedLimitPolicy, usage map[string]int64, ipMap map[string][]string) []speedLimitUser {
	type limits struct {
		down, up int64
		ipLimit  int
		strategy string
	}
	merged := make(map[string]limits)

	for _, p := range policies {
		down, up := inboundSpeedLimitRates(p.inbound)
		coreIPCap := ipLimitEnforcedInCore(p.inbound)
		// The rates and the IP cap are INDEPENDENT contributions: an inbound with no
		// speed limit at all still publishes its clients' caps. Skipping the policy on
		// the rates alone is what would make an ipLimit-only account (the common case
		// once the IP Limit UI is visible again) silently absent from the file, i.e. the
		// feature doing nothing at all.
		if down == 0 && up == 0 && !coreIPCap {
			continue
		}
		for _, c := range p.clients {
			if c.email == "" {
				continue
			}
			m := merged[c.email]
			// Same email on several inbounds: minimum non-zero wins, per direction and
			// independently. The bucket is per email, so per-(email, inbound) rates would
			// hand a user on two inbounds twice their intended bandwidth.
			//
			// Below the threshold this inbound contributes NOTHING rather than
			// contributing "unlimited": a not-yet-armed inbound must not unlimit an
			// account that an armed one limits, which is the same 0-loses-the-min rule.
			// down/up are 0 for an ipLimit-only inbound, so this is a no-op there.
			if speedLimitArmed(p.inbound, usage[c.email]) {
				m.down = minNonZero(m.down, down)
				m.up = minNonZero(m.up, up)
			}
			// "Limit After" is deliberately not consulted for the cap: it is a
			// concurrency rule, not a quota, so it applies from the first connection.
			//
			// resolveIPLimit has already folded in the inbound's default and read the
			// negatives as absent, so a 0 here is a genuinely uncapped account. Keeping it
			// out of the min is what min() itself would get wrong, since it would take 0
			// for a real value.
			if ipCap := resolveIPLimit(p.inbound, c); coreIPCap && ipCap > 0 {
				m.ipLimit = minNonZero(m.ipLimit, ipCap)
				// The strategy is contributed by exactly the inbounds that contribute a
				// cap. An inbound that caps nobody has no opinion to merge: honouring its
				// strategy would let an inbound the account is not capped on decide what
				// happens at a cap set somewhere else.
				m.strategy = mergeIPLimitStrategy(m.strategy, normIPLimitStrategy(p.inbound))
			}
			merged[c.email] = m
		}
	}

	users := make([]speedLimitUser, 0, len(merged))
	for email, r := range merged {
		if r.down == 0 && r.up == 0 && r.ipLimit == 0 {
			continue // fully unlimited: absent from the file, so the core allocates nothing
		}
		// The default is published as an ABSENCE, not as the word: r.strategy is only ever
		// non-empty when a cap was contributed, so this also guarantees a strategy never
		// appears without the ipLimit it qualifies.
		strategy := r.strategy
		if strategy == ipLimitStrategyReject {
			strategy = ""
		}
		users = append(users, speedLimitUser{
			Email:    email,
			DownBps:  r.down,
			UpBps:    r.up,
			IPLimit:  r.ipLimit,
			Strategy: strategy,
			// Accounts with no addresses (ssh, mtproto, native Xray) still belong here:
			// their email arrives on the session itself, so they never touch the trie.
			IPs: speedLimitIPs(email, ipMap),
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
	return users
}

// speedLimitDocument renders the policies as the sidecar's bytes. Deterministic for a
// given input: identical input must produce identical bytes, which is what lets the
// writer skip unchanged ticks.
func speedLimitDocument(policies []speedLimitPolicy, usage map[string]int64, ipMap map[string][]string) ([]byte, error) {
	doc := speedLimitDoc{Users: computeSpeedLimits(policies, usage, ipMap)}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// loadSpeedLimitPolicies reads the limited inbounds and the clients they cover.
//
// The WHERE clause can no longer do the filtering on its own. A rate is a column, but a
// client's IP cap lives INSIDE the settings JSON, so "does any client on this inbound
// have a cap" is not a question SQL can answer here: every enabled inbound has to be
// fetched and, unless its protocol rules a cap out anyway, unmarshalled. Disabled
// inbounds stay excluded because they pass no traffic to shape.
//
// What is preserved is the expensive half. A policy that contributes nothing is dropped
// right here rather than later, so an operator using neither feature still costs one
// indexed query per tick, and never the client_traffics scan plus the email->IP index
// rebuild that WriteSpeedLimits gates on this returning something.
func loadSpeedLimitPolicies() []speedLimitPolicy {
	db := database.GetDB()
	if db == nil {
		return nil
	}
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).
		Where("enable = ?", true).
		Find(&inbounds).Error
	if err != nil {
		logger.Warning("speed limit: load inbounds failed:", err)
		return nil
	}

	// Decoded locally, and to the two fields used, rather than through
	// InboundService.GetClients: every protocol stores its accounts under settings.clients
	// with an email, so this needs no per-protocol knowledge and pulls in no service.
	type clientEntry struct {
		Email   string `json:"email"`
		LimitIP int    `json:"limitIp"`
	}
	type settingsJSON struct {
		Clients []clientEntry `json:"clients"`
	}

	policies := make([]speedLimitPolicy, 0, len(inbounds))
	for _, inbound := range inbounds {
		coreIPCap := ipLimitEnforcedInCore(inbound)
		if !inbound.SpeedLimitEnable && !coreIPCap {
			// A VPN/ssh/mtproto inbound with no speed limit can contribute nothing, and
			// its blob is the one worth not parsing: those are the inbounds with a client
			// per device.
			continue
		}
		var settings settingsJSON
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		clients := make([]speedLimitClient, 0, len(settings.Clients))
		// The inbound's own default caps every client on it, so it arms the policy by
		// itself: nobody needs an override for this inbound to contribute one.
		capped := coreIPCap && inbound.IPLimit > 0
		for _, c := range settings.Clients {
			if strings.TrimSpace(c.Email) == "" {
				continue
			}
			// The email is used verbatim, NOT trimmed or folded: it has to match the key
			// BuildVpnEmailToIPMap and client_traffics use, and those are the stored
			// string. Normalization belongs on write (see normalizeClientEmails), not here.
			clients = append(clients, speedLimitClient{email: c.Email, ipLimit: c.LimitIP})
			if c.LimitIP > 0 {
				capped = true
			}
		}
		if !inbound.SpeedLimitEnable && !capped {
			continue // native inbound, but nobody on it is capped
		}
		policies = append(policies, speedLimitPolicy{inbound: inbound, clients: clients})
	}
	return policies
}

// loadSpeedLimitUsage returns cumulative up+down per email.
//
// This is the same counter the quota enforcer reads, so "Limit After" and totalGB
// measure the same bytes, including the traffic multiplier's weighting.
func loadSpeedLimitUsage() map[string]int64 {
	usage := make(map[string]int64)
	db := database.GetDB()
	if db == nil {
		return usage
	}
	var rows []xray.ClientTraffic
	err := db.Model(xray.ClientTraffic{}).Select("email", "up", "down").Find(&rows).Error
	if err != nil {
		logger.Warning("speed limit: load usage failed:", err)
		return usage
	}
	for _, r := range rows {
		usage[r.Email] = r.Up + r.Down
	}
	return usage
}

// WriteSpeedLimits recomputes every account's effective rate and IP cap and republishes
// the sidecar. Safe to call on every traffic tick.
//
// Write ONLY on change. The core watches this file's mtime, and a write bumps mtime
// whether or not the bytes differ, so an unconditional write would make it reload every
// 10s forever and would defeat the deterministic ordering above, which exists precisely
// so the common (nothing changed) tick is byte-identical. MTProto's config writer hit
// exactly this and documents it at generateServerConfig.
//
// The write is atomic (temp + rename) because the reader is a live process polling the
// path: a plain overwrite lets it catch a half-written document and parse-fail, which
// on a rate table means either no limits or stale ones until the next change.
func WriteSpeedLimits() {
	// Consume the dirty mark BEFORE reading the DB, never after. A config write that
	// lands while this pass is running must leave the flag set so the NEXT tick picks it
	// up: clearing at the end would swallow that write and strand the change until some
	// unrelated edit happened to re-arm the flag, which is the exact class of bug this
	// mechanism exists to fix. The cost of the other ordering is only a redundant pass,
	// and a redundant pass writes nothing (the compare below).
	//
	// Clearing here is also what keeps the republish cron off a busy box's back: the
	// traffic tick calls this unconditionally, so it satisfies whatever the tick's own
	// AddTraffic marked, and WriteSpeedLimitsIfDirty then finds nothing to do.
	speedLimitsDirty.Store(false)

	policies := loadSpeedLimitPolicies()
	var usage map[string]int64
	var ipMap map[string][]string
	// With nothing limited anywhere, the document is empty whatever the usage and
	// addresses are, so neither is loaded. That keeps the feature's cost on an operator
	// who uses neither limiter (the common case) to the one query loadSpeedLimitPolicies
	// already ran, instead of a full client_traffics scan plus an email->IP index rebuild
	// on every tick.
	if len(policies) > 0 {
		usage = loadSpeedLimitUsage()
		ipMap = BuildVpnEmailToIPMap()
	}
	data, err := speedLimitDocument(policies, usage, ipMap)
	if err != nil {
		logger.Warning("speed limit: marshal failed:", err)
		return
	}
	path := xray.GetSpeedLimitPath()
	if old, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(old, data) {
		return
	}
	// 0600: the file names every limited account. Nothing but the panel writes it and
	// nothing but Xray (running as the same user) reads it.
	if err := backend.WriteFileAtomic(path, data, 0o600); err != nil {
		logger.Warning("speed limit: write", path, "failed:", err)
	}
}

// The sidecar has TWO independent inputs and used to be wired to only one of them.
//
// Usage moves it (a "Limit After" threshold arms itself as bytes accumulate) and CONFIG
// moves it (an operator sets an IP limit, a rate, a strategy). Only the usage half had a
// hook: WriteSpeedLimits ran from the traffic tick, which early-returns on a tick that
// carried no bytes. So on an idle box a limit changed in the panel reached the core only
// when somebody happened to generate traffic. Measured: ipLimit 1 -> 0 via the API, the
// panel reported success, and minutes later the core was still enforcing 1; one download
// made the next tick republish and the change took effect at once. An account that had
// never used the box was worse: its limit had no first tick to wait for.
//
// The config half is therefore hooked HERE, at the table the config lives in, and the
// republish is a separate cron (web.go) rather than anything on the restart path. Nothing
// in the xray.Config graph changes when a rate does, and a restart would drop every live
// connection on the box, which is the whole reason the sidecar exists.
var speedLimitsDirty atomic.Bool

// MarkSpeedLimitsDirty records that the published limits may no longer match the DB.
//
// Must stay this cheap. It runs from a GORM callback on EVERY write to the inbounds
// table, which includes the traffic job's own per-tick counter updates, so it may never
// touch the DB, the file, or a lock.
func MarkSpeedLimitsDirty() {
	speedLimitsDirty.Store(true)
}

// WriteSpeedLimitsIfDirty republishes the sidecar only if something changed since the
// last pass. This is the republish cron's entry point.
//
// The gate is the whole point: WriteSpeedLimits reads every enabled inbound and parses
// the settings blob of each one that could carry a limit, and a blob holds every client
// on the inbound. That is fine at the traffic tick's 10s, but running it unconditionally
// at the 1s the config half needs (an operator watching the UI should not wait) would be
// a real cost regression on an inbound with thousands of clients. An unchanged second
// costs one atomic load instead.
func WriteSpeedLimitsIfDirty() {
	if !speedLimitsDirty.Load() {
		return
	}
	WriteSpeedLimits()
}

// inboundsTable is the table every published limit is derived from: the rate/cap/strategy
// columns, the per-client limitIp overrides inside the settings blob, and the enable flag
// that decides whether the inbound contributes at all.
const inboundsTable = "inbounds"

// RegisterSpeedLimitInvalidation arms the dirty flag on every write to the inbounds
// table, and marks the limits dirty once so the first tick after startup republishes.
//
// A GORM callback, NOT a call at each edit site, and specifically not one hung off
// SetToNeedRestart. Hanging it there is the obvious move and it does not work: the panel
// calls SetToNeedRestart only in an `else if needRestart` branch, and the two paths that
// matter both miss it. A native inbound whose live del/add API call SUCCEEDS returns
// needRestart=false (see InboundService.UpdateInbound), which is exactly the measured
// repro; and a VPN inbound takes the on<Proto>Changed branch instead, so it never reaches
// the else at all. "Wanted a restart" is a proxy for "config changed" that is false
// precisely where this bug lives.
//
// The 30-odd SetToNeedRestart sites are the other option the research offered, and they
// are a hand-maintained list of the same shape this codebase has already been bitten by.
// A callback on the table cannot be forgotten by a future edit path: to change a
// published limit you must write this table, and every such write (panel, tgbot, LDAP
// sync, bulk ops) goes through GORM.
//
// The signal is deliberately COARSE: it fires for writes that cannot change a limit
// (the traffic job's up/down counters) and for statements a transaction later rolls back.
// Both are safe and cheap by design. A false positive costs one recompute that the
// compare-then-write in WriteSpeedLimits turns into no write at all, while a false
// negative is the bug. When in doubt, mark.
func RegisterSpeedLimitInvalidation() {
	db := database.GetDB()
	if db == nil {
		logger.Warning("speed limit: no database; config changes will not reach the core")
		return
	}
	mark := func(tx *gorm.DB) {
		// Statement.Table is the parsed destination table. A raw db.Exec leaves it empty
		// and so goes unnoticed: the only raw writes to inbounds are the one-shot startup
		// migrations, which touch all_time (no limit reads it) and in any case run before
		// the startup republish below.
		if tx.Statement != nil && tx.Statement.Table == inboundsTable {
			MarkSpeedLimitsDirty()
		}
	}
	// All three write kinds, because all three change what is published: create (a new
	// capped inbound), update (the measured repro, and every client-level limitIp edit,
	// which rewrites the settings blob), delete (an inbound's clients stop being limited
	// and must leave the file, or the core keeps capping accounts that no longer exist).
	// Registration failures are not fatal but do mean the config half is unhooked again,
	// so they are logged rather than left for an operator to discover as "the limit I set
	// does nothing".
	//
	// Replace, not Register, so this is idempotent: the panel can re-Start() a server over
	// the SAME gorm handle (a panel restart that does not re-exec), and Register would
	// then log a "duplicated callback" warning for a hook that is merely being re-armed.
	// Both dedupe to the last handler, so only the noise differs.
	//
	// gorm's own processor/callback types are unexported, so these cannot be looped over.
	if err := db.Callback().Create().After("gorm:create").Replace("speedlimit:mark_dirty_create", mark); err != nil {
		logger.Warning("speed limit: cannot watch inbound creates; config changes may not reach the core:", err)
	}
	if err := db.Callback().Update().After("gorm:update").Replace("speedlimit:mark_dirty_update", mark); err != nil {
		logger.Warning("speed limit: cannot watch inbound updates; config changes may not reach the core:", err)
	}
	if err := db.Callback().Delete().After("gorm:delete").Replace("speedlimit:mark_dirty_delete", mark); err != nil {
		logger.Warning("speed limit: cannot watch inbound deletes; config changes may not reach the core:", err)
	}
	// Republish once at startup. The sidecar is a file that outlives the process, so it
	// can disagree with the DB the moment we come up: a restored backup, a hand-edited
	// row, or simply a panel that was down when the file was last written. One recompute
	// per start settles that, and writes nothing when the file already agrees.
	MarkSpeedLimitsDirty()
}
