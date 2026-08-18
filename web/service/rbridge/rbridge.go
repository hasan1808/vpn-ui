// Package rbridge (Radius Bridge) is a light, parallel bridge that brings non-RADIUS VPN
// protocols (WireGuard, ikev2 psk/eap-tls, and future SSH/MTProto) into the RADIUS session
// model. Such protocols authenticate without a RADIUS round-trip, so they get no connect-time
// session record, no traffic counter, and no User-Limit gate from the normal path. Instead of
// each one cloning the ikev2-local reconcile/enforce/account logic, they implement the small
// Adapter interface and the Sweeper does the shared work once per traffic tick: poll live
// tunnels, enforce quota/disable plus User-Limit K and strategy by evicting, and hand the
// survivors to the existing session registry and nft accounting via the Sink.
//
// It runs ALONGSIDE the in-binary RADIUS server, which still owns the session store; it
// does not replace it. The RADIUS-authenticated protocols are unaffected.
package rbridge

import (
	"sort"
	"time"
)

// Live is one live tunnel observed by an Adapter during a tick.
type Live struct {
	Protocol  string
	InboundID int
	Email     string    // account identity; attributes usage and routing
	IP        string    // tunnel IP (10.N.x.x); the session-registry key and nft-counter key
	DeviceKey string    // opaque adapter handle used by Evict (charon SA-id, wg pubkey, ...)
	Disabled  bool      // account disabled in protocol settings; evict regardless of quota
	Since     time.Time // first-seen / arrival time; drives oldest-first eviction ordering
}

// Adapter is implemented by each non-RADIUS, sweep-reconciled protocol. Three thin methods:
// enumerate my live tunnels, report an inbound's User Limit, and kill one tunnel. All other
// control-plane work (registry merge, accounting, quota/disable and User-Limit enforcement)
// is the Sweeper's job.
type Adapter interface {
	// Protocol is the protocol id these sessions are billed and routed under (e.g. "ikev2").
	Protocol() string
	// Poll enumerates the currently live tunnels, each attributed to an inbound and account.
	Poll() ([]Live, error)
	// Limit returns the User Limit K and normalized strategy ("reject"/"accept") for one
	// inbound. k <= 0 means no limit.
	Limit(inboundID int) (k int, strategy string)
	// Evict terminates exactly one live tunnel, identified by its DeviceKey. Best-effort.
	Evict(Live) error
}

// Reconciled is one survivor handed to the Sink: whose tunnel it is and which inbound
// serves it.
//
// The inbound is carried rather than resolved on the far side because only the adapter
// knows it for certain. Every one of them already does (Live.InboundID is required),
// and the alternatives downstream are all first-match-by-lowest-id guesses that put one
// inbound's bytes on another's row.
type Reconciled struct {
	Email     string
	InboundID int
}

// Sink is the framework's write side into the existing data plane, implemented by the
// RADIUS service (session registry) together with the nft service (per-IP accounting).
// Ownership of the session store stays in RADIUS; the framework only writes through here.
type Sink interface {
	// ReconcileLocalSessions replaces the tracked sessions for one protocol with desired
	// (tunnel IP -> account + inbound): newly seen IPs gain an nft accounting counter,
	// vanished IPs are folded into client_traffics and their counter removed (mirrors
	// Acct-Stop), and the in-memory session map is updated so this tick's traffic
	// collection bills them and attributes them to the right inbound.
	ReconcileLocalSessions(protocol string, desired map[string]Reconciled)
	// DisabledEmails returns the set of accounts currently disabled: a quota/expiry hit, or
	// disabled in settings (client_traffics.enable = false).
	DisabledEmails() map[string]bool
}

// Sweeper drives all registered adapters once per traffic-collection tick.
type Sweeper struct {
	adapters []Adapter
	sink     Sink
}

// New returns a Sweeper that writes through sink.
func New(sink Sink) *Sweeper { return &Sweeper{sink: sink} }

// Register adds an adapter to be swept each tick. Register all adapters at wire-up; it is not
// safe for concurrent use with Tick.
func (sw *Sweeper) Register(a Adapter) { sw.adapters = append(sw.adapters, a) }

// Tick polls every registered adapter, enforces disable/quota and User-Limit K plus strategy
// by evicting, and hands the survivors to the sink. It is intended to run in the traffic-job
// goroutine (never an auth handler), so adapters may call their daemon CLIs synchronously.
func (sw *Sweeper) Tick() {
	if sw.sink == nil {
		return
	}
	disabled := sw.sink.DisabledEmails()
	for _, a := range sw.adapters {
		live, err := a.Poll()
		if err != nil {
			continue
		}
		desired := make(map[string]Reconciled, len(live))
		for key, group := range groupByAccount(live) {
			// 1. Disabled (in settings) or over-quota account: evict every tunnel, bill
			// nothing further.
			active := make([]Live, 0, len(group))
			for _, s := range group {
				if s.Disabled || disabled[s.Email] {
					_ = a.Evict(s)
					continue
				}
				active = append(active, s)
			}
			// 2. User Limit K + strategy.
			k, strategy := a.Limit(key.inboundID)
			survivors, evicted := TrimToLimit(active, k, strategy)
			for _, s := range evicted {
				_ = a.Evict(s)
			}
			// 3. Survivors -> session registry + accounting.
			for _, s := range survivors {
				desired[s.IP] = Reconciled{Email: s.Email, InboundID: s.InboundID}
			}
		}
		sw.sink.ReconcileLocalSessions(a.Protocol(), desired)
	}
}

// accountKey identifies one account within one inbound.
type accountKey struct {
	inboundID int
	email     string
}

// groupByAccount buckets live tunnels by (inbound, account), so the User Limit K is enforced
// per account rather than per inbound (an inbound may host several accounts). For a protocol
// with a single account per inbound this is equivalent to grouping by inbound.
func groupByAccount(live []Live) map[accountKey][]Live {
	m := make(map[accountKey][]Live)
	for _, s := range live {
		k := accountKey{inboundID: s.InboundID, email: s.Email}
		m[k] = append(m[k], s)
	}
	return m
}

// TrimToLimit enforces a per-account User Limit of k simultaneous devices with the given
// strategy, over sessions belonging to ONE account/inbound. It orders sessions oldest-first by
// Since, then: "reject" keeps the oldest k (evicting the newest over the limit), and any other
// value ("accept") keeps the newest k (evicting the oldest over the limit). k <= 0 means no
// limit. The input slice is never modified; survivors is always a fresh slice.
//
// This mirrors the pre-framework ikev2-local trim exactly (reject = keep oldest K, accept =
// keep newest K), where the ordering key was the charon SA unique-id (monotonic, lower = older);
// Since is the protocol-agnostic equivalent.
func TrimToLimit(sessions []Live, k int, strategy string) (survivors, evicted []Live) {
	if k <= 0 || len(sessions) <= k {
		return append([]Live(nil), sessions...), nil
	}
	ordered := append([]Live(nil), sessions...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Since.Before(ordered[j].Since) })
	if strategy == "reject" {
		return ordered[:k], ordered[k:]
	}
	return ordered[len(ordered)-k:], ordered[:len(ordered)-k]
}
