package sub

import (
	"errors"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/xray"
)

// One account is now served on SEVERAL inbounds at once: one email, one quota, one
// expiry, N memberships. Everything in this file exists because the subscription
// layer was written when that was impossible, so reads that were correct while an
// account meant a single inbound are wrong under it.
//
//   - client_traffics.Email is unique PANEL-WIDE, so an account served on three
//     inbounds has exactly ONE row, naming exactly one of them. The per-inbound
//     lookup answers with a ZERO VALUE for the other two.
//   - the header aggregation then folded those zeros in, and its rules are "any
//     member with total 0 makes the subscription unlimited" and "members whose
//     expiry disagrees means no expiry". Two zeros are therefore enough to turn a
//     100GB, 30-day account into "∞, never expires" in the client, while the
//     account really does expire and really does stop working, with nothing
//     anywhere saying why.
//   - genRemark reads the same per-inbound row for its Show Info suffix, so the one
//     membership that happened to own the row showed remaining traffic and days
//     and the others showed none, and a disabled account got its ⛔️N/A marker on
//     one node out of three.
//
// The fix is to resolve the identity ONCE per response and have every membership
// read that, which is what subScope does. It is gated on the accounts backfill
// having completed: before then settings.clients is the only truth, the accounts
// table may be empty or partial, and the legacy per-inbound path stays in charge.

// subScope is the per-RESPONSE state one subscription is rendered with.
//
// It is deliberately NOT kept on the shared SubService. The router builds exactly
// one SubService at start-up and every request is served by it (GetSubs already
// writes the caller's host onto that shared instance, so two subscribers fetching
// at once can be handed each other's address; SubService.forResponse closes that
// too). The state here is maps, and a concurrent map write panics the whole process
// rather than merely producing a wrong address, so it must never be shared.
type subScope struct {
	accountService service.AccountService

	// migrated is read once per response. AccountsMigrated hits the settings table
	// and the answer cannot change mid-response.
	migrated bool

	// accounts caches the account row per identity, with a nil value meaning "this
	// email has no account", which is the ordinary state of an unmigrated panel.
	accounts map[string]*model.Account

	// traffics caches the account-wide traffic view per identity, so the one
	// client_traffics row is read once however many memberships ask for it.
	traffics map[string]identityTraffic

	// names is every node name already handed out in this response. See uniqueName.
	names map[string]bool
}

// identityTraffic is a cached answer, including the negative one.
type identityTraffic struct {
	traffic xray.ClientTraffic
	ok      bool
}

func newSubScope() *subScope {
	scope := &subScope{
		accounts: map[string]*model.Account{},
		traffics: map[string]identityTraffic{},
		names:    map[string]bool{},
	}
	scope.migrated = scope.accountService.AccountsMigrated()
	return scope
}

// identityKey normalizes an email to the identity the accounts layer compares on.
// It mirrors service.accountKey, which is unexported; the two have to agree, or an
// account whose email differs only in case or padding looks like a different
// account here and silently falls back to the legacy per-inbound numbers.
func identityKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// account returns the account behind an email, or nil when there is none (or when
// the backfill has not completed, which is the same thing as far as every reader
// here is concerned).
func (sc *subScope) account(email string) *model.Account {
	if sc == nil || !sc.migrated {
		return nil
	}
	key := identityKey(email)
	if key == "" {
		return nil
	}
	if account, cached := sc.accounts[key]; cached {
		return account
	}
	account, err := sc.accountService.GetAccountByEmail(email)
	if err != nil {
		// A failed read must not become "unlimited": leaving it nil falls back to
		// the per-inbound row, which is at worst what this panel reported before.
		logger.Error("SubService - account lookup for", email, ":", err)
		account = nil
	}
	sc.accounts[key] = account
	return account
}

// traffic is the account-wide view of one identity: quota and expiry from the
// ACCOUNT (one value, however many inbounds serve it) and usage from its single
// client_traffics row. ok is false when the email has no account, and the caller
// then keeps reading the inbound's own preloaded row.
func (sc *subScope) traffic(email string) (xray.ClientTraffic, bool) {
	if sc == nil {
		return xray.ClientTraffic{}, false
	}
	key := identityKey(email)
	if cached, ok := sc.traffics[key]; ok {
		return cached.traffic, cached.ok
	}

	account := sc.account(email)
	if account == nil {
		sc.traffics[key] = identityTraffic{}
		return xray.ClientTraffic{}, false
	}

	row, counted := accountTrafficRow(key)
	if !counted {
		// Never counted: no traffic row exists yet. Usage is zero and the enable
		// flag is the account's own, so a brand-new but disabled account still shows
		// its ⛔️N/A marker instead of looking like a working node.
		row = xray.ClientTraffic{Enable: account.Enable}
	} else {
		// Both flags matter and they legitimately disagree for a while: the account
		// carries the operator's intent while the traffic row is what the
		// enforcement job flipped when the quota ran out. Either being false means
		// the account cannot be used right now.
		row.Enable = row.Enable && account.Enable
	}
	row.Total = account.TotalGB
	row.ExpiryTime = account.ExpiryTime

	sc.traffics[key] = identityTraffic{traffic: row, ok: true}
	return row, true
}

// accountTrafficRow reads the ONE client_traffics row an identity has.
//
// It is a read by email rather than off inbound.ClientStats on purpose: the row
// names whichever inbound the account was created on, which is an accident, so
// every OTHER membership finds nothing in its own preload. Reading it here is also
// what keeps the usage visible when that one inbound is disabled, since
// getInboundsBySubId drops disabled inbounds from the response entirely.
func accountTrafficRow(key string) (xray.ClientTraffic, bool) {
	var row xray.ClientTraffic
	// Matched with LOWER(TRIM()) rather than on the raw column because the account
	// was matched that way too, and a row whose email differs only in case would
	// otherwise report zero usage against a real quota. The table holds one row per
	// account and a subscription is polled hourly at most, so the unindexed scan is
	// not worth carrying a second column to avoid.
	err := database.GetDB().Where("LOWER(TRIM(email)) = ?", key).First(&row).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("SubService - client traffic lookup for", key, ":", err)
		}
		return xray.ClientTraffic{}, false
	}
	return row, true
}

// uniqueName keeps the node names within ONE response distinct.
//
// A subscription client keys its nodes BY NAME: two entries sharing a name are not
// two servers, the later one replaces the earlier one. That was unreachable while
// an account lived on one inbound and is routine now that one is served on several,
// because genRemark composes the inbound remark, the email and a per-protocol
// extra: two memberships whose inbound remarks are equal (or both empty) produce
// byte-identical names, and the subscriber quietly ends up with fewer servers than
// they are paying for.
//
// Only an ALREADY-TAKEN name is ever rewritten, never the first one to claim it,
// and that is what keeps existing subscriptions intact on upgrade: a name can only
// change if it was a duplicate, and a duplicate was a node the client was throwing
// away anyway. An account on a single inbound cannot be touched at all, whatever
// its remark is, which is why an empty remark is not by itself a trigger here.
func (sc *subScope) uniqueName(name string, inbound *model.Inbound, separator string) string {
	if sc == nil || name == "" {
		return name
	}
	if !sc.names[name] {
		sc.names[name] = true
		return name
	}

	// The inbound tag is the distinguisher of choice: it is unique per inbound (a
	// UNIQUE column, and Xray refuses a config with two identical tags anyway) and
	// it is a value the operator can look up, unlike a bare row id. The id stands in
	// for an inbound with no tag, and the counter after it covers the remaining
	// case, since ONE inbound emits several nodes when external proxies are
	// configured and those can share a remark too.
	base := name
	if tag := strings.TrimSpace(inbound.Tag); tag != "" {
		base += separator + tag
	} else {
		base += separator + "#" + strconv.Itoa(inbound.Id)
	}
	candidate := base
	for i := 2; sc.names[candidate]; i++ {
		candidate = base + separator + strconv.Itoa(i)
	}
	sc.names[candidate] = true
	return candidate
}

// -----------------------------------------------------------------------------
// Subscription-Userinfo aggregation
// -----------------------------------------------------------------------------

// quotaFold is the aggregation this endpoint has always done over the entries of
// one subscription, kept verbatim so a panel serving several accounts under one
// subId keeps reporting exactly what it reported before:
//
//   - upload and download add up;
//   - total adds up UNLESS some entry is unlimited (0), which makes the whole
//     subscription unlimited;
//   - expiry survives only if every entry agrees on it, and only if it is a real
//     expiry: a negative value encodes a not-yet-started account and has always
//     been reported here as "no expiry".
//
// The rules are order independent (total collapses to 0 the moment any entry is 0
// and never recovers; expiry collapses the moment any entry disagrees), which is
// what lets the aggregation below fold per identity first and then across
// identities without changing a single legacy answer.
type quotaFold struct {
	traffic xray.ClientTraffic
	seeded  bool
}

func (f *quotaFold) add(t xray.ClientTraffic) {
	if !f.seeded {
		f.seeded = true
		f.traffic.Up = t.Up
		f.traffic.Down = t.Down
		f.traffic.Total = t.Total
		if t.ExpiryTime > 0 {
			f.traffic.ExpiryTime = t.ExpiryTime
		}
		return
	}
	f.traffic.Up += t.Up
	f.traffic.Down += t.Down
	if f.traffic.Total == 0 || t.Total == 0 {
		f.traffic.Total = 0
	} else {
		f.traffic.Total += t.Total
	}
	if t.ExpiryTime != f.traffic.ExpiryTime {
		f.traffic.ExpiryTime = 0
	}
}

// subUsage accumulates what the Subscription-Userinfo header and the subscriber
// page report, taking one entry per (inbound, client) pair the response covers.
//
// It folds PER IDENTITY first. That is the whole point: an account on three
// inbounds contributes three entries, and summing them would either multiply its
// quota by three or, once the two members holding no traffic row contribute their
// zeros, collapse it to unlimited. Distinct identities under one subId still fold
// together exactly as before.
type subUsage struct {
	order   []string
	entries map[string]*usageEntry

	// lastOnline is the most recent one seen, which the subscriber page shows.
	lastOnline int64
}

type usageEntry struct {
	fold quotaFold
	// counted marks an account-backed identity as already taken. Every membership
	// resolves to the SAME authoritative row, so the first one is the whole answer
	// and folding the rest in would multiply both the quota and the usage.
	counted bool
}

func newSubUsage() *subUsage {
	return &subUsage{entries: map[string]*usageEntry{}}
}

// add records one membership's contribution. accountBacked says the row came from
// the accounts layer rather than from this inbound's own preload.
func (u *subUsage) add(email string, traffic xray.ClientTraffic, accountBacked bool) {
	if traffic.LastOnline > u.lastOnline {
		u.lastOnline = traffic.LastOnline
	}

	key := identityKey(email)
	entry := u.entries[key]
	if entry == nil {
		entry = &usageEntry{}
		u.entries[key] = entry
		u.order = append(u.order, key)
	}
	if accountBacked {
		if entry.counted {
			return
		}
		entry.counted = true
	}
	entry.fold.add(traffic)
}

// result is the single traffic figure the header and the page are built from.
func (u *subUsage) result() xray.ClientTraffic {
	var out quotaFold
	for _, key := range u.order {
		out.add(u.entries[key].fold.traffic)
	}
	return out.traffic
}
