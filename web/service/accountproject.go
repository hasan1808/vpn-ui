package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

// The projection: rendering an Account plus one AccountInbound membership back
// into the inbound's settings.clients entry.
//
// This is the single writer of settings.clients once the accounts layer is
// authoritative, and it exists so that EVERY other consumer can stay exactly as
// it is. RADIUS, the slot allocator, all eleven daemon config writers, the
// routing translator and GetXrayConfig parse settings.clients and none of them
// learn about accounts.
//
// Two rules make this safe on a live panel:
//
//  1. OVERLAY, NEVER REBUILD. Rendering starts from the membership's stored copy
//     of the original entry and writes only the keys the account layer owns. A
//     rebuild-from-modelled-fields would silently drop wg-c/awg per-device
//     keypairs (clients[].devices[], which model.Client does not model at all)
//     and GRE pinned peers, invalidating client configs already installed on
//     users' devices.
//  2. SPLICE IN PLACE, NEVER REORDER. An entry is matched by email and updated
//     where it sits. Position is load-bearing: an account with no explicit slot
//     falls back to its INDEX in clients[] (slotOr), so reordering or compacting
//     the array moves live sessions onto other accounts' tunnel addresses.

// accountOwnedKeys are the settings-JSON keys the account row is authoritative
// for. Everything else in an entry belongs to the membership or the protocol and
// is passed through untouched.
//
// Credential keys are deliberately NOT in this list: which of them an account
// owns depends on the protocol, so they are applied by applyAccountCredential.
var accountOwnedKeys = []string{
	"email", "subId", "totalGB", "expiryTime", "enable",
	"reset", "limitIp", "tgId", "comment",
}

// applyAccountCredential writes the credential fields the given protocol keys on.
//
// The mapping mirrors buildTargetClientFromSource's switch, which is the tested
// answer to "what credential does protocol P need". Keep the two in step.
func applyAccountCredential(entry map[string]any, account *model.Account, inbound *model.Inbound) {
	switch inbound.Protocol {
	case model.VMESS:
		entry["id"] = account.UUID
		entry["security"] = account.Security
	case model.VLESS:
		entry["id"] = account.UUID
	case model.Trojan, model.ANYTLS:
		entry["password"] = account.Password
	case model.Shadowsocks:
		// The one protocol whose password is not free text. A 2022-blake3 cipher
		// takes a PSK that must be base64 of EXACTLY its key length, and the account
		// holds ONE password shared with trojan, anytls, naive and every credential
		// VPN. So an account that already had a password (a dashless uuid, say, from
		// joining an openvpn inbound) and then joined a 2022 inbound was projected
		// with a PSK that cipher cannot use: created, listed, and unable to connect
		// there, forever.
		//
		// Resolved per MEMBERSHIP, in three steps, because the account column cannot
		// be rewritten without changing the password of every other protocol on it:
		//
		//  1. an entry that already carries a password KEEPS it. That is what makes
		//     the minted PSK below stable across re-projections, and it is also what
		//     keeps the migration's round-trip check green: rendering a stored entry
		//     must reproduce it, and minting here would fail every stored ss entry
		//     and roll the whole migration back.
		//  2. otherwise the account's own password is used when it happens to be a
		//     legal PSK for this cipher, which is the shadowsocks-first case and
		//     keeps it byte-identical to before.
		//  3. otherwise a fresh PSK of the right length is minted for this membership
		//     alone.
		//
		// Non-2022 ciphers take any string, so they keep sharing the account
		// password exactly as before.
		if key := shadowsocksKeySize(inbound); key > 0 {
			if current, ok := entry["password"].(string); ok && current != "" {
				break
			}
			if validShadowsocksKey(account.Password, key) {
				entry["password"] = account.Password
			} else {
				entry["password"] = shadowsocksUserKey(inbound)
			}
			break
		}
		entry["password"] = account.Password
	case model.NAIVE:
		entry["password"] = account.Password
		// Optional Basic-auth username; empty means "use Email", which is what
		// every naive account created before the field existed relies on. Only
		// written when set, so those accounts' JSON does not grow a key.
		if account.NaiveUser != "" {
			entry["username"] = account.NaiveUser
		} else {
			delete(entry, "username")
		}
	case model.TUIC:
		// Authenticates with a uuid AND a password, and is keyed on the uuid.
		entry["id"] = account.UUID
		entry["password"] = account.Password
	case model.Hysteria, model.Hysteria2:
		entry["auth"] = account.Auth
	case model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2:
		// Username AND password. The username lives in "id"; the password is the
		// identity these are addressed by (clientIdentityKey).
		entry["id"] = account.VpnUsername
		entry["password"] = account.Password
	case model.SSH:
		// SSH's "id" is a REAL login username, compared directly against what the
		// client offers (web/service/ssh.go:371). It is emphatically not the email,
		// despite two in-tree comments that say so. Rendering the email here would
		// change the login name of every existing SSH account on first projection.
		entry["id"] = account.VpnUsername
		entry["password"] = account.Password
	case model.MTPROTO:
		// The secret is the credential; the identity is the email.
		entry["secret"] = account.Secret
		preserveOrDefaultID(entry, account.Email)
	case model.WGC, model.AWG, model.GRE, model.WireGuard:
		// Nothing reads "id" for these (verified: no .ID reference in wgc.go,
		// awg.go or gre.go), and the per-device keypairs live in the
		// passed-through part of the entry. The Xray-native wireguard inbound
		// joins them for exactly the same reason: a peer is authorised by its
		// public key, so there is no credential for an account to carry and its
		// key material is minted per membership (web/service/wgxray.go).
		preserveOrDefaultID(entry, account.Email)
	default:
		entry["id"] = account.UUID
	}
}

// preserveOrDefaultID keeps an existing "id" and only supplies one when the entry
// has none.
//
// For the four email-identity protocols (wg-c, awg, gre, mtproto) the stored "id"
// is a convention, not a guarantee. Nothing reads it, so nothing has ever forced
// it to equal the email, and on a real panel it does not: a live GRE account was
// found with id "grelive" against email "grelive@t". Overwriting it with the email
// was a gratuitous rewrite of stored data, and it broke the migration's
// round-trip check on the first live panel it met, correctly rolling the whole
// pass back.
//
// This is the projection's own overlay rule applied properly: write the fields
// the account OWNS, and pass through the ones it does not. The email is only a
// fallback for a brand new membership, which has no entry to preserve.
func preserveOrDefaultID(entry map[string]any, email string) {
	if existing, ok := entry["id"].(string); ok && existing != "" {
		return
	}
	entry["id"] = email
}

// MembershipEnabled reports whether a membership is switched on. A nil Enable is
// every row written before the column existed, and those are all serving.
func MembershipEnabled(membership *model.AccountInbound) bool {
	return membership == nil || membership.Enable == nil || *membership.Enable
}

// renderClientEntry produces the settings.clients entry for one membership,
// starting from whatever that entry already was.
//
// Takes the whole inbound rather than just its protocol because shadowsocks'
// credential depends on the inbound's cipher, not only on the protocol name.
func renderClientEntry(account *model.Account, membership *model.AccountInbound, inbound *model.Inbound, existing map[string]any) map[string]any {
	protocol := inbound.Protocol
	entry := map[string]any{}
	// Prefer the live entry we are updating; fall back to the membership's stored
	// copy (which is what a re-created inbound or a fresh projection has).
	source := existing
	if source == nil && membership.Extra != "" {
		var stored map[string]any
		if err := json.Unmarshal([]byte(membership.Extra), &stored); err == nil {
			source = stored
		}
	}
	for k, v := range source {
		entry[k] = v
	}

	entry["email"] = account.Email
	entry["subId"] = account.SubID
	entry["totalGB"] = account.TotalGB
	entry["expiryTime"] = account.ExpiryTime
	// The AND of the two questions the two flags answer: is this account live at
	// all, and is it served on THIS inbound. Both have to say yes, and either one
	// saying no has to reach the entry, because every enforcement path downstream
	// reads exactly this per-inbound field (radius.go:765, wgc.go:400, gre.go:403,
	// ssh.go:125, mtproto.go:629, and the core's own per-inbound user list).
	entry["enable"] = account.Enable && MembershipEnabled(membership)
	entry["reset"] = account.Reset
	entry["limitIp"] = account.LimitIP
	entry["tgId"] = account.TgID
	entry["comment"] = account.Comment

	// The three nullable limit overrides, projected onto the entry because THE ENTRY
	// IS WHERE EVERY READER LOOKS. The columns on the account are the editable copy;
	// none of the enforcement paths ever open that table:
	//
	//   - loadSpeedLimitPolicies (speedlimit.go) decodes speedLimitDown/speedLimitUp
	//     out of the inbound's settings blob, and publishes the resolved rate to the
	//     core through the sidecar
	//   - the four device-cap clamp sites each unmarshal userLimitOverride from the
	//     same blob: radius.go BuildVpnEmailToIPMap, openvpn.go writeClientConfigDir,
	//     ssh.go inboundLimit, mtproto.go user_max_unique_ips
	//
	// Without this the whole feature is inert: the form saves a value, the Clients
	// page reads it back and shows it, and nothing anywhere throttles or caps.
	//
	// DELETED rather than written as null when the override is nil, and that is what
	// makes the accounts migration's round-trip verification pass. It re-renders every
	// stored entry through this function and requires the result to equal what is on
	// disk; an entry that never had these keys must not grow three nulls, or check 3
	// in verifyAccountsPass reports a projection bug and rolls the migration back.
	// Client.SpeedLimitDown and friends carry omitempty for the same reason, so the
	// struct path and this map path agree about what "no override" looks like.
	setOverride := func(key string, v *int) {
		if v == nil {
			delete(entry, key)
			return
		}
		// float64 and not int: every other number in this map arrives from
		// encoding/json as a float64, and projectionRoundTrips compares the decoded
		// values. An int here would differ from its own stored form on the very next
		// read and fail a comparison that is otherwise about meaning.
		entry[key] = float64(*v)
	}
	setOverride("speedLimitDown", account.SpeedLimitDown)
	setOverride("speedLimitUp", account.SpeedLimitUp)
	setOverride("userLimitOverride", account.UserLimitOverride)

	applyAccountCredential(entry, account, inbound)

	// vless flow is an INBOUND setting that every account on the inbound inherits,
	// with the per-membership column left as an override for the rare account that
	// needs its own. Every other protocol leaves whatever the entry already had.
	//
	// The inbound-level default is what fixes a live outage: SetMemberships creates
	// memberships with Flow unset, so on a REALITY+TCP inbound the seed client had
	// vision and every account added from the Clients page afterwards projected NO
	// flow at all. Those accounts connected and then stalled, with nothing in any
	// log naming the reason.
	//
	// The value is written onto the client entry even though the core would fall
	// back to settings.flow by itself, because the four share-link generators
	// (inbound.js genLink, sub/subService.go, sub/subJsonService.go,
	// sub/subClashService.go) all read the per-client field and would otherwise emit
	// links with no flow= for a data plane that requires it.
	if protocol == model.VLESS {
		if flow := resolveVlessFlow(inbound, membership); flow != "" {
			entry["flow"] = flow
		} else {
			delete(entry, "flow")
		}
	}

	// The slot is written EXPLICITLY for every pool protocol, always. That is what
	// makes removing another account from the array safe: without a stored slot,
	// each remaining account falls back to its list index, so a compaction
	// renumbers everyone after the hole and moves their tunnel addresses.
	if slotPoolProtocol(protocol) && membership.Slot != nil {
		entry["slot"] = *membership.Slot
	}

	return entry
}

// projectAccountOntoInbound splices one account's entry into one inbound's
// settings, in place, matched by email. It returns the new settings JSON.
//
// Adding a membership appends; the caller must have allocated the slot first.
func projectAccountOntoInbound(inbound *model.Inbound, account *model.Account, membership *model.AccountInbound) (string, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &root); err != nil {
		return "", common.NewErrorf("inbound %d has unparseable settings: %v", inbound.Id, err)
	}
	if root == nil {
		root = map[string]any{}
	}
	list, _ := root["clients"].([]any)

	key := accountKey(account.Email)
	found := false
	for i, item := range list {
		existing, ok := item.(map[string]any)
		if !ok {
			continue
		}
		email, _ := existing["email"].(string)
		if accountKey(email) != key {
			continue
		}
		list[i] = renderClientEntry(account, membership, inbound, existing)
		found = true
		break
	}
	if !found {
		fresh := renderClientEntry(account, membership, inbound, nil)
		// Stamp the timestamps the legacy add path sets, so an account that joined
		// an inbound through a membership is not distinguishable in the client table
		// from one added directly (the panel renders a creation date from these, and
		// a projected entry showed none).
		//
		// Done HERE and not in renderClientEntry deliberately: that function is also
		// what the migration's round-trip verification renders through, and stamping
		// a fresh "now" there would make every entry lacking the keys fail to match
		// its stored form and roll the whole pass back. Same trap as writing a
		// derived id over a stored one; the write path may add, the render path may
		// not invent.
		now := time.Now().Unix() * 1000
		if _, has := fresh["created_at"]; !has {
			fresh["created_at"] = now
		}
		fresh["updated_at"] = now
		list = append(list, fresh)
	}

	root["clients"] = list
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// There is deliberately no per-protocol seeding on the fresh-entry path any more.
//
// It existed for exactly one case: MTProto's three transports were per-client
// booleans, and a membership created by ticking an inbound on the Clients page has no
// stored entry to inherit from, so all three decoded to false and the account was
// created, listed, and could not connect in ANY transport. Those booleans (with the
// FakeTLS domain and the device cap) now belong to the INBOUND (mtprotoSettings in
// web/service/mtproto.go), which every membership joins already configured, so there
// is nothing left for a fresh entry to be missing. The ad tag is still per-client and
// still needs no seeding, for the opposite reason: absent decodes to "no tag", which
// is the right default and the one an operator has to opt out of.
//
// If a protocol ever needs this again, note the constraint that shaped it: seeding may
// only happen HERE, on the write path, never inside renderClientEntry. That function
// is also what the migration's round-trip verification renders through, and inventing
// a field there makes every stored entry lacking it fail to match and rolls the whole
// pass back.

// removeAccountFromInbound drops an account's entry from an inbound's settings.
//
// Matching is by EMAIL, the account's stable identity, and never by credential:
// a credential can be rotated between the read and the write, and an entry that
// failed to match would be left behind as a live account nobody is billed for.
func removeAccountFromInbound(inbound *model.Inbound, email string) (string, bool, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &root); err != nil {
		return "", false, common.NewErrorf("inbound %d has unparseable settings: %v", inbound.Id, err)
	}
	if root == nil {
		return inbound.Settings, false, nil
	}
	list, _ := root["clients"].([]any)

	key := accountKey(email)
	kept := make([]any, 0, len(list))
	removed := false
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		entryEmail, _ := entry["email"].(string)
		if accountKey(entryEmail) == key {
			removed = true
			continue
		}
		kept = append(kept, item)
	}
	if !removed {
		return inbound.Settings, false, nil
	}

	root["clients"] = kept
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", false, err
	}
	return string(out), true, nil
}

// SyncInboundAccounts mirrors ONE inbound's settings.clients into the accounts
// tables: creating accounts and memberships that appeared, refreshing the ones
// that changed, and dropping memberships whose entry is gone.
//
// This is the direction OPPOSITE to the projection, and it is what lets every
// existing write path stay exactly as it is. AddInboundClient, UpdateInboundClient,
// DelInboundClient, the bulk operations, copyClients and ImportDB all keep writing
// settings.clients as their only storage; this runs after them and brings the
// accounts layer back into agreement.
//
// Keeping the mirror one-way-per-call, rather than making every caller account-aware,
// is deliberate: an account row that disagrees with settings.clients is repaired on
// the next start anyway (MigrationAccounts re-checks the counts on every boot), so a
// missed call degrades to a delay rather than to a wrong data plane.
func (s *AccountService) SyncInboundAccounts(tx *gorm.DB, inboundId int) error {
	var inbound model.Inbound
	if err := tx.Model(&model.Inbound{}).Where("id = ?", inboundId).First(&inbound).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// The inbound is gone: drop every membership pointing at it. An account
			// that is on OTHER inbounds survives, which is why the memberships go
			// rather than the accounts.
			var orphaned []int
			if derr := tx.Session(&gorm.Session{NewDB: true}).Model(&model.AccountInbound{}).
				Where("inbound_id = ?", inboundId).Distinct().Pluck("account_id", &orphaned).Error; derr != nil {
				return derr
			}
			if derr := tx.Where("inbound_id = ?", inboundId).Delete(&model.AccountInbound{}).Error; derr != nil {
				return derr
			}
			// But an account whose LAST membership was on that inbound is now
			// served by nothing, and returning here without pruning left it
			// listed forever on the Clients page and blocking revert-accounts.
			// Found by deleting a test inbound on a live panel.
			return s.pruneOrphanAccounts(tx, orphaned)
		}
		return err
	}

	clients, ok := parseSettingsClients(inbound.Settings)
	if !ok {
		// Unparseable settings: leave the accounts layer alone rather than
		// concluding this inbound has no clients and deleting every membership.
		return nil
	}

	present := map[int]bool{}
	for listIndex, entry := range clients {
		email, _ := entry["email"].(string)
		if accountKey(email) == "" {
			continue
		}
		account, err := s.upsertAccountFromEntry(tx, entry, &inbound)
		if err != nil {
			return err
		}
		if err := s.upsertMembership(tx, account.Id, &inbound, entry, listIndex); err != nil {
			return err
		}
		present[account.Id] = true
	}

	var existing []model.AccountInbound
	if err := tx.Where("inbound_id = ?", inboundId).Find(&existing).Error; err != nil {
		return err
	}
	// The accounts this sync just took OFF this inbound, and the only ones it may
	// prune. See pruneOrphanAccounts: "holds no membership" is a legitimate state
	// now, so the sweep has to be about the memberships this call removed rather
	// than about every empty account in the table.
	var dropped []int
	for _, membership := range existing {
		if present[membership.AccountId] {
			continue
		}
		if err := tx.Where("account_id = ? AND inbound_id = ?", membership.AccountId, inboundId).
			Delete(&model.AccountInbound{}).Error; err != nil {
			return err
		}
		dropped = append(dropped, membership.AccountId)
	}
	return s.pruneOrphanAccounts(tx, dropped)
}

// upsertAccountFromEntry creates or refreshes the account a client entry belongs
// to, INCLUDING the credential fields its protocol keys on.
//
// Lifting the credential is not optional here, and forgetting it is not a
// cosmetic omission: the projection renders the account back into settings.clients
// by writing entry["id"] (or "password", or "auth") FROM the account. An account
// whose credential columns were never filled therefore projects an EMPTY
// credential over the real one, which both unaddressable-ifies the client
// (clientIdentity returns "", so edit and delete stop matching it) and, for the
// native protocols, leaves a client the core cannot authenticate. It silently
// corrupts the entry the request was not even about.
//
// inbound may be nil, and that is the account with NO inbound: an entry posted by
// the Clients form for an account nothing serves yet. The protocol is then empty,
// which every credential helper below already handles as "no protocol owns a
// column here" - extractAccountCredential and overwriteAccountCredential fall
// through to their default, and liftCarriedCredentials takes every carried field
// rather than leaving the addressed protocol's own to the switch that follows it.
// That is exactly right for an account whose credentials are not yet keyed to
// anything.
func (s *AccountService) upsertAccountFromEntry(tx *gorm.DB, entry map[string]any, inbound *model.Inbound) (*model.Account, error) {
	protocol := model.Protocol("")
	inboundId := 0
	if inbound != nil {
		protocol, inboundId = inbound.Protocol, inbound.Id
	}
	email, _ := entry["email"].(string)
	key := accountKey(email)

	// The credential extractor reports divergences through a report; on this path
	// there is nobody to report to, and first-wins is the wrong rule anyway
	// (the entry just written IS the newer truth), so a scratch report is
	// discarded and the fields are taken from the entry below.
	var scratch AccountsMigrationReport
	scratchConflicts := map[conflictPair]bool{}

	var account model.Account
	err := tx.Where("LOWER(TRIM(email)) = ?", key).First(&account).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		fresh := newAccountFromEntry(entry)
		extractAccountCredential(fresh, entry, protocol, 0, &scratch, scratchConflicts)
		// The columns the entry carries for OTHER protocols. extractAccountCredential
		// reads only the addressed protocol's own fields - it is the migration's
		// reader, and a migration walks every membership in turn, so each protocol's
		// field arrives on its own pass. A CREATE has exactly one pass, so without
		// this an account first written through a vless or vmess inbound was born
		// holding nothing but a uuid: the password, VPN login name, auth and secret
		// the form had just shown the operator were dropped, and a different one was
		// minted the moment the account reached an inbound that needed it. The update
		// path below has lifted them since the accounts layer landed; only the create
		// path did not.
		liftCarriedCredentials(fresh, entry, protocol)
		if err := tx.Create(fresh).Error; err != nil {
			return nil, err
		}
		return fresh, nil
	case err != nil:
		return nil, err
	}

	updated := newAccountFromEntry(entry)
	updated.Id = account.Id
	// An entry reads enable=false for either of two reasons, and only one of them is
	// the account's. The projection renders the AND of the account flag and the
	// membership flag, so an account switched off on THIS inbound alone projects a
	// false here while being perfectly live everywhere else. Mirroring that back
	// would lower the account and take every other inbound down with it, which is
	// the exact bug the per-membership column exists to end. So a disabled
	// membership explains the false, and the account keeps what it had.
	//
	// An account with no inbound has no membership to explain anything, and
	// membershipEnabledFor answers "enabled" for a row that is not there, so the
	// posted entry decides - which is right: nothing else can.
	if !s.membershipEnabledFor(tx, account.Id, inboundId) {
		updated.Enable = account.Enable
	}
	// Credentials are per FIELD and are filled from whichever protocol supplies
	// them, so they are carried forward rather than reset: an account on vless and
	// l2tp would otherwise lose its uuid whenever the l2tp entry was the one
	// written.
	updated.UUID = account.UUID
	updated.VpnUsername = account.VpnUsername
	updated.Password = account.Password
	updated.Auth = account.Auth
	updated.Security = account.Security
	updated.Secret = account.Secret
	updated.NaiveUser = account.NaiveUser
	updated.CreatedAt = account.CreatedAt
	// subId is not a credential, but it is carried forward for the same reason and
	// only when the entry does not mention it AT ALL. A caller that omits the key
	// (any script posting a partial client) was blanking the account's subId, and
	// the next projection then wrote the blank onto every membership: one API call
	// on one inbound killed the subscription URL panel-wide. An entry that carries
	// subId="" still clears it, which is what the form does when the field is
	// emptied deliberately.
	if _, mentioned := entry["subId"]; !mentioned {
		updated.SubID = account.SubID
	}
	// The three nullable limit overrides need the SAME guard, and need it more than
	// subId does, because nearly every write reaches here without them.
	//
	// newAccountFromEntry reads an absent key as nil, and nil is a real value on these
	// columns: it means "inherit the inbound". So without this, any client write that
	// does not carry the keys silently clears the overrides - and the writes that do
	// not carry them are the COMMON ones, not the exotic ones: the enable toggle on
	// the Clients page, a bulk operation, a traffic reset, any script posting a
	// partial client. An operator would set a customer's speed limit, flip them off
	// and on again, and find the limit gone with nothing having reported a change.
	//
	// An entry that carries an explicit null still clears the override, which is what
	// the Limits tab posts when the box is emptied. Mentioned-but-null and absent have
	// to stay different, which is exactly why the test is on PRESENCE and not on the
	// decoded value.
	if _, mentioned := entry["speedLimitDown"]; !mentioned {
		updated.SpeedLimitDown = account.SpeedLimitDown
	}
	if _, mentioned := entry["speedLimitUp"]; !mentioned {
		updated.SpeedLimitUp = account.SpeedLimitUp
	}
	if _, mentioned := entry["userLimitOverride"]; !mentioned {
		updated.UserLimitOverride = account.UserLimitOverride
	}
	// Then let THIS entry set the fields its own protocol owns. An edit that
	// rotates a credential has to reach the account, or the projection would write
	// the stale one straight back over it on the next membership change.
	overwriteAccountCredential(updated, entry, protocol)
	// A 2022-blake3 shadowsocks entry can hold a PSK minted for THAT membership
	// alone (applyAccountCredential), and the account password is shared with
	// trojan, anytls, naive and every credential VPN. Lifting it would rotate all of
	// them to a key only shadowsocks can use.
	if protocol == model.Shadowsocks && shadowsocksKeySize(inbound) > 0 {
		updated.Password = account.Password
	}
	if err := tx.Save(updated).Error; err != nil {
		return nil, err
	}
	return updated, nil
}

// membershipEnabledFor answers "is this account switched on for this inbound",
// reading the stored membership. A membership that does not exist yet is enabled:
// it is about to be created by the same sync, and nothing has switched it off.
func (s *AccountService) membershipEnabledFor(tx *gorm.DB, accountId, inboundId int) bool {
	// A FRESH session, not the caller's *gorm.DB. This runs deep inside a
	// transaction that has already issued a Where, an Update and, through
	// ProjectAccount, one query per member inbound. Building the lookup on that
	// same statement risks inheriting leftover conditions, and here a WHERE that
	// silently stops matching reads as "no membership" -> enabled, which is the
	// permissive answer. pruneOrphanAccounts documents the same hazard.
	db := tx.Session(&gorm.Session{NewDB: true})
	var membership model.AccountInbound
	err := db.Where("account_id = ? AND inbound_id = ?", accountId, inboundId).
		First(&membership).Error
	if err == gorm.ErrRecordNotFound {
		// No membership row yet: the sync that is creating it is the one asking, so
		// the entry it carries IS the account's intent. Mirror it as normal.
		return true
	}
	if err != nil {
		// Cannot tell. Answer "disabled" so the caller PRESERVES the stored account
		// flag rather than letting one entry lower it. The two ways to be wrong are
		// not equal: preserving costs a stale flag until the next write, while
		// guessing "enabled" lets a single disabled entry switch the account off and
		// take every other inbound down with it.
		return false
	}
	return MembershipEnabled(&membership)
}

// overwriteAccountCredential copies the credential fields a protocol keys on from
// a client entry onto the account, unconditionally.
//
// Unlike the migration's extractAccountCredential, which keeps the FIRST value
// and records a conflict, this takes the entry's value: it runs after a write
// that the operator just made, so the entry is the newer truth and a rotated
// password must not be reverted by the account row.
func overwriteAccountCredential(account *model.Account, entry map[string]any, protocol model.Protocol) {
	str := func(k string) string { v, _ := entry[k].(string); return v }
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	liftCarriedCredentials(account, entry, protocol)

	switch protocol {
	case model.VMESS:
		set(&account.UUID, str("id"))
		set(&account.Security, str("security"))
	case model.VLESS:
		set(&account.UUID, str("id"))
	case model.Trojan, model.Shadowsocks, model.ANYTLS:
		set(&account.Password, str("password"))
	case model.NAIVE:
		set(&account.Password, str("password"))
		set(&account.NaiveUser, str("username"))
	case model.TUIC:
		set(&account.UUID, str("id"))
		set(&account.Password, str("password"))
	case model.Hysteria, model.Hysteria2:
		set(&account.Auth, str("auth"))
	case model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2, model.SSH:
		set(&account.VpnUsername, str("id"))
		set(&account.Password, str("password"))
	case model.MTPROTO:
		set(&account.Secret, str("secret"))
	case model.WGC, model.AWG, model.GRE, model.WireGuard:
		// Identity is the email and nothing reads "id"; no credential to lift.
	default:
		set(&account.UUID, str("id"))
	}
}

// liftCarriedCredentials copies the credential columns an entry carries FOR OTHER
// protocols onto the account.
//
// The Clients page edits an account, not one inbound's copy of it, so its form
// holds every credential column the account has and posts them all to whichever
// inbound the write happens to be addressed to. Without this only the addressed
// protocol's own fields survive, and every other field the operator typed is
// replaced by a server-minted random the first time the account is projected onto
// an inbound that reads it.
//
// An absent key changes nothing, so the inbound-shaped writes that predate the
// accounts layer behave exactly as before: they simply do not carry these keys.
//
// Each has its OWN key because it cannot share one: an entry's "id" is the uuid
// for vmess, the login name for l2tp and the email for wg-c, and one entry cannot
// mean all three at once.
func liftCarriedCredentials(account *model.Account, entry map[string]any, protocol model.Protocol) {
	str := func(k string) string { v, _ := entry[k].(string); return v }
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&account.VpnUsername, str("vpnUsername"))
	set(&account.Auth, str("auth"))
	set(&account.Secret, str("secret"))
	set(&account.NaiveUser, str("naiveUsername"))
	// Skipped where the ADDRESSED protocol owns the same column, because there the
	// caller's own switch is the authority and runs after this.
	if protocol != model.VMESS && protocol != model.VLESS && protocol != model.TUIC {
		set(&account.UUID, str("uuid"))
	}
	if protocol != model.L2TP && protocol != model.PPTP && protocol != model.OPENVPN &&
		protocol != model.OPENCONNECT && protocol != model.SSTP && protocol != model.IKEV2 &&
		protocol != model.SSH {
		set(&account.Password, str("password"))
	}
}

// upsertMembership creates or refreshes one (account, inbound) row.
func (s *AccountService) upsertMembership(tx *gorm.DB, accountId int, inbound *model.Inbound, entry map[string]any, listIndex int) error {
	membership := model.AccountInbound{AccountId: accountId, InboundId: inbound.Id}
	if slotPoolProtocol(inbound.Protocol) {
		slot := entrySlotOr(entry, listIndex)
		membership.Slot = &slot
	}
	if inbound.Protocol == model.VLESS {
		flow, _ := entry["flow"].(string)
		// Only a flow that DIFFERS from the inbound-level default is recorded as an
		// override. Every client entry now carries a mirror of that default, so
		// storing it verbatim would turn the mirror into an override on every
		// account, and the next change to the inbound-level picker would then be
		// ignored by all of them: renderClientEntry prefers the column. Storing ""
		// instead keeps "override" meaning what the column says it means, and heals
		// rows written before this by clearing them on the next sync.
		if flow == inboundVlessFlow(inbound) {
			flow = ""
		}
		membership.Flow = flow
	}
	if blob, err := json.Marshal(entry); err == nil {
		membership.Extra = string(blob)
	}

	var existing model.AccountInbound
	err := tx.Where("account_id = ? AND inbound_id = ?", accountId, inbound.Id).First(&existing).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		return tx.Create(&membership).Error
	case err != nil:
		return err
	}
	membership.CreatedAt = existing.CreatedAt
	return tx.Model(&model.AccountInbound{}).
		Where("account_id = ? AND inbound_id = ?", accountId, inbound.Id).
		Updates(map[string]any{
			"slot":  membership.Slot,
			"flow":  membership.Flow,
			"extra": membership.Extra,
		}).Error
}

// pruneOrphanAccounts deletes the CANDIDATE accounts that hold no membership at
// all: the mirror's way of noticing that a client entry it was tracking has gone
// from settings.clients for good.
//
// candidates is not an optimisation, it is the whole rule. "No membership" used to
// be an impossible state and so was proof the account was a leftover; an account
// may now be deliberately left on no inbound at all (see ApplyMemberships), and a
// panel-wide sweep on every sync of every inbound would delete exactly those
// accounts, minutes after an operator created them, with nothing reporting it.
// So the sweep is scoped to the accounts whose membership the CALLER just removed,
// which is the only population it was ever meant to be about: the deliberate case
// removes its rows through SetMemberships, so it is never in this list.
//
// An empty list prunes nothing, deliberately: "I removed no memberships" must not
// read as "consider every account".
//
// Resolved in two explicit steps rather than as a NOT IN sub-select built from
// the same *gorm.DB. That form reuses the caller's statement, and when this runs
// straight after a Delete on that same tx (the deleted-inbound path) the
// leftover statement state poisons the sub-select: it matched nothing, so EVERY
// account was treated as an orphan and accounts still serving other inbounds
// were deleted. Two queries, no shared statement, no ambiguity.
func (s *AccountService) pruneOrphanAccounts(tx *gorm.DB, candidates []int) error {
	if len(candidates) == 0 {
		return nil
	}
	var live []int
	if err := tx.Session(&gorm.Session{NewDB: true}).
		Model(&model.AccountInbound{}).
		Where("account_id IN ?", candidates).
		Distinct().Pluck("account_id", &live).Error; err != nil {
		return err
	}
	stillServed := make(map[int]bool, len(live))
	for _, id := range live {
		stillServed[id] = true
	}
	orphans := make([]int, 0, len(candidates))
	for _, id := range candidates {
		if !stillServed[id] {
			orphans = append(orphans, id)
		}
	}
	if len(orphans) == 0 {
		return nil
	}
	return tx.Session(&gorm.Session{NewDB: true}).
		Where("id IN ?", orphans).Delete(&model.Account{}).Error
}

// inboundVlessFlow is the inbound-level vless flow, which every account served on
// that inbound inherits unless its membership carries an override.
//
// The udp443 spelling is folded down to plain vision. xray-core accepts exactly ""
// and "xtls-rprx-vision" and refuses everything else, and at settings level a
// refusal takes the WHOLE config down rather than one client, so a legacy value
// lifted out of an old inbound must not be handed back verbatim. web/service/xray.go
// already applies the same fold to client entries on the way to the core; this is
// that rule one level up. The panel only ever writes the two accepted values, so
// this covers a hand-edited settings blob.
//
// Reading it out of the settings blob rather than off a struct field is deliberate:
// nothing in Go needs to write it, and adding a field would mean teaching every
// path that round-trips an inbound about a key that only the form and the core care
// about. shadowsocksKeySize below parses the same blob the same way.
func inboundVlessFlow(inbound *model.Inbound) string {
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return ""
	}
	flow, _ := settings["flow"].(string)
	if flow == "" {
		return ""
	}
	// The transport gate lives HERE, on the inbound-level default, and deliberately
	// not on the resolved answer. See resolveVlessFlow for why that distinction is
	// load-bearing.
	//
	// xtls-rprx-vision rides raw TCP under tls or reality and nothing else, which is
	// the rule the form's canEnableTlsFlow() applies before it will even show the
	// picker. The CORE does not enforce it: it validates the flow string and never
	// asks what stream it is riding, so a vless inbound carrying vision over ws or
	// grpc is accepted, comes up, and then stalls every account on it with nothing in
	// any log naming the reason. The browser model clears this case on load, so the
	// panel cannot produce it; this is for the blob that never went through a browser
	// at all - an imported database, a hand-edited settings field, a direct API POST.
	//
	// Gating the DEFAULT is what earns its keep, because the default is mirrored onto
	// every account on the inbound: ungated, one stray value in a stored blob turns
	// one broken account into all of them.
	if !vlessFlowFitsStream(inbound.StreamSettings) {
		return ""
	}
	if flow == "xtls-rprx-vision-udp443" {
		return "xtls-rprx-vision"
	}
	return flow
}

// resolveVlessFlow is the flow ONE membership's client entry should end up carrying,
// and it is the only thing that should ever decide that. inboundVlessFlow above is
// the inbound's DECLARED value and is not the answer on its own.
//
// A per-membership override is taken AS STORED, and is deliberately not put through
// the transport gate that inboundVlessFlow applies to the inbound's own value.
//
// That asymmetry is not an oversight, and it was wrong the other way round once. The
// gate used to sit here, on the resolved answer, on the reasoning that an override
// would otherwise walk straight past it. What that missed is that this function is
// not only consulted when writing something new: the accounts migration re-renders
// every stored client entry through it and REQUIRES the result to equal what is
// already on disk (verifyAccountsPass, check 3). Gating the override made the
// projection delete a flow that a stored entry legitimately carried, the round-trip
// verification correctly reported that as a projection bug, and the ENTIRE accounts
// migration rolled back - on any panel holding a vless inbound whose streamSettings
// do not parse as tcp plus tls or reality, which includes one with no streamSettings
// at all. Aborting a whole migration is far worse than the case it was defending.
//
// Nothing is lost by trusting the override. A stored per-membership flow on a
// transport that cannot carry it is broken for that ONE account and was already
// broken before any of this; leaving it alone is the status quo, not a new failure.
// The value that gets MIRRORED ONTO EVERY ACCOUNT is the inbound's, and that one is
// gated, which is where the 1-becomes-N risk actually lives.
//
// The udp443 fold IS repeated here, because an override column can hold the legacy
// spelling too and it reaches the core by a different path from the inbound default.
// A fold is safe where the gate was not: it rewrites a value the core would refuse
// into the one it accepts, which is what web/service/xray.go already does to the same
// key on the way out, so the round trip still agrees with what is stored.
func resolveVlessFlow(inbound *model.Inbound, membership *model.AccountInbound) string {
	flow := membership.Flow
	if flow == "" {
		flow = inboundVlessFlow(inbound)
	}
	if flow == "xtls-rprx-vision-udp443" {
		return "xtls-rprx-vision"
	}
	return flow
}

// vlessFlowFitsStream reports whether an inbound's transport can carry a vless flow.
//
// Absent or unparseable stream settings answer NO. That is the safe direction: the
// only thing this gates is whether a flow is projected onto every account, and
// declining to project one costs a working inbound nothing that the operator cannot
// restore from the form, while projecting a wrong one silently breaks every account
// served by that inbound.
func vlessFlowFitsStream(streamSettings string) bool {
	var stream map[string]any
	if err := json.Unmarshal([]byte(streamSettings), &stream); err != nil {
		return false
	}
	network, _ := stream["network"].(string)
	security, _ := stream["security"].(string)
	return network == "tcp" && (security == "tls" || security == "reality")
}

// shadowsocksKeySize is the exact PSK length the inbound's cipher requires, in
// bytes, or 0 when the cipher takes any string.
//
// Only the 2022-blake3 family constrains it; every legacy method is happy with the
// dashless uuid the other password protocols share.
func shadowsocksKeySize(inbound *model.Inbound) int {
	method := ""
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err == nil {
		method, _ = settings["method"].(string)
	}
	return shadowsocksMethodKeySize(method)
}

// shadowsocksMethodKeySize is the same answer for a named cipher, so a caller
// holding a per-CLIENT method (multi-user shadowsocks lets an account carry its own,
// and the inbound-level one is only the default) can ask about that instead.
func shadowsocksMethodKeySize(method string) int {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	return 0
}

// validShadowsocksKey reports whether a password is a legal PSK for a cipher of
// the given key size: base64 decoding to EXACTLY that many bytes.
//
// The length is what matters and what the shared account password gets wrong. A
// 32-character dashless uuid is legal base64 by accident (it decodes to 24 bytes),
// so "does it decode" alone would call a broken PSK good.
func validShadowsocksKey(password string, keySize int) bool {
	if keySize <= 0 {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(password)
	return err == nil && len(raw) == keySize
}

// shadowsocksUserKey mints a per-user password valid for the inbound's cipher.
//
// An account on two shadowsocks inbounds of DIFFERENT 2022 key lengths is served
// on both: each membership keeps its own minted PSK in its own entry (see the
// Shadowsocks case in applyAccountCredential), so the single account password
// column no longer decides it.
func shadowsocksUserKey(inbound *model.Inbound) string {
	size := shadowsocksKeySize(inbound)
	if size == 0 {
		return strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand does not fail in practice; a uuid pair is still 32 bytes of
		// unpredictable material rather than something guessable.
		copy(buf, []byte(strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// ApplyMemberships puts an account on exactly inboundIds and re-projects, so
// settings.clients on every one of them agrees with the account. Returns the
// inbound ids whose settings actually changed, for the caller's reconcile fan-out.
//
// All of it runs in ONE transaction. A partial fan-out is precisely the state
// this layer exists to prevent: an account written to three inbounds and
// half-removed from a fourth is a live account nobody is billed for.
//
// A single-inbound request does not touch the membership SET, but it still
// re-projects. That is not an optimisation, it is the fix for a de-sync the
// half-way version created: the mirror below writes the edited entry INTO the
// shared account row, so a write naming one inbound already changed the account's
// quota, expiry and enable for every membership it has. Returning before the
// projection left the other memberships' stored entries reading the OLD values,
// and every enforcement path reads those per-inbound entries. Measured on an
// account spanning 18 inbounds: the account row read enable=false while 17
// memberships still read enable=true, and the Clients page showed all 17 as
// serving. The change then reappeared later, when the next membership-carrying
// edit finally re-projected.
//
// So both halves of the write are applied or neither is. For a single-inbound
// account, which is nearly all of them, ProjectAccount touches that one inbound
// and this costs nothing.
//
// removable names the memberships the CALLER is allowed to drop. It is passed in
// rather than derived, because "not in the wanted set" is not sufficient
// authority to remove one: an account can be on an inbound the caller cannot
// see, and an edit that simply omitted it must not silently take the account off
// another admin's inbound. The controller resolves it by intersecting the
// account's current memberships with what the caller owns.
//
// The mirror anchor is wanted[0], the inbound whose settings the legacy write just
// changed. A caller whose anchor is NOT in the wanted set - the one write that takes
// an account off every inbound it has - has to name it, and calls
// ApplyMembershipsFrom directly.
func (s *AccountService) ApplyMemberships(email string, wanted []int, removable []int, explicit bool) ([]int, error) {
	anchor := 0
	if len(wanted) > 0 {
		anchor = wanted[0]
	}
	return s.ApplyMembershipsFrom(email, anchor, wanted, removable, explicit)
}

// ApplyMembershipsFrom is ApplyMemberships with the mirror anchor named separately:
// the inbound whose settings.clients the caller just wrote, which is where the
// account-wide fields of this edit (quota, expiry, comment, the limit overrides)
// are still sitting when this runs. It is normally the first of the wanted ids and
// has to be passed in when it is not one of them at all.
//
// An anchor of 0 means "no inbound was written", which is the create-an-account-on
// -nothing case: there is no settings blob to mirror and the account row is already
// the truth.
//
// EMPTYING THE SET. An account may deliberately be left on no inbound: created that
// way, or reduced to it by unticking its last membership. What survives is the whole
// point - the accounts row, its credentials and its client_traffics row all stay, so
// the customer's uuid, password and usage history are still there when an inbound is
// attached again later. That is the difference between this and a delete.
//
// wanted may therefore be empty, but ONLY when the caller said so. The guard this
// replaced refused every empty set, and it was protecting the IMPLICIT path: a write
// that names no memberships at all (the Telegram bot, a script posting one client,
// any caller predating the accounts layer) means "leave the SET alone and just
// re-project", and reading its silence as "take this account off everything" would
// unprovision a customer on every inbound serving them, from a request that never
// mentioned memberships. So the guard survives, narrowed to exactly that case:
// explicit=false with nothing wanted is still a no-op, and only a caller that
// SPOKE about memberships can empty an account.
func (s *AccountService) ApplyMembershipsFrom(email string, anchorInboundId int, wanted []int, removable []int, explicit bool) ([]int, error) {
	if email == "" {
		return nil, nil
	}
	if len(wanted) == 0 && !explicit {
		return nil, nil
	}
	var touched []int
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		// Mirror the inbound the legacy write just touched, so the account row and
		// its first membership exist before memberships are set.
		if anchorInboundId > 0 {
			if err := s.SyncInboundAccounts(tx, anchorInboundId); err != nil {
				return err
			}
		}
		account, err := s.GetAccountByEmailTx(tx, email)
		if err != nil {
			return err
		}
		if account == nil {
			// A delete path can legitimately leave no account behind (the mirror
			// prunes an account whose last membership went away), and a single-inbound
			// write has nothing further to do then. An explicit membership request
			// with no account is a real error: it named a set to apply.
			if !explicit {
				return nil
			}
			return common.NewErrorf("no account for %q after the write", email)
		}
		// The caller said nothing about memberships, so the SET is left exactly as it
		// is; only the account-wide fields it just changed are pushed back out.
		if explicit {
			// Everything the account is on that the caller may not touch stays, so an
			// edit can never remove a membership on someone else's inbound.
			keep, err := s.GetMembershipInboundIds(account.Id)
			if err != nil {
				return err
			}
			if err := s.SetMemberships(tx, account.Id, mergeKeepSet(wanted, keep, removable)); err != nil {
				return err
			}
		}
		changed, err := s.ProjectAccount(tx, account.Id)
		if err != nil {
			return err
		}
		touched = changed
		// Bring the mirror back in step with what the projection just wrote.
		for _, inboundId := range changed {
			if err := s.SyncInboundAccounts(tx, inboundId); err != nil {
				return err
			}
		}
		return nil
	})
	return touched, err
}

// SaveAccountWithoutInbound writes the account one posted client entry describes,
// with no inbound in the picture at all: the create half of "an account may exist
// on nothing", and the only edit an account in that state can be given.
//
// Everything else that writes a client is addressed to an inbound - /addClient
// splices the entry into that inbound's settings and /updateClient/:clientId matches
// it there by the identity its protocol keys on. An account on no inbound has
// neither: no settings blob carries it and no protocol gives it an identity, so
// there is nothing for those routes to be about. This is the one path that can
// write it, and it writes the two rows that hold an account when no settings blob
// does:
//
//   - the accounts row, through the same mirror the inbound-addressed writes use
//     (upsertAccountFromEntry with no inbound), so the credential columns, the
//     presence guards on subId and the three limit overrides all behave identically;
//   - the client_traffics row, which is the account's quota, expiry, enable flag and
//     usage counter panel-wide. It is created here rather than left to the first
//     membership because it IS the account as far as every enforcement path is
//     concerned, and an account whose quota exists nowhere is one that cannot be
//     billed the moment an inbound is attached.
//
// The membership set is the CALLER's next call (ApplyMembershipsFrom): this writes
// the account, that decides what serves it, and keeping them apart is what lets the
// same handler create an account on nothing and re-attach one to three inbounds.
func (s *AccountService) SaveAccountWithoutInbound(entry map[string]any) (*model.Account, error) {
	email, _ := entry["email"].(string)
	key := accountKey(email)
	if key == "" {
		return nil, common.NewError("a client needs an email")
	}
	var saved *model.Account
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		existing, err := s.GetAccountByEmailTx(tx, email)
		if err != nil {
			return err
		}
		var traffic xray.ClientTraffic
		trafficErr := tx.Where("LOWER(TRIM(email)) = ?", key).First(&traffic).Error
		if trafficErr != nil && trafficErr != gorm.ErrRecordNotFound {
			return trafficErr
		}
		hasTraffic := trafficErr == nil
		if existing == nil && hasTraffic {
			// A counter row with no account behind it means the email is spoken for by
			// something this layer cannot see - a client written straight into an
			// inbound's settings, or a row a delete left behind. Creating an account
			// over it would silently adopt that usage history and that quota.
			return common.NewErrorf("the email %q is already in use", email)
		}

		account, err := s.upsertAccountFromEntry(tx, entry, nil)
		if err != nil {
			return err
		}

		if !hasTraffic {
			// InboundId 0, and it is a truthful 0: the column is documented as the
			// account's HOME inbound, "whichever one it was created on", and this one
			// was created on none. Nothing resolves service by it (every enforcement
			// path keys on the email), and the has-many preload behind the Inbounds
			// page simply never matches it.
			traffic = xray.ClientTraffic{InboundId: 0, Email: account.Email}
		}
		// Up/Down/AllTime are deliberately untouched on an edit: they are the
		// customer's usage history, and the whole reason an account may sit on no
		// inbound rather than being deleted is that this row survives.
		traffic.Email = account.Email
		traffic.Enable = account.Enable
		traffic.Total = account.TotalGB
		traffic.ExpiryTime = account.ExpiryTime
		traffic.Reset = account.Reset
		if err := tx.Save(&traffic).Error; err != nil {
			return err
		}
		saved = account
		return nil
	})
	return saved, err
}

// DeleteAccountWithoutInbound removes an account nothing serves, with its counter
// row, and refuses one that is still on an inbound.
//
// The refusal is what keeps there being ONE destructive path for a served account:
// DelInboundClientByEmail also takes the entry out of settings.clients, drops the IP
// bindings and pulls the user out of the running core, and none of that would happen
// here. An account on no inbound has none of those to clean up, which is exactly why
// it needs its own removal - the inbound-addressed delete has no inbound to be
// addressed to.
func (s *AccountService) DeleteAccountWithoutInbound(email string) error {
	key := accountKey(email)
	if key == "" {
		return common.NewError("no email")
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		account, err := s.GetAccountByEmailTx(tx, email)
		if err != nil {
			return err
		}
		if account == nil {
			return common.NewErrorf("no account for %q", email)
		}
		var memberships int64
		if err := tx.Model(&model.AccountInbound{}).
			Where("account_id = ?", account.Id).Count(&memberships).Error; err != nil {
			return err
		}
		if memberships > 0 {
			return common.NewErrorf(
				"%q is still served on %d inbound(s); delete it from those instead",
				email, memberships)
		}
		if err := tx.Where("LOWER(TRIM(email)) = ?", key).Delete(&xray.ClientTraffic{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", account.Id).Delete(&model.Account{}).Error
	})
}

// SetMembershipEnable switches one account on or off on ONE inbound, leaving every
// other inbound serving it.
//
// Its own entry point rather than a flag on the client write, because the wire
// cannot tell the two intents apart otherwise: `enable` inside a posted client
// entry has always meant the account's own flag (that is what the bulk paths, the
// Telegram bot and the Clients form all mean by it), and reading it as
// per-membership instead would silently turn every existing caller's account-wide
// disable into a one-inbound one.
//
// Returns the inbound ids whose settings changed, for the caller's reconcile.
func (s *AccountService) SetMembershipEnable(email string, inboundId int, enable bool) ([]int, error) {
	if email == "" {
		return nil, common.NewError("no email")
	}
	var touched []int
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		account, err := s.GetAccountByEmailTx(tx, email)
		if err != nil {
			return err
		}
		if account == nil {
			return common.NewErrorf("no account for %q", email)
		}
		var membership model.AccountInbound
		if err := tx.Where("account_id = ? AND inbound_id = ?", account.Id, inboundId).
			First(&membership).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return common.NewErrorf("account %q is not on inbound %d", email, inboundId)
			}
			return err
		}
		if err := tx.Model(&model.AccountInbound{}).
			Where("account_id = ? AND inbound_id = ?", account.Id, inboundId).
			Update("enable", enable).Error; err != nil {
			return err
		}
		// Re-project the whole account rather than just this inbound. The rendered
		// entry is the AND of the account flag and the membership flag, so only this
		// one can actually change, but going through the same path as every other
		// write is what keeps there being exactly one writer of settings.clients.
		changed, err := s.ProjectAccount(tx, account.Id)
		if err != nil {
			return err
		}
		touched = changed
		for _, id := range changed {
			if err := s.SyncInboundAccounts(tx, id); err != nil {
				return err
			}
		}
		return nil
	})
	return touched, err
}

// mergeKeepSet computes the membership set to write: everything the caller asked
// for, plus every CURRENT membership the caller is not allowed to remove.
//
// The asymmetry is the point. Adding is authorized by owning the inbound being
// added (checked at the route), but removing is authorized by owning the inbound
// being removed FROM, which is a different set. An admin editing a shared
// account without ticking an inbound they cannot see must leave it alone rather
// than silently unprovision it.
func mergeKeepSet(wanted, current, removable []int) []int {
	mayRemove := make(map[int]bool, len(removable))
	for _, id := range removable {
		mayRemove[id] = true
	}
	out := make([]int, 0, len(wanted)+len(current))
	seen := make(map[int]bool, len(wanted)+len(current))
	for _, id := range wanted {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, id := range current {
		if seen[id] || mayRemove[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// SetMemberships makes an account's membership set exactly inboundIds, adding and
// removing rows as needed, then re-projects so settings.clients agrees.
//
// The credential fields must already be on the account: a new membership renders
// the credential its protocol keys on, and a blank one produces an account that
// is listed but cannot authenticate.
func (s *AccountService) SetMemberships(tx *gorm.DB, accountId int, inboundIds []int) error {
	wanted := map[int]bool{}
	for _, id := range inboundIds {
		wanted[id] = true
	}

	var existing []model.AccountInbound
	if err := tx.Where("account_id = ?", accountId).Find(&existing).Error; err != nil {
		return err
	}
	have := map[int]bool{}
	for _, m := range existing {
		have[m.InboundId] = true
		if wanted[m.InboundId] {
			continue
		}
		if err := tx.Where("account_id = ? AND inbound_id = ?", accountId, m.InboundId).
			Delete(&model.AccountInbound{}).Error; err != nil {
			return err
		}
	}

	for _, inboundId := range inboundIds {
		if have[inboundId] {
			continue
		}
		var inbound model.Inbound
		if err := tx.Where("id = ?", inboundId).First(&inbound).Error; err != nil {
			return err
		}
		// A new membership renders the credential ITS protocol keys on, and the
		// account may not hold one yet: an account that only ever existed on vless
		// has a uuid and no VPN username, so joining an l2tp inbound would project
		// an empty id and produce an account that is listed, looks fine, and can
		// never authenticate. Mint what is missing before the projection runs.
		if err := s.ensureCredentialsFor(tx, accountId, &inbound); err != nil {
			return err
		}

		membership := model.AccountInbound{AccountId: accountId, InboundId: inboundId}
		if slotPoolProtocol(inbound.Protocol) {
			// A NEW membership takes the lowest free slot in THAT inbound's pool,
			// never the account's slot elsewhere: slots are per inbound and reusing
			// one would hand this account an address another account already holds.
			slot, err := s.nextFreeSlot(tx, &inbound)
			if err != nil {
				return err
			}
			membership.Slot = &slot
		}
		if err := tx.Create(&membership).Error; err != nil {
			return err
		}
	}
	return nil
}

// ensureCredentialsFor mints any credential field a protocol needs and the
// account does not have yet, then persists it.
//
// The minting rules mirror buildTargetClientFromSource (the copyClients path),
// which is the tested answer to "what credential does protocol P need": a real
// dashed UUID where a client parses one, a dashless token elsewhere, and a
// username AND password for the six credential VPNs plus ssh, since minting only
// the username used to create accounts that RADIUS had nothing to check against.
//
// Existing fields are never overwritten. That is the point of the per-FIELD
// split: one uuid serves every vmess/vless membership and one password every
// trojan membership, so a second membership of the same family reuses the
// credential the customer already has installed.
func (s *AccountService) ensureCredentialsFor(tx *gorm.DB, accountId int, inbound *model.Inbound) error {
	var account model.Account
	if err := tx.Where("id = ?", accountId).First(&account).Error; err != nil {
		return err
	}
	protocol := inbound.Protocol

	changed := false
	need := func(dst *string, mint func() string) {
		if *dst == "" {
			*dst = mint()
			changed = true
		}
	}
	dashless := func() string { return strings.ReplaceAll(uuid.NewString(), "-", "") }
	dashed := func() string { return uuid.NewString() }

	switch protocol {
	case model.VMESS:
		need(&account.UUID, dashed)
		need(&account.Security, func() string { return "auto" })
	case model.VLESS:
		need(&account.UUID, dashed)
	case model.Trojan, model.ANYTLS, model.NAIVE:
		need(&account.Password, dashless)
	case model.Shadowsocks:
		// A 2022-blake3 cipher does not take an arbitrary string: the user PSK must
		// be base64 of EXACTLY the cipher's key length, and a dashless uuid (32 hex
		// characters, 24 bytes decoded) is refused. The account was created, listed
		// and looked fine, and could never connect. The client form has always
		// minted this correctly (RandomUtil.randomShadowsocksPassword); the
		// membership path had not.
		//
		// This only seeds the account column for a shadowsocks-FIRST account, and it
		// is no longer what decides the entry: an account that already holds a
		// password keeps it here, and applyAccountCredential mints a per-membership
		// PSK when that password cannot serve this inbound's cipher.
		need(&account.Password, func() string { return shadowsocksUserKey(inbound) })
	case model.TUIC:
		// Authenticates with a uuid AND a password, and the uuid must keep its
		// dashes: a TUIC client parses this field as a real UUID.
		need(&account.UUID, dashed)
		need(&account.Password, dashless)
	case model.Hysteria, model.Hysteria2:
		need(&account.Auth, dashless)
	case model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2, model.SSH:
		need(&account.VpnUsername, dashless)
		need(&account.Password, dashless)
	case model.MTPROTO:
		// 32 hex characters, which is exactly a dashless uuid.
		need(&account.Secret, dashless)
	case model.WGC, model.AWG, model.GRE, model.WireGuard:
		// Identity is the email; the per-device keypairs are minted by the
		// protocol's own reconcile, not here.
	default:
		need(&account.UUID, dashed)
	}

	if !changed {
		return nil
	}
	return tx.Save(&account).Error
}

// nextFreeSlot returns the lowest unused slot in an inbound's address pool.
func (s *AccountService) nextFreeSlot(tx *gorm.DB, inbound *model.Inbound) (int, error) {
	clients, ok := parseSettingsClients(inbound.Settings)
	if !ok {
		return 0, common.NewErrorf("inbound %d has unparseable settings", inbound.Id)
	}
	used := map[int]bool{}
	for listIndex, entry := range clients {
		used[entrySlotOr(entry, listIndex)] = true
	}
	for slot := 0; ; slot++ {
		if !used[slot] {
			return slot, nil
		}
	}
}

// ProjectAccount rewrites every member inbound's settings from the account, and
// removes the account from every inbound it is no longer a member of.
//
// Runs inside the caller's transaction so a partial fan-out cannot be committed:
// an account written to three inbounds and half-removed from a fourth is exactly
// the free-traffic state this layer exists to prevent.
func (s *AccountService) ProjectAccount(tx *gorm.DB, accountId int) ([]int, error) {
	var account model.Account
	if err := tx.Where("id = ?", accountId).First(&account).Error; err != nil {
		return nil, err
	}

	var memberships []model.AccountInbound
	if err := tx.Where("account_id = ?", accountId).Order("inbound_id ASC").Find(&memberships).Error; err != nil {
		return nil, err
	}

	member := make(map[int]*model.AccountInbound, len(memberships))
	for i := range memberships {
		member[memberships[i].InboundId] = &memberships[i]
	}

	// Every inbound that currently carries this email, so ex-memberships can be
	// cleaned up. A panel-wide scan rather than a diff against a remembered set:
	// the entry could have been put there by an older binary, by copyClients, or
	// by a DB import, and a leftover entry is a working account.
	var inbounds []*model.Inbound
	if err := tx.Model(&model.Inbound{}).Order("id ASC").Find(&inbounds).Error; err != nil {
		return nil, err
	}

	touched := make([]int, 0, len(memberships))
	for _, inbound := range inbounds {
		m, isMember := member[inbound.Id]
		if isMember {
			settings, err := projectAccountOntoInbound(inbound, &account, m)
			if err != nil {
				return nil, err
			}
			if settings == inbound.Settings {
				continue
			}
			if err := tx.Model(&model.Inbound{}).Where("id = ?", inbound.Id).
				Update("settings", settings).Error; err != nil {
				return nil, err
			}
			touched = append(touched, inbound.Id)
			continue
		}

		// Not a member. Only rewrite if the email is actually present, so this
		// stays a no-op for the overwhelming majority of inbounds.
		if !strings.Contains(strings.ToLower(inbound.Settings), accountKey(account.Email)) {
			continue
		}
		settings, removed, err := removeAccountFromInbound(inbound, account.Email)
		if err != nil {
			return nil, err
		}
		if !removed {
			continue
		}
		if err := tx.Model(&model.Inbound{}).Where("id = ?", inbound.Id).
			Update("settings", settings).Error; err != nil {
			return nil, err
		}
		touched = append(touched, inbound.Id)
	}

	return touched, nil
}

// -----------------------------------------------------------------------------
// Rename and removal: keeping the accounts layer in step with a settings write
// -----------------------------------------------------------------------------

// RenameAccount carries an existing account row onto a new email instead of
// leaving the old one behind.
//
// Without it a rename SPLITS the customer in two. UpdateInboundClient rewrites the
// one inbound it was posted against, and the controller then applies memberships
// under the NEW email: no account answers to that key, so a SECOND account row is
// created, and projectAccountOntoInbound matches on the new email, fails on every
// other member inbound, and APPENDS. The old email is left as a live, working,
// billable account on all of them, listed under a customer who no longer exists.
// resellerService.RenameClient already does this for the ledger; this is the same
// carry-over for the accounts layer.
//
// The settings entries move first, so the account row and the blobs are never
// briefly disagreeing about which key names the customer, and so the projection
// that follows matches in place rather than appending.
//
// Returns the inbound ids whose settings changed, for the caller's reconcile: a
// renamed account is a new RADIUS login and a new per-account routing rule, so every
// daemon serving it has to be regenerated.
func (s *AccountService) RenameAccount(oldEmail, newEmail string) ([]int, error) {
	oldKey, newKey := accountKey(oldEmail), accountKey(newEmail)
	// A case-only change still has to reach the settings (the stored spelling is what
	// the core and RADIUS carry), but it is not a change of identity, so the account
	// row already answers to it.
	if oldKey == "" || newKey == "" || oldKey == newKey {
		return nil, nil
	}

	var touched []int
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		var account model.Account
		err := tx.Where("LOWER(TRIM(email)) = ?", oldKey).First(&account).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				// Nothing mirrored under the old key. The ordinary caller's
				// SyncInboundAccounts will create the account under the new one.
				return nil
			}
			return err
		}

		// An account already holding the new key is NOT merged into and NOT deleted.
		// Both rows are live customers with their own quota, credentials and
		// memberships, and picking one silently moves the other's traffic. The
		// duplicate-email check is what is supposed to stop this reaching here, so
		// arriving is a bug worth a log line rather than a data-destroying repair.
		var clash int64
		if err := tx.Model(&model.Account{}).
			Where("LOWER(TRIM(email)) = ? AND id != ?", newKey, account.Id).
			Count(&clash).Error; err != nil {
			return err
		}
		if clash > 0 {
			logger.Warningf("RenameAccount - %q is already an account; the rename from %q was left alone rather than merging two live customers", newEmail, oldEmail)
			return nil
		}

		changed, err := renameInSettings(tx, oldKey, newEmail)
		if err != nil {
			return err
		}
		touched = changed

		return tx.Model(&model.Account{}).Where("id = ?", account.Id).
			Update("email", newEmail).Error
	})
	if err != nil {
		return nil, err
	}
	return touched, nil
}

// renameInSettings rewrites the email of every stored client entry that resolves to
// oldKey, across every inbound, leaving the rest of each entry untouched.
//
// Every inbound is scanned rather than just the account's memberships: settings.clients
// is the source of truth and the membership table is the mirror, so an entry the
// mirror does not know about is exactly the one a rename must not strand.
func renameInSettings(tx *gorm.DB, oldKey string, newEmail string) ([]int, error) {
	var inbounds []*model.Inbound
	if err := tx.Model(&model.Inbound{}).Select("id", "settings").
		Order("id ASC").Find(&inbounds).Error; err != nil {
		return nil, err
	}

	var touched []int
	for _, inbound := range inbounds {
		var root map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &root); err != nil || root == nil {
			// Not this function's blob to report on: it is renaming one account, and
			// failing the whole rename over an unrelated malformed inbound would leave
			// the customer split, which is the thing it exists to prevent.
			continue
		}
		list, _ := root["clients"].([]any)
		changed := false
		for _, item := range list {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			email, _ := entry["email"].(string)
			if accountKey(email) != oldKey {
				continue
			}
			entry["email"] = newEmail
			entry["updated_at"] = time.Now().Unix() * 1000
			changed = true
		}
		if !changed {
			continue
		}
		out, err := json.MarshalIndent(root, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := tx.Model(&model.Inbound{}).Where("id = ?", inbound.Id).
			Update("settings", string(out)).Error; err != nil {
			return nil, err
		}
		touched = append(touched, inbound.Id)
	}
	return touched, nil
}

// DropMembership takes an account off ONE inbound in the accounts layer, and is the
// mirror of a client entry being removed from that inbound's settings.
//
// A membership that outlives its settings entry is not inert: it RESURRECTS the
// client. ProjectAccount treats memberships as the source and appends the account to
// any member inbound whose blob does not carry it, so the next projection from any
// cause - an unrelated edit, a membership change, a core uninstall - puts the
// deleted customer back on the inbound they were removed from, live and serving.
//
// Called from the delete paths themselves rather than left to each caller, because
// the callers are exactly where it kept being forgotten: the LDAP sync job and the
// reseller cascade both delete clients and neither reconciles the mirror afterwards.
//
// The account row goes only when the membership removed was its LAST one, and it is
// found by accountKey rather than by an exact match, because the settings spelling
// and the accounts spelling are written by different paths.
func (s *AccountService) DropMembership(tx *gorm.DB, inboundId int, email string) error {
	key := accountKey(email)
	if tx == nil || key == "" {
		return nil
	}

	var account model.Account
	if err := tx.Where("LOWER(TRIM(email)) = ?", key).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil // nothing mirrored for this email
		}
		return err
	}

	if err := tx.Where("account_id = ? AND inbound_id = ?", account.Id, inboundId).
		Delete(&model.AccountInbound{}).Error; err != nil {
		return err
	}

	// Counted for THIS account only, not through pruneOrphanAccounts: that one reads
	// "no memberships anywhere" as "every account is an orphan" and empties the whole
	// table, which is right where it is called (straight after removing an inbound's
	// last membership) and catastrophic here, on a path that runs for every ordinary
	// client delete.
	var left int64
	if err := tx.Model(&model.AccountInbound{}).
		Where("account_id = ?", account.Id).Count(&left).Error; err != nil {
		return err
	}
	if left > 0 {
		return nil
	}
	return tx.Where("id = ?", account.Id).Delete(&model.Account{}).Error
}
