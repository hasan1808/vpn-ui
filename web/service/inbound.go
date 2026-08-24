// Package service provides business logic services for the vpn-ui web panel,
// including inbound/outbound management, user administration, settings, and Xray integration.
package service

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/util/random"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"gorm.io/gorm"
)

// InboundService provides business logic for managing Xray inbound configurations.
// It handles CRUD operations for inbounds, client management, traffic monitoring,
// and integration with the Xray API for real-time updates.
type InboundService struct {
	xrayApi xray.XrayAPI
}

type CopyClientsResult struct {
	Added   []string `json:"added"`
	Skipped []string `json:"skipped"`
	Errors  []string `json:"errors"`
}

// GetInboundsFor retrieves the inbounds an admin may see, with their client stats.
//
// A super admin sees every inbound by role. Everyone else sees exactly what has been
// granted to them: access is assigned, not inferred from who created the row, so an
// admin with no grants correctly sees nothing.
//
// A reseller is the third branch, and the difference is what makes the role a role
// rather than a permission bit: two admins granted one inbound see the same accounts
// on it, while a reseller granted that same inbound sees only the accounts it sold.
// The grant decides WHICH INBOUNDS, the ownership rows decide WHICH CLIENTS inside
// them, and both questions have to be answered here because this is the only place
// the page's payload is assembled.
//
// Takes the whole user rather than an id because the super-admin case is a different
// query, and a signature taking only an id invites callers to forget that.
func (s *InboundService) GetInboundsFor(user *model.User) ([]*model.Inbound, error) {
	if user == nil {
		return []*model.Inbound{}, nil
	}
	if user.IsSuperAdmin {
		return s.getInboundsWhere(nil)
	}
	var adminService AdminService
	ids, err := adminService.AccessibleInboundIds(user.Id)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []*model.Inbound{}, nil
	}
	inbounds, err := s.getInboundsWhere(ids)
	if err != nil {
		return nil, err
	}
	if !user.IsReseller {
		return inbounds, nil
	}
	// Fail closed, like every other ownership question in this panel: an OwnedEmails
	// that errors must not fall through to the unfiltered list, which is every
	// admin's clients on every inbound this reseller shares with them.
	var resellerService ResellerService
	owned, err := resellerService.OwnedEmails(user.Id)
	if err != nil {
		return nil, err
	}
	s.FilterInboundsForReseller(inbounds, owned)
	return inbounds, nil
}

// emptyClientSettings is what an inbound's settings become when they cannot be read
// well enough to filter: a valid blob the page renders as an inbound with no accounts.
const emptyClientSettings = `{"clients": []}`

// FilterInboundsForReseller strips every client a reseller did not create out of a
// batch of inbounds, in place.
//
// ownedEmails is ResellerService.OwnedEmails: one lower-cased key per account the
// reseller created. An empty map is a legitimate state, not a missing argument, and
// correctly empties every client list: a reseller who has sold nothing sees the
// inbounds they may sell on and no accounts at all.
func (s *InboundService) FilterInboundsForReseller(inbounds []*model.Inbound, ownedEmails map[string]bool) {
	for _, inbound := range inbounds {
		s.FilterInboundForReseller(inbound, ownedEmails)
	}
}

// FilterInboundForReseller is the single-inbound form, for the routes that hand back
// one row (/get/:id) rather than the list.
//
// BOTH halves have to go, because either one alone still leaks the account. Settings
// is what the Inbounds page parses client-side to build its table, so a client left
// there is visible down to its credentials; ClientStats is the traffic and expiry the
// same table joins onto it.
func (s *InboundService) FilterInboundForReseller(inbound *model.Inbound, ownedEmails map[string]bool) {
	if inbound == nil {
		return
	}
	inbound.ClientStats = s.FilterClientTrafficsForReseller(inbound.ClientStats, ownedEmails)
	rescopeInboundTraffic(inbound)
	filtered, err := filterSettingsClients(inbound.Settings, ownedEmails)
	if err != nil {
		// Settings we cannot parse are settings we cannot prove are safe to hand
		// over. The inbound stays visible, since the grant is real, but empty.
		logger.Warning("reseller scoping: unreadable settings on inbound", inbound.Id, ":", err)
		inbound.Settings = emptyClientSettings
		return
	}
	inbound.Settings = filtered
}

// rescopeInboundTraffic rewrites an inbound's OWN traffic counters to cover only the
// client rows left on it, and is meaningful solely after the reseller filter has run.
//
// Up/Down/AllTime on the inbound row are panel-wide: they are the sum over every
// account on the inbound, whoever sold it. The Inbounds page renders them twice, once
// per row and once as the "Total usage" / "All-time total usage" band above the table,
// so a reseller handed the raw values reads the whole panel's traffic as their own.
// Filtering ClientStats does not touch them, which is why the band stayed wrong long
// after the client table was correctly scoped.
//
// Safe to write because a reseller can never send these back: the role holds no
// PermEditInbound, so /add and /update/:id (the only routes that persist an inbound's
// counters, and the only ones the page posts up/down to) are refused for them.
//
// The AllTime fallback mirrors what the page does for rows written before all_time
// existed (`allTime || up + down`), so a reseller's band and an admin's answer the
// same question rather than differing on legacy data.
func rescopeInboundTraffic(inbound *model.Inbound) {
	var up, down, allTime int64
	for _, stat := range inbound.ClientStats {
		up += stat.Up
		down += stat.Down
		if stat.AllTime > 0 {
			allTime += stat.AllTime
		} else {
			allTime += stat.Up + stat.Down
		}
	}
	inbound.Up = up
	inbound.Down = down
	inbound.AllTime = allTime
}

// FilterClientTrafficsForReseller narrows a panel-wide set of traffic rows to one
// reseller's accounts. Returns a fresh slice rather than mutating the caller's.
func (s *InboundService) FilterClientTrafficsForReseller(traffics []xray.ClientTraffic, ownedEmails map[string]bool) []xray.ClientTraffic {
	kept := make([]xray.ClientTraffic, 0, len(traffics))
	for _, traffic := range traffics {
		if ResellerOwnsEmail(ownedEmails, traffic.Email) {
			kept = append(kept, traffic)
		}
	}
	return kept
}

// ResellerOwnsEmail tests one email against an OwnedEmails set.
//
// The set is lower-cased at the source and emails are the panel's case-insensitive
// account identity (see sameEmail), so the folding lives here rather than at each of
// the call sites: one that forgets it matches nothing, which fails closed but is
// indistinguishable from a reseller who has sold nothing, and so would ship.
func ResellerOwnsEmail(ownedEmails map[string]bool, email string) bool {
	return ownedEmails[strings.ToLower(strings.TrimSpace(email))]
}

// filterSettingsClients removes every client not in ownedEmails from a settings blob
// and leaves every other key alone.
//
// Decoded into json.RawMessage rather than into `any`: the blob carries protocol
// settings this panel does not model (decryption, fallbacks, external proxy lists)
// plus whatever a future Xray adds, and all of it has to come back out unchanged.
// Raw values are copied verbatim, so the only thing lost is top-level key ORDER,
// which no Go map can preserve, and only on a blob that actually had a client
// removed.
func filterSettingsClients(settings string, ownedEmails map[string]bool) (string, error) {
	root := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(settings), &root); err != nil {
		return "", err
	}
	raw, ok := root["clients"]
	if !ok {
		// A clients-less protocol (dokodemo-door, the relay inbounds). Nothing to
		// strip, so nothing to churn either.
		return settings, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return "", err
	}
	kept := make([]json.RawMessage, 0, len(list))
	for _, item := range list {
		var probe struct {
			Email string `json:"email"`
		}
		// A client whose email will not decode cannot be shown to belong to this
		// reseller, so it goes with the rest.
		if err := json.Unmarshal(item, &probe); err != nil {
			continue
		}
		if ResellerOwnsEmail(ownedEmails, probe.Email) {
			kept = append(kept, item)
		}
	}
	if len(kept) == len(list) {
		return settings, nil
	}
	// kept is make()d, never nil: json writes a nil slice as null, and the page
	// iterates this array, where [] is the reseller with no accounts here.
	clients, err := json.Marshal(kept)
	if err != nil {
		return "", err
	}
	root["clients"] = clients
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// inboundDisplayOrder is the order the panel's inbound list is shown in: the
// positions the operator dragged the rows into, then id for everything they have not
// touched.
//
// The CASE is what lets sort_order default to 0 without disturbing a live panel. A
// plain "sort_order, id" would sort every unpositioned row (0) ABOVE the positioned
// ones, so the first drag on a 50-inbound panel would appear to fling 49 rows to the
// bottom, and every inbound added afterwards would jump to the top. Sorting 0 last
// instead means: an upgraded panel where every row is still 0 keeps exactly the id
// order it has always had, and a new inbound appends to the end as it always did.
const inboundDisplayOrder = "CASE WHEN sort_order > 0 THEN 0 ELSE 1 END, sort_order, id"

// getInboundsWhere loads inbounds by id, or all of them when ids is nil.
func (s *InboundService) getInboundsWhere(ids []int) ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	q := db.Model(model.Inbound{}).Preload("ClientStats").Order(inboundDisplayOrder)
	if ids != nil {
		q = q.Where("id IN (?)", ids)
	}
	err := q.Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	// Enrich client stats with UUID/SubId from inbound settings
	for _, inbound := range inbounds {
		clients, _ := s.GetClients(inbound)
		if len(clients) == 0 || len(inbound.ClientStats) == 0 {
			continue
		}
		// Build a map email -> client
		cMap := make(map[string]model.Client, len(clients))
		for _, c := range clients {
			cMap[strings.ToLower(c.Email)] = c
		}
		for i := range inbound.ClientStats {
			email := strings.ToLower(inbound.ClientStats[i].Email)
			if c, ok := cMap[email]; ok {
				inbound.ClientStats[i].UUID = c.ID
				inbound.ClientStats[i].SubId = c.SubID
			}
		}
	}
	return inbounds, nil
}

// ReorderInbounds moves the named inbounds into the given order and leaves every
// other inbound where it is. Display only: nothing here reaches Xray, so no caller
// needs a restart afterwards.
//
// ids is the list AS THE CALLER SEES IT, which for anyone but a super admin is a
// subset of the panel. That is why the ids are not simply renumbered 1..N: doing so
// would renumber them over positions held by inbounds the caller cannot see and
// reshuffle another admin's table as a side effect. Instead the SLOTS the named
// inbounds currently occupy in the panel-wide order are collected, and re-filled in
// the requested order. Exactly the rows named move, into positions they already held
// between them.
//
// Ownership is the CALLER's to prove, not this function's: like every other route
// whose targets arrive in the body, the controller checks the ids against the caller's
// grants first (see callerOwnsInbounds).
func (s *InboundService) ReorderInbounds(ids []int) error {
	if len(ids) < 2 {
		// One row cannot change places with itself, and an empty list has nothing to
		// say. Both are a no-op rather than an error: the page can fire a reorder for
		// a drag that landed where it started.
		return nil
	}
	db := database.GetDB()
	var all []*model.Inbound
	if err := db.Model(model.Inbound{}).Select("id", "sort_order").
		Order(inboundDisplayOrder).Find(&all).Error; err != nil {
		return err
	}

	// Every inbound's CURRENT position, 1-based and panel-wide. Positions rather than
	// stored sort_order values, because those start out 0 for every row: without
	// resolving them to positions first, every inbound would share slot 0 and the
	// arithmetic below would collapse.
	position := make(map[int]int, len(all))
	for i, inbound := range all {
		position[inbound.Id] = i + 1
	}

	slots := make([]int, 0, len(ids))
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		p, ok := position[id]
		if !ok {
			return common.NewError("reorder: no such inbound: ", id)
		}
		if seen[id] {
			return common.NewError("reorder: inbound listed twice: ", id)
		}
		seen[id] = true
		slots = append(slots, p)
	}
	sort.Ints(slots)

	want := make(map[int]int, len(ids))
	for i, id := range ids {
		want[id] = slots[i]
	}

	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	for _, inbound := range all {
		newOrder, moved := want[inbound.Id]
		if !moved {
			// Pinned where it already sits. This is what converts a panel full of
			// zeroes into real positions on the first reorder: leave the untouched
			// rows at 0 and they would all sort below the ones that just got a
			// position, which is the drag flinging rows to the bottom.
			newOrder = position[inbound.Id]
		}
		if inbound.SortOrder == newOrder {
			continue
		}
		if err := tx.Model(model.Inbound{}).Where("id = ?", inbound.Id).
			Update("sort_order", newOrder).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

// GetAllInbounds retrieves all inbounds from the database.
// Returns a slice of all inbound models with their associated client statistics.
func (s *InboundService) GetAllInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Preload("ClientStats").Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	// Enrich client stats with UUID/SubId from inbound settings
	for _, inbound := range inbounds {
		clients, _ := s.GetClients(inbound)
		if len(clients) == 0 || len(inbound.ClientStats) == 0 {
			continue
		}
		cMap := make(map[string]model.Client, len(clients))
		for _, c := range clients {
			cMap[strings.ToLower(c.Email)] = c
		}
		for i := range inbound.ClientStats {
			email := strings.ToLower(inbound.ClientStats[i].Email)
			if c, ok := cMap[email]; ok {
				inbound.ClientStats[i].UUID = c.ID
				inbound.ClientStats[i].SubId = c.SubID
			}
		}
	}
	return inbounds, nil
}

func (s *InboundService) GetInboundsByTrafficReset(period string) ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("traffic_reset = ?", period).Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return inbounds, nil
}

func (s *InboundService) checkPortExist(listen string, port int, ignoreId int) (bool, error) {
	db := database.GetDB()
	if listen == "" || listen == "0.0.0.0" || listen == "::" || listen == "::0" {
		db = db.Model(model.Inbound{}).Where("port = ?", port)
	} else {
		db = db.Model(model.Inbound{}).
			Where("port = ?", port).
			Where(
				db.Model(model.Inbound{}).Where(
					"listen = ?", listen,
				).Or(
					"listen = \"\"",
				).Or(
					"listen = \"0.0.0.0\"",
				).Or(
					"listen = \"::\"",
				).Or(
					"listen = \"::0\""))
	}
	if ignoreId > 0 {
		db = db.Where("id != ?", ignoreId)
	}
	var count int64
	err := db.Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// greBookkeepingPortBase is where the search for a GRE inbound's port starts. 47 is GRE's
// IP protocol number, so the stored numbers at least read as GRE to whoever opens the DB.
const greBookkeepingPortBase = 47

// NormalizeGrePort settles a GRE inbound's port server-side, which is why the form has no
// port box for GRE at all. GRE is IP protocol 47: it binds nothing and has no ports, so
// the number is pure bookkeeping. It cannot simply be dropped, because the inbound tag is
// built from it ("inbound-<port>") and the routing rules, the paired dokodemo-door inbound
// and the traffic rows are all keyed on that tag. The row therefore still needs a port
// that is valid and unique, with nobody left to type one.
//
// On add (id == 0) a port that cannot be used, whether missing, out of range or already
// claimed, is replaced with the lowest free one, so creating a GRE inbound can never fail
// on a conflict the operator can neither see nor fix. On update the stored port is kept
// whenever the request carries no usable one: renumbering an existing GRE inbound would
// move its tag out from under everything keyed on it.
func (s *InboundService) NormalizeGrePort(inbound *model.Inbound, id int) error {
	if inbound == nil || inbound.Protocol != model.GRE {
		return nil
	}

	if inbound.Port >= 1 && inbound.Port <= 65535 {
		exist, err := s.checkPortExist(inbound.Listen, inbound.Port, id)
		if err != nil {
			return err
		}
		if !exist {
			return nil
		}
	}

	if id > 0 {
		old, err := s.GetInbound(id)
		if err != nil {
			return err
		}
		inbound.Port = old.Port
		return nil
	}

	// Every port in use, regardless of which address its inbound listens on. Stricter
	// than checkPortExist, which lets two inbounds share a port on different addresses:
	// a GRE port that is unique panel-wide cannot trip that check whatever Listen ends
	// up being, and it keeps the tags unique too.
	var used []int
	if err := database.GetDB().Model(model.Inbound{}).Pluck("port", &used).Error; err != nil {
		return err
	}
	taken := make(map[int]bool, len(used))
	for _, port := range used {
		taken[port] = true
	}
	for port := greBookkeepingPortBase; port <= 65535; port++ {
		if !taken[port] {
			inbound.Port = port
			return nil
		}
	}
	return common.NewError("no free port left to key a GRE inbound on")
}

// GetClients decodes an inbound's accounts from its settings JSON.
//
// The discarded Unmarshal error is DELIBERATE and load-bearing. The browser's ClientBase
// defaults tgId to the empty string while model.Client.TgID is an int64, so every inbound
// the panel has ever written decodes with an UnmarshalTypeError on that one field. Go's
// decoder skips the mistyped field and keeps going, so the accounts come back complete
// with TgID=0. Checking the error here would fail EVERY inbound in the database at once.
//
// Fixing it at the source is worse than it looks: the client form binds
// v-model.number="client.tgId", so defaulting to 0 instead would show a spurious 0 in the
// Telegram box of every account that never set one, across all eight ClientBase
// protocols. Pinned by TestUnmarshalRecoversFromBrowserTgIdString, which asserts both
// that the error is real and that the data survives it.
func (s *InboundService) GetClients(inbound *model.Inbound) ([]model.Client, error) {
	settings := map[string][]model.Client{}
	json.Unmarshal([]byte(inbound.Settings), &settings)
	if settings == nil {
		return nil, fmt.Errorf("setting is null")
	}

	clients := settings["clients"]
	if clients == nil {
		return nil, nil
	}
	return clients, nil
}

// A client's email is the panel's GLOBAL account identity, not a per-inbound label:
// it is the unique key of client_traffics, the name RADIUS authenticates and the
// selector the per-account routing rules are built from. Two clients sharing one
// email are therefore one account to everything downstream, whichever inbounds they
// live in, which is why the checks below query across all inbounds rather than the
// one being edited.

// sameEmail reports whether two emails name the same account. Identity is case- and
// whitespace-insensitive, so every comparison must be too: comparing with == would
// read a "Bob" -> "bob" rename as a change of identity.
func sameEmail(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// containsEmail is the identity-aware counterpart of contains (which stays exact for
// PPP usernames). It trims the stored side too, because rows written before
// normalizeClientEmails existed may still carry untrimmed emails.
func containsEmail(emails []string, email string) bool {
	for _, e := range emails {
		if sameEmail(e, email) {
			return true
		}
	}
	return false
}

// normalizeClientEmails trims surrounding whitespace off every client email in an
// inbound's settings JSON, which is what later gets persisted.
//
// Normalizing on WRITE rather than only at compare time: client_traffics.email is
// the unique index, so storing "bob " beside "bob" leaves two keys the index is
// perfectly happy to accept, and downstream two accounts. Trimming before the
// settings are parsed means the key that lands in the DB is the one uniqueness was
// checked against.
//
// The JSON is only rebuilt when something actually changed, so the common case does
// not churn key order or re-encode numbers.
func normalizeClientEmails(settings string) string {
	var root map[string]any
	if err := json.Unmarshal([]byte(settings), &root); err != nil || root == nil {
		// Malformed settings are the callers' own unmarshal to report, not ours.
		return settings
	}
	list, ok := root["clients"].([]any)
	if !ok {
		return settings
	}
	changed := false
	for _, item := range list {
		client, ok := item.(map[string]any)
		if !ok {
			continue
		}
		email, ok := client["email"].(string)
		if !ok {
			continue
		}
		if trimmed := strings.TrimSpace(email); trimmed != email {
			client["email"] = trimmed
			changed = true
		}
	}
	if !changed {
		return settings
	}
	normalized, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return settings
	}
	return string(normalized)
}

// duplicateEmailError is shared so the mutation paths cannot drift into wording the
// UI shows differently for the same rejection.
func duplicateEmailError(email string) error {
	return common.NewErrorf("Duplicate email: %q is already used by another client. Emails must be unique across all inbounds.", email)
}

// getAllEmailsExcludingInbound lists every client email in the DB except one
// inbound's. An ignoreInboundId of 0 excludes nothing: inbound ids are AUTOINCREMENT
// and start at 1, so no row can hold 0.
func (s *InboundService) getAllEmailsExcludingInbound(ignoreInboundId int) ([]string, error) {
	db := database.GetDB()
	var emails []string
	// COALESCE, because a client that carries no `email` key at all yields SQL NULL and
	// scanning NULL into a string fails with "converting NULL to string is unsupported".
	// That error propagates out of the duplicate check, so ONE malformed stored client
	// would make every later add/edit of any client fail with "Something went wrong".
	// Client JSON is spliced into the settings as posted (AddInboundClient works through
	// map[string]any), so a caller that omits the field really does store it missing.
	// An empty entry is harmless here: the callers only look up non-empty values.
	err := db.Raw(`
		SELECT COALESCE(JSON_EXTRACT(client.value, '$.email'), '')
		FROM inbounds,
			JSON_EACH(JSON_EXTRACT(inbounds.settings, '$.clients')) AS client
		WHERE inbounds.id != ?
		`, ignoreInboundId).Scan(&emails).Error
	if err != nil {
		return nil, err
	}
	return emails, nil
}

func (s *InboundService) getAllEmails() ([]string, error) {
	return s.getAllEmailsExcludingInbound(0)
}

func (s *InboundService) contains(slice []string, str string) bool {
	lowerStr := strings.ToLower(str)
	for _, s := range slice {
		if strings.ToLower(s) == lowerStr {
			return true
		}
	}
	return false
}

func (s *InboundService) getAllPPPUsernames(protocol string) ([]string, error) {
	db := database.GetDB()
	var usernames []string
	// COALESCE for the same reason as getAllEmailsExcludingInbound, and here it is not
	// hypothetical: model.Client.ID is `json:"id,omitempty"`, so an account created
	// without a username is stored with NO id key. The NULL that produced then broke this
	// scan, and with it EVERY subsequent add/edit of a client on that protocol —
	// "openvpn works but a second account cannot be created" reduces to this one line.
	err := db.Raw(`
		SELECT COALESCE(JSON_EXTRACT(client.value, '$.id'), '')
		FROM inbounds,
			JSON_EACH(JSON_EXTRACT(inbounds.settings, '$.clients')) AS client
		WHERE inbounds.protocol = ?
		`, protocol).Scan(&usernames).Error
	if err != nil {
		return nil, err
	}
	return usernames, nil
}

func (s *InboundService) checkPPPUsernamesForDuplicates(protocol string, clients []model.Client) (string, error) {
	allUsernames, err := s.getAllPPPUsernames(protocol)
	if err != nil {
		return "", err
	}
	var usernames []string
	for _, client := range clients {
		if client.ID != "" {
			if s.contains(usernames, client.ID) {
				return client.ID, nil
			}
			if s.contains(allUsernames, client.ID) {
				return client.ID, nil
			}
			usernames = append(usernames, client.ID)
		}
	}
	return "", nil
}

// vpnLoginProtocols are the protocols whose client "id" is a LOGIN NAME: a value
// the customer types into their client and the server authenticates them by.
//
// wg-c, awg, gre and mtproto are deliberately absent even though they also store an
// "id". Nothing reads it for them (the identity is the email, and the credential is
// a keypair or a secret), so it is not a login and folding it into this namespace
// would refuse names nobody can log in with.
var vpnLoginProtocols = []model.Protocol{
	model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT,
	model.SSTP, model.IKEV2, model.SSH,
}

func isVpnLoginProtocol(protocol model.Protocol) bool {
	for _, p := range vpnLoginProtocols {
		if protocol == p {
			return true
		}
	}
	return false
}

// loginKey normalises a login name for comparison, the same way accountKey
// normalises an email. Authentication itself compares exactly, so this is STRICTER
// than the wire: it refuses "Alice" against a stored "alice". That is deliberate.
// Two accounts differing only in case are indistinguishable to the operator who has
// to support them, and the email rule this is modelled on already works this way.
func loginKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// getAllVpnLoginOwners maps every login name in use, panel-wide, to the set of
// account emails currently using it.
//
// Panel-wide and cross-protocol, which is the whole point. It used to be scoped to
// one protocol, because that is all the DATA PLANE strictly needs: l2tp/pptp/ikev2
// share a daemon that sends a bare NAS-Identifier, so RadiusService.findClientInbound
// resolves an account by username across a protocol's inbounds and takes the first
// match. But "unique per protocol" is an implementation detail leaking into policy:
// an operator does not think of a customer's login as belonging to l2tp, and two
// customers sharing one name is a support problem whatever the protocols are.
//
// A set of emails per name, not one email, because MIGRATED data can legitimately
// already contain a collision (a panel that predates this rule, or an import). The
// caller forgives a name the posting account already holds, which is what keeps that
// data editable while still refusing every NEW collision.
func (s *InboundService) getAllVpnLoginOwners() (map[string]map[string]bool, error) {
	db := database.GetDB()
	var rows []struct {
		Login string
		Email string
	}
	protocols := make([]string, 0, len(vpnLoginProtocols))
	for _, p := range vpnLoginProtocols {
		protocols = append(protocols, string(p))
	}
	// COALESCE for the same reason as getAllPPPUsernames: `id` is omitempty, so an
	// account stored without one yields NULL and a bare scan into a string dies,
	// taking every add and edit of that protocol with it.
	err := db.Raw(`
		SELECT COALESCE(JSON_EXTRACT(client.value, '$.id'), '')   AS login,
		       COALESCE(JSON_EXTRACT(client.value, '$.email'), '') AS email
		FROM inbounds,
			JSON_EACH(JSON_EXTRACT(inbounds.settings, '$.clients')) AS client
		WHERE inbounds.protocol IN ?
		`, protocols).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	owners := map[string]map[string]bool{}
	for _, r := range rows {
		key := loginKey(r.Login)
		if key == "" {
			continue
		}
		if owners[key] == nil {
			owners[key] = map[string]bool{}
		}
		owners[key][accountKey(r.Email)] = true
	}
	return owners, nil
}

// findNewDuplicateLogin returns the first login name in clients that a DIFFERENT
// account already answers to, panel-wide. Empty means the batch is clean.
//
// Two things count as taken, because RADIUS treats them as the same thing: another
// account's login name, and another account's EMAIL. getClientPassword matches on
// `client.ID == username || client.Email == username` (radius.go:764), so a login of
// "bob@example.com" authenticates as whoever owns that email. Checking only the login
// column would leave that door open.
//
// Only CHANGED names are held to the rule. A name the posting account already holds
// passes, so re-saving an inbound works, and so does editing an account that a
// migration left sharing a name with another one. New collisions are refused
// outright; old ones are left for the operator to clean up deliberately.
func (s *InboundService) findNewDuplicateLogin(clients []model.Client) (string, error) {
	owners, err := s.getAllVpnLoginOwners()
	if err != nil {
		return "", err
	}
	emails, err := s.getAllEmailsExcludingInbound(0)
	if err != nil {
		return "", err
	}
	emailOwners := map[string]bool{}
	for _, e := range emails {
		if k := accountKey(e); k != "" {
			emailOwners[k] = true
		}
	}

	seen := map[string]string{} // login -> the email in THIS batch that claimed it
	for _, client := range clients {
		key := loginKey(client.ID)
		if key == "" {
			continue
		}
		mine := accountKey(client.Email)
		// Inside the posted list a repeat is always wrong unless it is the same
		// account twice, which one inbound cannot serve anyway.
		if prev, dup := seen[key]; dup && prev != mine {
			return client.ID, nil
		}
		seen[key] = mine
		// Already stored against this account: unchanged, so not a new collision.
		if owners[key][mine] {
			continue
		}
		if len(owners[key]) > 0 {
			return client.ID, nil
		}
		// A login that is somebody else's email would authenticate as them.
		if key != mine && emailOwners[key] {
			return client.ID, nil
		}
	}
	return "", nil
}

// checkEmailsExistExcludingInbound returns the first email in clients that already
// names another account, whether inside the batch itself or anywhere in the DB
// outside ignoreInboundId.
//
// The exclusion is what makes this usable from UpdateInbound, which REPLACES an
// inbound's whole client list: measured against the whole DB, every client it is
// KEEPING would collide with its own persisted row. Callers whose row is not yet
// persisted (AddInbound) or whose write is additive (AddInboundClient) pass 0 and
// get a plain global check.
func (s *InboundService) checkEmailsExistExcludingInbound(clients []model.Client, ignoreInboundId int) (string, error) {
	return s.checkEmailsExistExcludingKnown(clients, ignoreInboundId, nil)
}

// checkEmailsExistExcludingKnown is the same check with a set of emails that are
// ALREADY served on this inbound and are therefore not new duplicates.
//
// This exists because one account may now legitimately be on several inbounds.
// The plain check asks "does this email appear on any OTHER inbound", which used
// to mean "a different account already owns it". It no longer does: the same
// email on two inbounds is ONE account with two memberships, which is the whole
// feature. So saving an inbound that holds any multi-inbound account failed with
// "Duplicate email ... must be unique across all inbounds", and the operator
// could not edit that inbound at all. Found on a live panel.
//
// The exemption is deliberately narrow: only emails ALREADY stored on this
// inbound are forgiven, so re-saving an existing member works while typing a
// stranger's email into the client list still fails. Joining an account to a new
// inbound goes through inboundIds, where the intent is explicit.
func (s *InboundService) checkEmailsExistExcludingKnown(clients []model.Client, ignoreInboundId int, known []string) (string, error) {
	allEmails, err := s.getAllEmailsExcludingInbound(ignoreInboundId)
	if err != nil {
		return "", err
	}
	var emails []string
	for _, client := range clients {
		email := strings.TrimSpace(client.Email)
		if email == "" {
			continue
		}
		// A duplicate WITHIN the posted list is always wrong, membership or not:
		// one inbound cannot serve the same account twice.
		if containsEmail(emails, email) {
			return email, nil
		}
		if containsEmail(allEmails, email) && !containsEmail(known, email) {
			return email, nil
		}
		emails = append(emails, email)
	}
	return "", nil
}

func (s *InboundService) checkEmailsExistForClients(clients []model.Client) (string, error) {
	return s.checkEmailsExistExcludingInbound(clients, 0)
}

// firstAnytlsPasswordCollision returns the EMAIL of the first account here that shares
// its password with an earlier one, or "" when they are all distinct. It names the
// account rather than the password so the collision can be reported without putting a
// live credential in an error message, a log line or the panel's UI.
//
// AnyTLS carries no username on the wire: a client sends only its password and the core
// looks the account up by that password's hash. Two accounts sharing one are therefore
// indistinguishable to everything downstream, and the loser's traffic is booked against
// the winner, so the core refuses to build such an inbound at all.
//
// That refusal is why this is caught here instead of being left to the core. The panel
// logs AddUser's rejection at Debug and swallows it (it only sets needRestart), so the
// operator is told the add succeeded; the restart that follows then hands Xray a config
// it rejects OUTRIGHT, and one unbuildable inbound takes every OTHER inbound on the box
// down with it. Only hand-typed passwords can collide (generated ones are uuids), but
// the cost of the one that does is the whole node.
func firstAnytlsPasswordCollision(clients []model.Client) string {
	seen := make(map[string]struct{}, len(clients))
	for _, client := range clients {
		if client.Password == "" {
			continue
		}
		if _, duplicate := seen[client.Password]; duplicate {
			return client.Email
		}
		seen[client.Password] = struct{}{}
	}
	return ""
}

// naiveAuthUsername returns the Basic-auth username the core will actually match for
// this account: its own username when it has one, its email otherwise. The fallback is
// what every naive account predating the username field authenticates with.
//
// The test is EMPTY, not blank. The same one-line rule is written four more times (the
// core's Validator, both share-link generators, the exports), and a trim here would make
// this the only place where a username of " " means the email, so the panel would
// validate one credential and hand out another.
func naiveAuthUsername(client model.Client) string {
	if client.Username != "" {
		return client.Username
	}
	return client.Email
}

// firstNaiveUsernameFault returns the EMAIL of the first account whose Basic-auth
// username is unusable, plus what is wrong with it, or ("", "") when they are all fine.
// It names the account rather than the username so a collision can be reported without
// putting half a live credential in an error message or the panel's UI.
//
// Two faults, both of which produce an account that exists in the panel and can never
// log in:
//
//   - A COLON. HTTP Basic is base64("user:pass") and the server splits on the FIRST
//     colon, so a colon in the username silently moves the split and the password the
//     core compares is not the one the operator typed.
//   - A DUPLICATE. The core indexes accounts by this value, so two accounts sharing one
//     are indistinguishable and the loser's traffic is booked against the winner.
//     Checked against the resolved value, not the raw field: an account with username
//     "bob" collides with a username-less account whose EMAIL is "bob" just as surely.
//
// Caught here rather than left to the core because the core deliberately degrades with
// a warning instead of failing Build() (an error there makes Xray refuse the ENTIRE
// config and takes every unrelated inbound on the box down with it), so nothing
// downstream would ever tell the operator.
func firstNaiveUsernameFault(clients []model.Client) (string, string) {
	seen := make(map[string]struct{}, len(clients))
	for _, client := range clients {
		if strings.Contains(client.Username, ":") {
			return client.Email, "a naive username cannot contain a colon"
		}
		username := naiveAuthUsername(client)
		if username == "" {
			continue
		}
		if _, duplicate := seen[username]; duplicate {
			return client.Email, "duplicate naive username"
		}
		seen[username] = struct{}{}
	}
	return "", ""
}

// isVpnProtocol reports whether a protocol is one of the panel's built-in VPN
// backends (L2TP/PPTP/OpenVPN). These are NOT native Xray inbounds — Xray only
// sees a separately-injected dokodemo-door that shares the inbound's tag — so
// the live add/del inbound API must not touch them: DelInbound(tag) would drop
// that dokodemo and AddInbound can't recreate it ("openvpn" etc. aren't Xray
// protocols), silently killing the clients' route to the internet. Changes to
// them are applied by a full Xray restart instead.
func isVpnProtocol(p model.Protocol) bool {
	return p == model.L2TP || p == model.PPTP || p == model.OPENVPN || p == model.OPENCONNECT || p == model.SSTP || p == model.IKEV2 || p == model.WGC || p == model.AWG || p == model.GRE
}

// isRelayProtocol reports whether p is a relay: it terminates its own protocol outside
// Xray (telemt for mtproto, the in-binary gateway for ssh) and reaches Xray through a
// PAIRED socks inbound the panel builds separately (GetSocksConfig), sharing this
// inbound's tag.
func isRelayProtocol(p model.Protocol) bool {
	return p == model.MTPROTO || p == model.SSH
}

// hasDerivedXrayInbound reports whether what this inbound contributes to Xray is
// something the panel DERIVES — a dokodemo-door for the VPN protocols, a socks inbound
// for the relays — rather than GenXrayInboundConfig's own output.
//
// Such an inbound must never take the live del/add API path, and the relay half of that
// is not a variation on the VPN reasoning above but the same bug with a worse ending.
// DelInbound(tag) succeeds, because the derived inbound carries this inbound's tag, and
// then AddInbound hands Xray a panel-only protocol ("unknown config id: mtproto") and
// fails. The running core is left with no socks inbound, so telemt's upstream is refused
// and every client on it is dead.
//
// What makes it stick is that nothing repairs it. The GENERATED config still contains
// the derived inbound, so the running config and the generated one compare equal and
// RestartXray takes its "does not need to restart" path, leaving the live instance
// diverged from the config that describes it. It stays dead until some unrelated edit
// changes the config enough to force a restart.
//
// Reported as "enabling the speed limit on an mtproto inbound kills the backend until
// I restart all cores". The speed limit is only how it was found: it is delivered by the
// speedlimits.json sidecar and touches no Xray inbound, which is exactly what leaves the
// config byte-identical. Any inbound-level edit that does the same (remark, quota,
// expiry, traffic multiplier) had the same effect.
func hasDerivedXrayInbound(p model.Protocol) bool {
	return isVpnProtocol(p) || isRelayProtocol(p)
}

// AddInbound creates a new inbound configuration.
// It validates port uniqueness, client email uniqueness, and required fields,
// then saves the inbound to the database and optionally adds it to the running Xray instance.
// Returns the created inbound, whether Xray needs restart, and any error.
// validateInboundConfig enforces invariants the panel UI is also expected to
// guard, so an API client (or a stale/buggy frontend) can't persist a bad
// inbound: a sane TCP/UDP port range, and — for OpenVPN — that a server
// certificate actually exists before the inbound is created.
// ikev2AuthMode returns an ikev2 inbound's auth mode ("eap-mschapv2" default,
// "psk", or "eap-tls"). Empty string for non-ikev2 inbounds.
func ikev2AuthMode(inbound *model.Inbound) string {
	if inbound == nil || inbound.Protocol != "ikev2" {
		return ""
	}
	var st struct {
		AuthMode string `json:"authMode"`
	}
	_ = json.Unmarshal([]byte(inbound.Settings), &st)
	if m := strings.TrimSpace(st.AuthMode); m != "" {
		return m
	}
	return "eap-mschapv2"
}

func (s *InboundService) validateInboundConfig(inbound *model.Inbound) error {
	validPort := func(p int) bool { return p >= 1 && p <= 65535 }

	// Traffic multiplier. Rejected here so a poisoned value never reaches the DB:
	// the form binder parses "NaN"/"Inf" happily, and a NaN multiplier drives a
	// client's counter to MinInt64, after which `up + down >= total` is false
	// forever and the account can never be quota-disabled again.
	if inbound.TrafficMultiplierEnable && !validMultiplier(inbound.TrafficMultiplier) {
		return common.NewError(
			fmt.Sprintf("Traffic multiplier must be a number greater than 1 and at most %d (got %v)",
				MaxTrafficMultiplier, inbound.TrafficMultiplier))
	}
	if inbound.TrafficMultiplierAfter < 0 {
		return common.NewError("Traffic multiplier threshold cannot be negative")
	}

	// Speed limit. The form's :min="0" is not a guard: the API can be posted directly.
	// A negative rate would reach the sidecar and become a negative rate.Limit, which
	// blocks the account outright instead of throttling it, so reject it here rather
	// than let it look like a mysterious dead connection.
	if inbound.SpeedLimitDown < 0 || inbound.SpeedLimitUp < 0 {
		return common.NewError("Speed limit cannot be negative")
	}
	if inbound.SpeedLimitAfter < 0 {
		return common.NewError("Speed limit threshold cannot be negative")
	}

	// IP limit. The resolver already reads a negative as "absent" so nothing bad can
	// reach the core, but that defence is SILENT: an operator posting -1 would get a
	// 200 and an account with no limit, and nothing would say why. Reject it here for
	// the same reason the speed limits above are rejected, and keep the read-side
	// guard as the last line against a hand-edited or imported DB, which no request
	// validator ever sees.
	if inbound.IPLimit < 0 {
		return common.NewError("IP limit cannot be negative")
	}
	// The strategy resolver absorbs any unknown value as "reject", which is the safe
	// default but silently discards a typo like "Accept" or "evict". Only the two
	// words the VPN User Limit already uses are accepted.
	switch inbound.IPLimitStrategy {
	case "", "reject", "accept":
	default:
		return common.NewError(fmt.Sprintf("IP limit strategy must be \"reject\" or \"accept\" (got %q)", inbound.IPLimitStrategy))
	}

	if inbound.Protocol == "openvpn" {
		var st struct {
			TcpEnable  bool   `json:"tcpEnable"`
			TcpPort    int    `json:"tcpPort"`
			UdpEnable  bool   `json:"udpEnable"`
			CaCert     string `json:"caCert"`
			ServerCert string `json:"serverCert"`
		}
		if err := json.Unmarshal([]byte(inbound.Settings), &st); err != nil {
			return common.NewError("Invalid OpenVPN settings:", err)
		}
		if !st.TcpEnable && !st.UdpEnable {
			return common.NewError("OpenVPN requires at least one of TCP/UDP enabled")
		}
		if st.UdpEnable && !validPort(inbound.Port) {
			return common.NewError("Invalid OpenVPN UDP port (must be 1-65535):", inbound.Port)
		}
		if st.TcpEnable && !validPort(st.TcpPort) {
			return common.NewError("Invalid OpenVPN TCP port (must be 1-65535):", st.TcpPort)
		}
		if strings.TrimSpace(st.CaCert) == "" || strings.TrimSpace(st.ServerCert) == "" {
			return common.NewError("OpenVPN certificate is required: generate or provide a certificate before saving")
		}
		return nil
	}

	if inbound.Protocol == "sstp" {
		var st struct {
			TlsUseFile      bool   `json:"tlsUseFile"`
			CertificateFile string `json:"certificateFile"`
			KeyFile         string `json:"keyFile"`
			Certificate     string `json:"certificate"`
			Key             string `json:"key"`
		}
		if err := json.Unmarshal([]byte(inbound.Settings), &st); err != nil {
			return common.NewError("Invalid SSTP settings:", err)
		}
		if !validPort(inbound.Port) {
			return common.NewError("Invalid SSTP port (must be 1-65535):", inbound.Port)
		}
		// A server cert+key must be present before saving (accel-pppd's sstp module
		// refuses to start without one): either operator-supplied file paths, or inline
		// PEM content (e.g. from "Generate Self-Signed Cert"). Mirrors the OpenVPN guard.
		hasFile := st.TlsUseFile && strings.TrimSpace(st.CertificateFile) != "" && strings.TrimSpace(st.KeyFile) != ""
		hasInline := strings.TrimSpace(st.Certificate) != "" && strings.TrimSpace(st.Key) != ""
		if !hasFile && !hasInline {
			return common.NewError("SSTP certificate is required: generate or provide a certificate before saving")
		}
		return nil
	}

	if inbound.Protocol == "ikev2" {
		var st struct {
			AuthMode        string `json:"authMode"`
			TlsUseFile      bool   `json:"tlsUseFile"`
			CertificateFile string `json:"certificateFile"`
			KeyFile         string `json:"keyFile"`
			Certificate     string `json:"certificate"`
			Key             string `json:"key"`
		}
		if err := json.Unmarshal([]byte(inbound.Settings), &st); err != nil {
			return common.NewError("Invalid IKEv2 settings:", err)
		}
		// PSK mode needs no server cert; the EAP-MSCHAPv2 / EAP-TLS modes require one
		// (charon presents a server cert the client validates). Mirrors the SSTP guard.
		if strings.TrimSpace(st.AuthMode) != "psk" {
			hasFile := st.TlsUseFile && strings.TrimSpace(st.CertificateFile) != "" && strings.TrimSpace(st.KeyFile) != ""
			hasInline := strings.TrimSpace(st.Certificate) != "" && strings.TrimSpace(st.Key) != ""
			if !hasFile && !hasInline {
				return common.NewError("IKEv2 certificate is required: generate or provide a server certificate before saving")
			}
		}
		return nil
	}

	if !validPort(inbound.Port) {
		return common.NewError("Invalid port (must be 1-65535):", inbound.Port)
	}
	return nil
}

func (s *InboundService) AddInbound(inbound *model.Inbound) (*model.Inbound, bool, error) {
	// Fill in every settings key of the protocol's shape the caller left out, then
	// validate what is left, so a MINIMAL API body (or none at all) creates the same
	// inbound the panel's own Add form would. Only for the protocols whose settings JSON
	// is built client-side (see web/service/protocoldefaults.go); an Xray-native inbound
	// passes through untouched.
	//
	// Defaults only ADD absent keys, so every request the UI makes today (all of which
	// already carry the full shape) comes back byte-identical and nothing it sent is
	// second-guessed. Ahead of everything below, so the blob validated is the blob
	// stored.
	if err := NormalizeInboundSettings(inbound); err != nil {
		return inbound, false, err
	}

	// Before anything parses the settings, so the emails checked below and the ones
	// persisted are the same strings.
	inbound.Settings = normalizeClientEmails(inbound.Settings)

	if err := s.validateInboundConfig(inbound); err != nil {
		return inbound, false, err
	}
	// Some settings are dictated by the shared daemon, so refuse a value that would
	// be accepted and then silently ignored.
	if err := CheckSharedDaemonConflicts(inbound, 0); err != nil {
		return inbound, false, err
	}
	exist, err := s.checkPortExist(inbound.Listen, inbound.Port, 0)
	if err != nil {
		return inbound, false, err
	}
	if exist {
		return inbound, false, common.NewError("Port already exists:", inbound.Port)
	}

	clients, err := s.GetClients(inbound)
	if err != nil {
		return inbound, false, err
	}

	// Reject an identity that cannot safely round-trip through the daemon config
	// files and the Xray stat names, BEFORE anything is written.
	if err := validateClientIdentities(inbound.Protocol, clients); err != nil {
		return inbound, false, err
	}

	// Nothing to exclude: this inbound has no row yet, so the whole DB is "other".
	existEmail, err := s.checkEmailsExistExcludingInbound(clients, 0)
	if err != nil {
		return inbound, false, err
	}
	if existEmail != "" {
		return inbound, false, duplicateEmailError(existEmail)
	}

	// Ensure created_at and updated_at on clients in settings
	if len(clients) > 0 {
		var settings map[string]any
		if err2 := json.Unmarshal([]byte(inbound.Settings), &settings); err2 == nil && settings != nil {
			now := time.Now().Unix() * 1000
			updatedClients := make([]model.Client, 0, len(clients))
			for i, c := range clients {
				if c.CreatedAt == 0 {
					c.CreatedAt = now
				}
				c.UpdatedAt = now
				// A new inbound's accounts take slots 0..n-1, which is what their
				// positions would have given them; storing it is what keeps the address
				// once a later delete compacts the list.
				if c.Slot == nil && slotPoolProtocol(inbound.Protocol) {
					slot := i
					c.Slot = &slot
				}
				updatedClients = append(updatedClients, c)
			}
			settings["clients"] = updatedClients
			if bs, err3 := json.MarshalIndent(settings, "", "  "); err3 == nil {
				inbound.Settings = string(bs)
			} else {
				logger.Debug("Unable to marshal inbound settings with timestamps:", err3)
			}
		} else if err2 != nil {
			logger.Debug("Unable to parse inbound settings for timestamps:", err2)
		}
	}

	// Secure client ID
	for _, client := range clients {
		if clientIdentity(inbound.Protocol, client) == "" {
			return inbound, false, common.NewError("empty client ID")
		}
	}

	// A login name is unique PANEL-WIDE, exactly like an email. See
	// findNewDuplicateLogin: the old check was per protocol, which is all the RADIUS
	// demux strictly needs but is not a rule an operator can hold in their head, and
	// it left openconnect out of the list entirely.
	if isVpnLoginProtocol(inbound.Protocol) {
		dupUser, err := s.findNewDuplicateLogin(clients)
		if err != nil {
			return inbound, false, err
		}
		if dupUser != "" {
			return inbound, false, common.NewError("Duplicate username:", dupUser)
		}
	} else if inbound.Protocol == model.WGC || inbound.Protocol == model.AWG || inbound.Protocol == model.GRE {
		// Their "id" is the email by convention and nothing authenticates by it, so
		// they keep the narrow per-protocol check rather than joining the login
		// namespace.
		dupUser, err := s.checkPPPUsernamesForDuplicates(string(inbound.Protocol), clients)
		if err != nil {
			return inbound, false, err
		}
		if dupUser != "" {
			return inbound, false, common.NewError("Duplicate username:", dupUser)
		}
	}

	if inbound.Protocol == model.ANYTLS {
		if dupClient := firstAnytlsPasswordCollision(clients); dupClient != "" {
			return inbound, false, common.NewError("Duplicate AnyTLS password on client:", dupClient)
		}
	}

	if inbound.Protocol == model.NAIVE {
		if badClient, reason := firstNaiveUsernameFault(clients); badClient != "" {
			return inbound, false, common.NewError(reason, " on client:", badClient)
		}
	}

	db := database.GetDB()
	tx := db.Begin()
	defer func() {
		if err == nil {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()

	err = tx.Save(inbound).Error
	if err == nil {
		if len(inbound.ClientStats) == 0 {
			for _, client := range clients {
				s.AddClientStat(tx, inbound.Id, &client)
			}
		}
	} else {
		return inbound, false, err
	}

	needRestart := false
	if inbound.Enable {
		if hasDerivedXrayInbound(inbound.Protocol) {
			// Its dokodemo (VPN) or socks inbound (relay) is added by the full restart
			// the caller triggers. Neither can be built from this inbound's own
			// protocol, so the API path below would only log a failure and set this
			// same flag.
			needRestart = true
		} else {
			s.xrayApi.Init(p.GetAPIPort())
			inboundJson, err1 := json.MarshalIndent(inbound.GenXrayInboundConfig(), "", "  ")
			if err1 != nil {
				logger.Debug("Unable to marshal inbound config:", err1)
			}

			err1 = s.xrayApi.AddInbound(inboundJson)
			if err1 == nil {
				logger.Debug("New inbound added by api:", inbound.Tag)
			} else {
				logger.Debug("Unable to add inbound by api:", err1)
				needRestart = true
			}
			s.xrayApi.Close()
		}
	}

	return inbound, needRestart, err
}

// DelInbound deletes an inbound configuration by ID.
// It removes the inbound from the database and the running Xray instance if active.
// Returns whether Xray needs restart and any error.
func (s *InboundService) DelInbound(id int) (bool, error) {
	// Drop every admin's grant for this inbound. Ids are AUTOINCREMENT so they are
	// not reissued, but leaving the rows means a stale grant lingers forever and the
	// Admins modal would tick a checkbox for an inbound that no longer exists.
	var adminService AdminService
	if err := adminService.RevokeInboundEverywhere(id); err != nil {
		logger.Warning("revoking inbound access on delete: ", err)
	}
	db := database.GetDB()

	var tag string
	needRestart := false
	result := db.Model(model.Inbound{}).Select("tag").Where("id = ? and enable = ?", id, true).First(&tag)
	if result.Error == nil {
		s.xrayApi.Init(p.GetAPIPort())
		err1 := s.xrayApi.DelInbound(tag)
		if err1 == nil {
			logger.Debug("Inbound deleted by api:", tag)
		} else {
			logger.Debug("Unable to delete inbound by api:", err1)
			needRestart = true
		}
		s.xrayApi.Close()
	} else {
		logger.Debug("No enabled inbound founded to removing by api", tag)
	}

	// Delete client traffics of inbounds
	err := db.Where("inbound_id = ?", id).Delete(xray.ClientTraffic{}).Error
	if err != nil {
		return false, err
	}
	inbound, err := s.GetInbound(id)
	if err != nil {
		return false, err
	}
	clients, err := s.GetClients(inbound)
	if err != nil {
		return false, err
	}
	for _, client := range clients {
		err := s.DelClientIPs(db, client.Email)
		if err != nil {
			return false, err
		}
	}

	return needRestart, db.Delete(model.Inbound{}, id).Error
}

// LoadClientStats fills in an inbound's traffic rows, for the callers that fetched the
// row through GetInbound (which does not preload them) and still need them.
//
// Deliberately not folded into GetInbound: that one is on every write path in this
// service, and none of them read ClientStats, so the join would be paid dozens of
// times per request for nothing.
func (s *InboundService) LoadClientStats(inbound *model.Inbound) error {
	if inbound == nil {
		return nil
	}
	var stats []xray.ClientTraffic
	err := database.GetDB().Model(xray.ClientTraffic{}).
		Where("inbound_id = ?", inbound.Id).Find(&stats).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	inbound.ClientStats = stats
	return nil
}

func (s *InboundService) GetInbound(id int) (*model.Inbound, error) {
	db := database.GetDB()
	inbound := &model.Inbound{}
	err := db.Model(model.Inbound{}).First(inbound, id).Error
	if err != nil {
		return nil, err
	}
	return inbound, nil
}

// UpdateInbound modifies an existing inbound configuration.
// It validates changes, updates the database, and syncs with the running Xray instance.
// Returns the updated inbound, whether Xray needs restart, and any error.
func (s *InboundService) UpdateInbound(inbound *model.Inbound) (*model.Inbound, bool, error) {
	// Before anything parses the settings, so the emails checked below and the ones
	// persisted are the same strings.
	inbound.Settings = normalizeClientEmails(inbound.Settings)

	if err := s.validateInboundConfig(inbound); err != nil {
		return inbound, false, err
	}
	if err := CheckSharedDaemonConflicts(inbound, inbound.Id); err != nil {
		return inbound, false, err
	}
	exist, err := s.checkPortExist(inbound.Listen, inbound.Port, inbound.Id)
	if err != nil {
		return inbound, false, err
	}
	if exist {
		return inbound, false, common.NewError("Port already exists:", inbound.Port)
	}

	// This edit REPLACES the client list, so the inbound's own persisted row is not a
	// competitor and must be excluded, or every client being kept collides with
	// itself. Ahead of updateClientTraffics because that is what would otherwise hit
	// the client_traffics unique index mid-transaction, turning a duplicate the user
	// can fix into an opaque constraint failure.
	updatedClients, err := s.GetClients(inbound)
	if err != nil {
		return inbound, false, err
	}
	// Only entries that actually CHANGED are held to the identity rules. This save
	// posts every client on the inbound, so validating all of them would let one
	// account created before these rules existed block every later edit to the
	// inbound (its DNS, its remark, an unrelated new account) until someone went and
	// fixed that row. See validateChangedClientIdentities.
	// Emails already served on THIS inbound, needed twice below: to exempt an
	// unchanged identity from the new validation rules, and to stop a legitimate
	// membership reading as a duplicate.
	var knownEmails []string
	if storedInbound, gerr := s.GetInbound(inbound.Id); gerr == nil && storedInbound != nil {
		storedClients, cerr := s.GetClients(storedInbound)
		if cerr != nil {
			return inbound, false, cerr
		}
		for i := range storedClients {
			if e := strings.TrimSpace(storedClients[i].Email); e != "" {
				knownEmails = append(knownEmails, e)
			}
		}
		if err := validateChangedClientIdentities(inbound.Protocol, updatedClients, storedClients); err != nil {
			return inbound, false, err
		}
	} else if err := validateClientIdentities(inbound.Protocol, updatedClients); err != nil {
		return inbound, false, err
	}

	existEmail, err := s.checkEmailsExistExcludingKnown(updatedClients, inbound.Id, knownEmails)
	if err != nil {
		return inbound, false, err
	}
	if existEmail != "" {
		return inbound, false, duplicateEmailError(existEmail)
	}

	// No exclusion needed, unlike the email check above: this list REPLACES the stored
	// one wholesale, so it is already the exact set of accounts the core will be asked
	// to build.
	if inbound.Protocol == model.ANYTLS {
		if dupClient := firstAnytlsPasswordCollision(updatedClients); dupClient != "" {
			return inbound, false, common.NewError("Duplicate AnyTLS password on client:", dupClient)
		}
	}

	if inbound.Protocol == model.NAIVE {
		if badClient, reason := firstNaiveUsernameFault(updatedClients); badClient != "" {
			return inbound, false, common.NewError(reason, " on client:", badClient)
		}
	}

	oldInbound, err := s.GetInbound(inbound.Id)
	if err != nil {
		return inbound, false, err
	}

	tag := oldInbound.Tag

	db := database.GetDB()
	tx := db.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	err = s.updateClientTraffics(tx, oldInbound, inbound)
	if err != nil {
		return inbound, false, err
	}

	// Ensure created_at and updated_at exist in inbound.Settings clients
	{
		var oldSettings map[string]any
		_ = json.Unmarshal([]byte(oldInbound.Settings), &oldSettings)
		emailToCreated := map[string]int64{}
		emailToUpdated := map[string]int64{}
		if oldSettings != nil {
			if oc, ok := oldSettings["clients"].([]any); ok {
				for _, it := range oc {
					if m, ok2 := it.(map[string]any); ok2 {
						if email, ok3 := m["email"].(string); ok3 {
							switch v := m["created_at"].(type) {
							case float64:
								emailToCreated[email] = int64(v)
							case int64:
								emailToCreated[email] = v
							}
							switch v := m["updated_at"].(type) {
							case float64:
								emailToUpdated[email] = int64(v)
							case int64:
								emailToUpdated[email] = v
							}
						}
					}
				}
			}
		}
		var newSettings map[string]any
		if err2 := json.Unmarshal([]byte(inbound.Settings), &newSettings); err2 == nil && newSettings != nil {
			now := time.Now().Unix() * 1000
			if nSlice, ok := newSettings["clients"].([]any); ok {
				for i := range nSlice {
					if m, ok2 := nSlice[i].(map[string]any); ok2 {
						email, _ := m["email"].(string)
						if _, ok3 := m["created_at"]; !ok3 {
							if v, ok4 := emailToCreated[email]; ok4 && v > 0 {
								m["created_at"] = v
							} else {
								m["created_at"] = now
							}
						}
						// Preserve client's updated_at if present; do not bump on parent inbound update
						if _, hasUpdated := m["updated_at"]; !hasUpdated {
							if v, ok4 := emailToUpdated[email]; ok4 && v > 0 {
								m["updated_at"] = v
							}
						}
						nSlice[i] = m
					}
				}
				// Carry pool slots forward the same way created_at is carried: this form
				// posts EVERY client, so without it a save would re-derive addresses from
				// the posted order. Matched by email; a genuinely new account here takes
				// the lowest free slot.
				if oldClients, gerr := s.GetClients(oldInbound); gerr == nil {
					assignSlotsToClientMaps(inbound.Protocol, oldClients, nSlice)
				}
				newSettings["clients"] = nSlice
				if bs, err3 := json.MarshalIndent(newSettings, "", "  "); err3 == nil {
					inbound.Settings = string(bs)
				}
			}
		}
	}

	oldInbound.Up = inbound.Up
	oldInbound.Down = inbound.Down
	oldInbound.Total = inbound.Total
	oldInbound.Remark = inbound.Remark
	oldInbound.Enable = inbound.Enable
	oldInbound.ExpiryTime = inbound.ExpiryTime
	oldInbound.TrafficReset = inbound.TrafficReset
	oldInbound.TrafficMultiplierEnable = inbound.TrafficMultiplierEnable
	oldInbound.TrafficMultiplierAfter = inbound.TrafficMultiplierAfter
	oldInbound.TrafficMultiplier = inbound.TrafficMultiplier
	oldInbound.SpeedLimitEnable = inbound.SpeedLimitEnable
	oldInbound.SpeedLimitSeparate = inbound.SpeedLimitSeparate
	oldInbound.SpeedLimitDown = inbound.SpeedLimitDown
	oldInbound.SpeedLimitUp = inbound.SpeedLimitUp
	oldInbound.SpeedLimitAfter = inbound.SpeedLimitAfter
	oldInbound.IPLimit = inbound.IPLimit
	oldInbound.IPLimitStrategy = inbound.IPLimitStrategy
	oldInbound.Listen = inbound.Listen
	oldInbound.Port = inbound.Port
	oldInbound.Protocol = inbound.Protocol
	oldInbound.Settings = inbound.Settings
	oldInbound.StreamSettings = inbound.StreamSettings
	oldInbound.Sniffing = inbound.Sniffing
	if inbound.Listen == "" || inbound.Listen == "0.0.0.0" || inbound.Listen == "::" || inbound.Listen == "::0" {
		oldInbound.Tag = fmt.Sprintf("inbound-%v", inbound.Port)
	} else {
		oldInbound.Tag = fmt.Sprintf("inbound-%v:%v", inbound.Listen, inbound.Port)
	}

	needRestart := false
	if hasDerivedXrayInbound(oldInbound.Protocol) {
		// Leave the running dokodemo (VPN) or socks inbound (relay) in place. The live
		// del/add API would drop it and be unable to recreate it, cutting the clients'
		// internet until a full restart that an unchanged config will not trigger. The
		// caller's on<Proto>Changed handles the restart that rebuilds it.
		needRestart = true
	} else {
		s.xrayApi.Init(p.GetAPIPort())
		if s.xrayApi.DelInbound(tag) == nil {
			logger.Debug("Old inbound deleted by api:", tag)
		}
		if inbound.Enable {
			runtimeInbound, err2 := s.buildRuntimeInboundForAPI(tx, oldInbound)
			if err2 != nil {
				logger.Debug("Unable to prepare runtime inbound config:", err2)
				needRestart = true
			} else {
				inboundJson, err2 := json.MarshalIndent(runtimeInbound.GenXrayInboundConfig(), "", "  ")
				if err2 != nil {
					logger.Debug("Unable to marshal updated inbound config:", err2)
					needRestart = true
				} else {
					err2 = s.xrayApi.AddInbound(inboundJson)
					if err2 == nil {
						logger.Debug("Updated inbound added by api:", oldInbound.Tag)
					} else {
						logger.Debug("Unable to update inbound by api:", err2)
						needRestart = true
					}
				}
			}
		}
		s.xrayApi.Close()
	}

	return inbound, needRestart, tx.Save(oldInbound).Error
}

func (s *InboundService) buildRuntimeInboundForAPI(tx *gorm.DB, inbound *model.Inbound) (*model.Inbound, error) {
	if inbound == nil {
		return nil, fmt.Errorf("inbound is nil")
	}

	runtimeInbound := *inbound
	settings := map[string]any{}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return nil, err
	}

	clients, ok := settings["clients"].([]any)
	if !ok {
		return &runtimeInbound, nil
	}

	// Deliberately NOT filtered by inbound_id. client_traffics.Email is UNIQUE
	// panel-wide, so one account has one row naming one inbound; scoping this read
	// to inbound.Id meant that on every other inbound serving the same account the
	// lookup missed and a depleted client was pushed to the live core as enabled.
	// This is the no-restart twin of the same hole in GetXrayConfig.
	var clientStats []xray.ClientTraffic
	err := tx.Model(xray.ClientTraffic{}).
		Select("email", "enable").
		Find(&clientStats).Error
	if err != nil {
		return nil, err
	}

	enableMap := make(map[string]bool, len(clientStats))
	for _, clientTraffic := range clientStats {
		enableMap[accountKey(clientTraffic.Email)] = clientTraffic.Enable
	}

	finalClients := make([]any, 0, len(clients))
	for _, client := range clients {
		c, ok := client.(map[string]any)
		if !ok {
			continue
		}

		email, _ := c["email"].(string)
		if enable, exists := enableMap[accountKey(email)]; exists && !enable {
			continue
		}

		if manualEnable, ok := c["enable"].(bool); ok && !manualEnable {
			continue
		}

		finalClients = append(finalClients, c)
	}

	settings["clients"] = finalClients
	modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	runtimeInbound.Settings = string(modifiedSettings)

	return &runtimeInbound, nil
}

func (s *InboundService) updateClientTraffics(tx *gorm.DB, oldInbound *model.Inbound, newInbound *model.Inbound) error {
	oldClients, err := s.GetClients(oldInbound)
	if err != nil {
		return err
	}
	newClients, err := s.GetClients(newInbound)
	if err != nil {
		return err
	}

	var emailExists bool

	for _, oldClient := range oldClients {
		emailExists = false
		for _, newClient := range newClients {
			if oldClient.Email == newClient.Email {
				emailExists = true
				break
			}
		}
		if !emailExists {
			err = s.DelClientStat(tx, oldClient.Email)
			if err != nil {
				return err
			}
		}
	}
	for _, newClient := range newClients {
		emailExists = false
		for _, oldClient := range oldClients {
			if newClient.Email == oldClient.Email {
				emailExists = true
				break
			}
		}
		if !emailExists {
			err = s.AddClientStat(tx, oldInbound.Id, &newClient)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *InboundService) AddInboundClient(data *model.Inbound) (bool, error) {
	// Before anything parses the settings: interfaceClients below is spliced into the
	// inbound's stored JSON verbatim, so an email left untrimmed here is persisted.
	data.Settings = normalizeClientEmails(data.Settings)

	clients, err := s.GetClients(data)
	if err != nil {
		return false, err
	}

	// Reject an unusable identity before it reaches the settings blob. The protocol
	// comes from the STORED inbound: the request body carries only id and settings
	// on this path, so data.Protocol is usually empty and the VPN username rules
	// would be skipped for exactly the protocols that need them.
	if target, terr := s.GetInbound(data.Id); terr == nil && target != nil {
		if err := validateClientIdentities(target.Protocol, clients); err != nil {
			return false, err
		}
	}

	var settings map[string]any
	err = json.Unmarshal([]byte(data.Settings), &settings)
	if err != nil {
		return false, err
	}

	interfaceClients := settings["clients"].([]any)
	// Add timestamps for new clients being appended
	nowTs := time.Now().Unix() * 1000
	for i := range interfaceClients {
		if cm, ok := interfaceClients[i].(map[string]any); ok {
			if _, ok2 := cm["created_at"]; !ok2 {
				cm["created_at"] = nowTs
			}
			cm["updated_at"] = nowTs
			interfaceClients[i] = cm
		}
	}
	// Additive: these clients are not in any row yet, so the whole DB is "other".
	existEmail, err := s.checkEmailsExistForClients(clients)
	if err != nil {
		return false, err
	}
	if existEmail != "" {
		return false, duplicateEmailError(existEmail)
	}

	oldInbound, err := s.GetInbound(data.Id)
	if err != nil {
		return false, err
	}

	// Capacity guard (per-account-IP protocols): refuse an add the IP pool can never
	// place. Index-based allocation hands accounts past capacity a nil tunnel IP, so the
	// client would otherwise be created and listed in the UI yet be silently unroutable
	// (no peer, no route). Reject loudly with an actionable message instead. maxVpnAccounts
	// is an upper bound, so this never rejects a client the pool could actually hold.
	if maxAcc, ok := maxVpnAccounts(oldInbound); ok {
		existing, _ := s.GetClients(oldInbound)
		// Slots can be sparse (a delete frees one without renumbering the rest), so the
		// question is whether the slots these accounts would take fit the pool, not how
		// many accounts there are.
		slots := slotsForNewAccounts(existing, len(clients))
		if len(slots) > 0 && slots[len(slots)-1] >= maxAcc {
			return false, common.NewError(fmt.Sprintf(
				"IP pool full for this %s inbound: it can hold at most %d account(s) at the current User Limit (%d already present). Lower the User Limit, or add another inbound.",
				oldInbound.Protocol, maxAcc, len(existing)))
		}
	}

	// IKEv2 auth-mode client-management constraints:
	//   psk / eap-tls - exactly one email-only account (shared key / client cert)
	//   eap-mschapv2  - many accounts
	switch ikev2AuthMode(oldInbound) {
	case "psk", "eap-tls":
		if existing, _ := s.GetClients(oldInbound); len(existing) >= 1 {
			return false, common.NewError("PSK and EAP-TLS IKEv2 inbounds allow only one account")
		}
	}

	// Secure client ID
	for _, client := range clients {
		if clientIdentity(oldInbound.Protocol, client) == "" {
			return false, common.NewError("empty client ID")
		}
	}

	// Panel-wide login uniqueness; see findNewDuplicateLogin. Re-saving an inbound is
	// safe because every name it already holds belongs to the account posting it.
	if isVpnLoginProtocol(oldInbound.Protocol) {
		dupUser, err := s.findNewDuplicateLogin(clients)
		if err != nil {
			return false, err
		}
		if dupUser != "" {
			return false, common.NewError("Duplicate username:", dupUser)
		}
	} else if oldInbound.Protocol == model.WGC || oldInbound.Protocol == model.AWG || oldInbound.Protocol == model.GRE {
		dupUser, err := s.checkPPPUsernamesForDuplicates(string(oldInbound.Protocol), clients)
		if err != nil {
			return false, err
		}
		if dupUser != "" {
			return false, common.NewError("Duplicate username:", dupUser)
		}
	}

	// Measured against what the inbound ALREADY holds, not just the incoming batch:
	// the core's account list is per-inbound, so a new client colliding with a
	// persisted one is the same fatal config as two new ones colliding with each other.
	if oldInbound.Protocol == model.ANYTLS {
		existing, gerr := s.GetClients(oldInbound)
		if gerr != nil {
			return false, gerr
		}
		if dupClient := firstAnytlsPasswordCollision(append(existing, clients...)); dupClient != "" {
			return false, common.NewError("Duplicate AnyTLS password on client:", dupClient)
		}
	}

	// Same reasoning as the anytls check above: the core's account index is per-inbound,
	// so a new username colliding with a persisted one is the same broken account as two
	// new ones colliding with each other.
	if oldInbound.Protocol == model.NAIVE {
		existing, gerr := s.GetClients(oldInbound)
		if gerr != nil {
			return false, gerr
		}
		if badClient, reason := firstNaiveUsernameFault(append(existing, clients...)); badClient != "" {
			return false, common.NewError(reason, " on client:", badClient)
		}
	}

	var oldSettings map[string]any
	err = json.Unmarshal([]byte(oldInbound.Settings), &oldSettings)
	if err != nil {
		return false, err
	}

	oldClients := oldSettings["clients"].([]any)
	// Give each added account its pool slot before it joins the list, from what the
	// inbound already holds: the address must not depend on where in the list it lands.
	if existing, gerr := s.GetClients(oldInbound); gerr == nil {
		assignSlotsToClientMaps(oldInbound.Protocol, existing, interfaceClients)
	}
	oldClients = append(oldClients, interfaceClients...)

	oldSettings["clients"] = oldClients

	newSettings, err := json.MarshalIndent(oldSettings, "", "  ")
	if err != nil {
		return false, err
	}

	oldInbound.Settings = string(newSettings)

	db := database.GetDB()
	tx := db.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	needRestart := false
	s.xrayApi.Init(p.GetAPIPort())
	for _, client := range clients {
		if len(client.Email) > 0 {
			s.AddClientStat(tx, data.Id, &client)
			if client.Enable {
				cipher := ""
				if oldInbound.Protocol == "shadowsocks" {
					cipher = oldSettings["method"].(string)
				}
				err1 := s.xrayApi.AddUser(string(oldInbound.Protocol), oldInbound.Tag, map[string]any{
					"email":    client.Email,
					"id":       client.ID,
					"auth":     client.Auth,
					"security": client.Security,
					"flow":     client.Flow,
					"password": client.Password,
					"username": client.Username,
					"cipher":   cipher,
				})
				if err1 == nil {
					logger.Debug("Client added by api:", client.Email)
				} else {
					logger.Debug("Error in adding client by api:", err1)
					needRestart = true
				}
			}
		} else {
			needRestart = true
		}
	}
	s.xrayApi.Close()

	return needRestart, tx.Save(oldInbound).Error
}

// clientIdentityKey returns the settings-JSON field a protocol's clients are
// IDENTIFIED by: the value the panel puts in /updateClient/:clientId and
// /delClient/:clientId, and the one every lookup must match on.
//
// This switch used to be copy-pasted into five places (AddInbound, AddInboundClient,
// UpdateInboundClient, DelInboundClient, getClientPrimaryKey) plus twice more in the
// browser, and the copies drifted apart. The newer username+password protocols
// (openconnect, sstp, ikev2) were added to the browser's list and to AddInbound's but
// to none of the other three, so an edit was keyed on the password client-side while
// the backend looked the account up by id. Nothing ever matched, and the edit came
// back as "empty client ID"; the delete silently removed nobody. One function now,
// and every id-keyed path goes through it.
func clientIdentityKey(protocol model.Protocol) string {
	switch protocol {
	// Username+password VPN protocols. The password is the identity rather than the
	// username because the username is the field operators actually rename, and a key
	// that moves mid-edit cannot be matched against the one the modal opened with.
	case model.Trojan, model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2:
		return "password"
	// Password-credential native Xray protocols. anytls authenticates on the password
	// alone. naive now carries its own Basic-auth username, and it still must not be
	// the identity: it is OPTIONAL (an account created before the field has none, and
	// keying on it would make every one of them unaddressable, "empty client ID" on
	// edit and a silent no-op on delete) and it is exactly the field an operator
	// renames, which is the rule the block above already states.
	case model.ANYTLS, model.NAIVE:
		return "password"
	case model.Shadowsocks:
		return "email"
	case model.Hysteria, model.Hysteria2:
		return "auth"
	default:
		// vmess/vless (uuid) and the email-identity protocols (wg-c, awg, mtproto,
		// ssh), whose settings JSON carries id=email. tuic also lands here: it
		// carries BOTH a uuid and a password, and the uuid is the identity.
		return "id"
	}
}

// clientIdentity returns client's value under its protocol's identity field. Empty
// means the client cannot be addressed, which every caller treats as an error.
func clientIdentity(protocol model.Protocol, client model.Client) string {
	switch clientIdentityKey(protocol) {
	case "password":
		return client.Password
	case "email":
		return client.Email
	case "auth":
		return client.Auth
	default:
		return client.ID
	}
}

func (s *InboundService) getClientPrimaryKey(protocol model.Protocol, client model.Client) string {
	return clientIdentity(protocol, client)
}

func (s *InboundService) writeBackClientSubID(sourceInboundID int, sourceProtocol model.Protocol, client model.Client, subID string) (bool, error) {
	client.SubID = subID
	client.UpdatedAt = time.Now().UnixMilli()
	clientID := s.getClientPrimaryKey(sourceProtocol, client)
	if clientID == "" {
		return false, common.NewError("empty client ID")
	}

	settingsBytes, err := json.Marshal(map[string][]model.Client{
		"clients": {client},
	})
	if err != nil {
		return false, err
	}

	updatePayload := &model.Inbound{
		Id:       sourceInboundID,
		Settings: string(settingsBytes),
	}
	return s.UpdateInboundClient(updatePayload, clientID)
}

func (s *InboundService) generateRandomCredential(targetProtocol model.Protocol) string {
	switch targetProtocol {
	case model.VMESS, model.VLESS:
		return uuid.NewString()
	default:
		return strings.ReplaceAll(uuid.NewString(), "-", "")
	}
}

func (s *InboundService) buildTargetClientFromSource(source model.Client, targetProtocol model.Protocol, email string, flow string) (model.Client, error) {
	nowTs := time.Now().UnixMilli()
	target := source
	target.Email = email
	target.CreatedAt = nowTs
	target.UpdatedAt = nowTs

	target.ID = ""
	target.Password = ""
	target.Auth = ""
	target.Flow = ""
	// naive's Basic-auth username is unique within an inbound, so carrying the source's
	// over would give the copy a credential that collides on arrival. Cleared rather
	// than minted: empty falls back to the new email, which is already unique.
	target.Username = ""
	// The address-pool slot belongs to the SOURCE inbound's pool. Carrying it over would
	// hand the copy an address an account in the target inbound may already hold; the add
	// path allocates a free one there instead.
	target.Slot = nil

	switch targetProtocol {
	case model.VMESS:
		target.ID = s.generateRandomCredential(targetProtocol)
	case model.VLESS:
		target.ID = s.generateRandomCredential(targetProtocol)
		if flow == "xtls-rprx-vision" || flow == "xtls-rprx-vision-udp443" {
			target.Flow = flow
		}
	case model.Trojan, model.Shadowsocks:
		target.Password = s.generateRandomCredential(targetProtocol)
	case model.ANYTLS, model.NAIVE:
		// Password-only accounts. naive's Basic-auth username is the email, which
		// was already set above, so nothing else has to be minted.
		target.Password = s.generateRandomCredential(targetProtocol)
	case model.TUIC:
		// TUIC authenticates with a uuid AND a password and is keyed on the uuid, so
		// both have to be minted or the copy is unusable. The uuid must keep its
		// dashes: generateRandomCredential strips them for everything but
		// vmess/vless, and a TUIC client parses this field as a real UUID.
		target.ID = uuid.NewString()
		target.Password = s.generateRandomCredential(targetProtocol)
	case model.Hysteria, model.Hysteria2:
		target.Auth = s.generateRandomCredential(targetProtocol)
	case model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2:
		// These authenticate with a username AND a password, and both were wiped
		// above. Only the username used to be minted back, so a copied account was
		// created, listed in the table, and could never log in: RADIUS had nothing
		// to check against. It also left the account with no identity at all for the
		// protocols keyed on the password (see clientIdentityKey).
		target.ID = s.generateRandomCredential(targetProtocol)
		target.Password = s.generateRandomCredential(targetProtocol)
	case model.WGC, model.AWG, model.GRE, model.MTPROTO, model.SSH:
		// Email-identity protocols: their settings JSON stores id=email and the
		// panel's client models derive id from email, so a random credential here
		// would name an account that does not exist.
		target.ID = email
	default:
		target.ID = s.generateRandomCredential(targetProtocol)
	}

	// Nothing downstream can address a client whose identity field is blank, and a
	// silently unusable account is worse than a refused copy.
	if clientIdentity(targetProtocol, target) == "" {
		return target, common.NewError("cannot build a ", targetProtocol, " client: no ", clientIdentityKey(targetProtocol), " was generated")
	}

	return target, nil
}

func (s *InboundService) nextAvailableCopiedEmail(originalEmail string, targetID int, occupied map[string]struct{}) string {
	base := fmt.Sprintf("%s_%d", originalEmail, targetID)
	candidate := base
	suffix := 0
	for {
		if _, exists := occupied[strings.ToLower(candidate)]; !exists {
			occupied[strings.ToLower(candidate)] = struct{}{}
			return candidate
		}
		suffix++
		candidate = fmt.Sprintf("%s_%d", base, suffix)
	}
}

func (s *InboundService) CopyInboundClients(targetInboundID int, sourceInboundID int, clientEmails []string, flow string) (*CopyClientsResult, bool, error) {
	return s.CopyInboundClientsScoped(targetInboundID, sourceInboundID, clientEmails, flow, nil)
}

// CopyInboundClientsScoped is the copy narrowed to a set of source accounts.
//
// A nil onlyEmails is the admin case. A non-nil one is a reseller's own accounts, and
// it closes the hole in the clientEmails argument below: an EMPTY list means "copy
// everything on the source", and a reseller reaches this route with PermCreateClient
// plus access to an inbound it shares with an admin. One request with no emails would
// otherwise clone every one of that admin's accounts.
//
// Note this only decides WHAT may be copied. Charging the copies to the reseller's
// balance and recording ownership of them is the caller's job, since the ledger lives
// a layer up.
func (s *InboundService) CopyInboundClientsScoped(targetInboundID int, sourceInboundID int, clientEmails []string, flow string, onlyEmails map[string]bool) (*CopyClientsResult, bool, error) {
	result := &CopyClientsResult{
		Added:   []string{},
		Skipped: []string{},
		Errors:  []string{},
	}
	if targetInboundID == sourceInboundID {
		return result, false, common.NewError("source and target inbounds must be different")
	}

	targetInbound, err := s.GetInbound(targetInboundID)
	if err != nil {
		return result, false, err
	}
	sourceInbound, err := s.GetInbound(sourceInboundID)
	if err != nil {
		return result, false, err
	}

	sourceClients, err := s.GetClients(sourceInbound)
	if err != nil {
		return result, false, err
	}
	if len(sourceClients) == 0 {
		return result, false, nil
	}

	allowedEmails := map[string]struct{}{}
	if len(clientEmails) > 0 {
		for _, email := range clientEmails {
			allowedEmails[strings.ToLower(strings.TrimSpace(email))] = struct{}{}
		}
	}

	occupiedEmails := map[string]struct{}{}
	allEmails, err := s.getAllEmails()
	if err != nil {
		return result, false, err
	}
	for _, email := range allEmails {
		clean := strings.Trim(email, "\"")
		if clean != "" {
			occupiedEmails[strings.ToLower(clean)] = struct{}{}
		}
	}

	newClients := make([]model.Client, 0)
	needRestart := false
	for _, sourceClient := range sourceClients {
		originalEmail := strings.TrimSpace(sourceClient.Email)
		if originalEmail == "" {
			continue
		}
		if onlyEmails != nil && !ResellerOwnsEmail(onlyEmails, originalEmail) {
			continue
		}
		if len(allowedEmails) > 0 {
			if _, ok := allowedEmails[strings.ToLower(originalEmail)]; !ok {
				continue
			}
		}

		if sourceClient.SubID == "" {
			newSubID := uuid.NewString()
			subNeedRestart, subErr := s.writeBackClientSubID(sourceInbound.Id, sourceInbound.Protocol, sourceClient, newSubID)
			if subErr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to write source subId: %v", originalEmail, subErr))
				continue
			}
			if subNeedRestart {
				needRestart = true
			}
			sourceClient.SubID = newSubID
		}

		targetEmail := s.nextAvailableCopiedEmail(originalEmail, targetInboundID, occupiedEmails)
		targetClient, buildErr := s.buildTargetClientFromSource(sourceClient, targetInbound.Protocol, targetEmail, flow)
		if buildErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", originalEmail, buildErr))
			continue
		}
		newClients = append(newClients, targetClient)
		result.Added = append(result.Added, targetEmail)
	}

	if len(newClients) == 0 {
		return result, needRestart, nil
	}

	settingsPayload, err := json.Marshal(map[string][]model.Client{
		"clients": newClients,
	})
	if err != nil {
		return result, needRestart, err
	}

	addNeedRestart, err := s.AddInboundClient(&model.Inbound{
		Id:       targetInboundID,
		Settings: string(settingsPayload),
	})
	if err != nil {
		return result, needRestart, err
	}
	if addNeedRestart {
		needRestart = true
	}

	return result, needRestart, nil
}

func (s *InboundService) DelInboundClient(inboundId int, clientId string) (bool, error) {
	oldInbound, err := s.GetInbound(inboundId)
	if err != nil {
		logger.Error("Load Old Data Error")
		return false, err
	}
	var settings map[string]any
	err = json.Unmarshal([]byte(oldInbound.Settings), &settings)
	if err != nil {
		return false, err
	}

	email := ""
	client_key := clientIdentityKey(oldInbound.Protocol)

	interfaceClients, _ := settings["clients"].([]any)
	var newClients []any
	needApiDel := false
	matched := false
	for _, client := range interfaceClients {
		c, ok := client.(map[string]any)
		if !ok {
			newClients = append(newClients, client)
			continue
		}
		// Comma-ok, not a bare assertion: a client stored without the identity field
		// (an older record, or a protocol whose UI never wrote it) used to panic the
		// whole request here rather than simply failing to match.
		c_id, _ := c[client_key].(string)
		if c_id != "" && c_id == clientId {
			matched = true
			email, _ = c["email"].(string)
			needApiDel, _ = c["enable"].(bool)
		} else {
			newClients = append(newClients, client)
		}
	}

	// No match means the caller addressed a client that is not in this inbound.
	// Reporting success while removing nobody is worse than an error: the row
	// disappears from the table until the next refresh puts it back.
	if !matched {
		return false, common.NewError("client not found:", clientId)
	}

	if len(newClients) == 0 {
		return false, common.NewError("no client remained in Inbound")
	}

	settings["clients"] = newClients
	newSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}

	oldInbound.Settings = string(newSettings)

	db := database.GetDB()

	err = s.DelClientIPs(db, email)
	if err != nil {
		logger.Error("Error in delete client IPs")
		return false, err
	}
	needRestart := false

	if len(email) > 0 {
		notDepleted := true
		err = db.Model(xray.ClientTraffic{}).Select("enable").Where("email = ?", email).First(&notDepleted).Error
		if err != nil {
			logger.Error("Get stats error")
			return false, err
		}
		err = s.DelClientStat(db, email)
		if err != nil {
			logger.Error("Delete stats Data Error")
			return false, err
		}
		if needApiDel && notDepleted {
			s.xrayApi.Init(p.GetAPIPort())
			err1 := s.xrayApi.RemoveUser(oldInbound.Tag, email)
			if err1 == nil {
				logger.Debug("Client deleted by api:", email)
				needRestart = false
			} else {
				if strings.Contains(err1.Error(), fmt.Sprintf("User %s not found.", email)) {
					logger.Debug("User is already deleted. Nothing to do more...")
				} else {
					logger.Debug("Error in deleting client by api:", err1)
					needRestart = true
				}
			}
			s.xrayApi.Close()
		}
	}
	return needRestart, db.Save(oldInbound).Error
}

func (s *InboundService) UpdateInboundClient(data *model.Inbound, clientId string) (bool, error) {
	// TODO: check if TrafficReset field is updating
	// Before anything parses the settings: interfaceClients[0] below replaces the
	// stored client verbatim, so an email left untrimmed here is persisted.
	data.Settings = normalizeClientEmails(data.Settings)

	clients, err := s.GetClients(data)
	if err != nil {
		return false, err
	}

	var settings map[string]any
	err = json.Unmarshal([]byte(data.Settings), &settings)
	if err != nil {
		return false, err
	}

	interfaceClients := settings["clients"].([]any)

	oldInbound, err := s.GetInbound(data.Id)
	if err != nil {
		return false, err
	}

	oldClients, err := s.GetClients(oldInbound)
	if err != nil {
		return false, err
	}

	// Validated against the STORED protocol, for the same reason as the add path,
	// and exempting an identity that is unchanged: editing only the QUOTA of an
	// account created before these rules existed has to keep working, or the rules
	// would be retroactive in practice. Touching any part of the identity makes the
	// tuple new and holds it to the current rules.
	if err := validateChangedClientIdentities(oldInbound.Protocol, clients, oldClients); err != nil {
		return false, err
	}

	oldEmail := ""
	newClientId := clientIdentity(oldInbound.Protocol, clients[0])
	clientIndex := -1
	for index, oldClient := range oldClients {
		if clientId == clientIdentity(oldInbound.Protocol, oldClient) {
			oldEmail = oldClient.Email
			clientIndex = index
			break
		}
	}

	// Validate new client ID
	if newClientId == "" || clientIndex == -1 {
		return false, common.NewError("empty client ID")
	}

	// Only a change of IDENTITY needs checking, and identity is case- and
	// whitespace-insensitive. Comparing with != instead made "Bob" -> "bob" look like
	// a rename and run the check, which searches the whole DB INCLUDING this client's
	// own persisted row, matches it case-insensitively and rejects the edit as a
	// duplicate of itself. Keeping the check global (no exclusion) is right here: a
	// genuine rename must not land on a sibling in this very inbound either.
	if len(clients[0].Email) > 0 && !sameEmail(clients[0].Email, oldEmail) {
		existEmail, err := s.checkEmailsExistForClients(clients)
		if err != nil {
			return false, err
		}
		if existEmail != "" {
			return false, duplicateEmailError(existEmail)
		}
	}

	// Panel-wide login uniqueness on the single-client edit path (see
	// findNewDuplicateLogin). The "did it actually change" gate stays: findNewDuplicateLogin
	// already forgives a name the posting account holds, but an edit that renames an
	// account whose OLD name was a migrated duplicate must not be refused for the name it
	// is moving away from.
	if isVpnLoginProtocol(oldInbound.Protocol) {
		if loginKey(clients[0].ID) != loginKey(oldClients[clientIndex].ID) {
			dupUser, err := s.findNewDuplicateLogin(clients)
			if err != nil {
				return false, err
			}
			if dupUser != "" {
				return false, common.NewError("Duplicate username:", dupUser)
			}
		}
	} else if oldInbound.Protocol == model.WGC || oldInbound.Protocol == model.AWG || oldInbound.Protocol == model.GRE {
		oldUsername := oldClients[clientIndex].ID
		newUsername := clients[0].ID
		if newUsername != oldUsername {
			dupUser, err := s.checkPPPUsernamesForDuplicates(string(oldInbound.Protocol), clients)
			if err != nil {
				return false, err
			}
			if dupUser != "" {
				return false, common.NewError("Duplicate username:", dupUser)
			}
		}
	}

	// The edited client REPLACES its old self here rather than joining the list: it is
	// still in oldClients, and measuring against that unchanged would reject every edit
	// as a collision with the account being edited.
	if oldInbound.Protocol == model.ANYTLS {
		prospective := make([]model.Client, len(oldClients))
		copy(prospective, oldClients)
		prospective[clientIndex] = clients[0]
		if dupClient := firstAnytlsPasswordCollision(prospective); dupClient != "" {
			return false, common.NewError("Duplicate AnyTLS password on client:", dupClient)
		}
	}

	if oldInbound.Protocol == model.NAIVE {
		prospective := make([]model.Client, len(oldClients))
		copy(prospective, oldClients)
		prospective[clientIndex] = clients[0]
		if badClient, reason := firstNaiveUsernameFault(prospective); badClient != "" {
			return false, common.NewError(reason, " on client:", badClient)
		}
	}

	var oldSettings map[string]any
	err = json.Unmarshal([]byte(oldInbound.Settings), &oldSettings)
	if err != nil {
		return false, err
	}
	settingsClients := oldSettings["clients"].([]any)
	// Preserve created_at and set updated_at for the replacing client
	var preservedCreated any
	// The account's pool slot is carried from the entry being replaced, by POSITION not
	// email: an edit may rename the email, and an account's address must not move because
	// its label changed. Falls back to the old list index for an unstamped row, which is
	// the address it has been using.
	preservedSlot := clientIndex
	if clientIndex >= 0 && clientIndex < len(settingsClients) {
		if oldMap, ok := settingsClients[clientIndex].(map[string]any); ok {
			if v, ok2 := oldMap["created_at"]; ok2 {
				preservedCreated = v
			}
			if v, ok2 := oldMap["slot"].(float64); ok2 && v >= 0 {
				preservedSlot = int(v)
			}
		}
	}
	if len(interfaceClients) > 0 {
		if newMap, ok := interfaceClients[0].(map[string]any); ok {
			if preservedCreated == nil {
				preservedCreated = time.Now().Unix() * 1000
			}
			newMap["created_at"] = preservedCreated
			newMap["updated_at"] = time.Now().Unix() * 1000
			if slotPoolProtocol(oldInbound.Protocol) {
				newMap["slot"] = preservedSlot
			}
			interfaceClients[0] = newMap
		}
	}
	settingsClients[clientIndex] = interfaceClients[0]
	oldSettings["clients"] = settingsClients

	newSettings, err := json.MarshalIndent(oldSettings, "", "  ")
	if err != nil {
		return false, err
	}

	oldInbound.Settings = string(newSettings)
	db := database.GetDB()
	tx := db.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	if len(clients[0].Email) > 0 {
		if len(oldEmail) > 0 {
			err = s.UpdateClientStat(tx, oldEmail, &clients[0])
			if err != nil {
				return false, err
			}
			err = s.UpdateClientIPs(tx, oldEmail, clients[0].Email)
			if err != nil {
				return false, err
			}
		} else {
			s.AddClientStat(tx, data.Id, &clients[0])
		}
	} else {
		err = s.DelClientStat(tx, oldEmail)
		if err != nil {
			return false, err
		}
		err = s.DelClientIPs(tx, oldEmail)
		if err != nil {
			return false, err
		}
	}
	needRestart := false
	if len(oldEmail) > 0 {
		s.xrayApi.Init(p.GetAPIPort())
		if oldClients[clientIndex].Enable {
			err1 := s.xrayApi.RemoveUser(oldInbound.Tag, oldEmail)
			if err1 == nil {
				logger.Debug("Old client deleted by api:", oldEmail)
			} else {
				if strings.Contains(err1.Error(), fmt.Sprintf("User %s not found.", oldEmail)) {
					logger.Debug("User is already deleted. Nothing to do more...")
				} else {
					logger.Debug("Error in deleting client by api:", err1)
					needRestart = true
				}
			}
		}
		if clients[0].Enable {
			cipher := ""
			if oldInbound.Protocol == "shadowsocks" {
				cipher = oldSettings["method"].(string)
			}
			err1 := s.xrayApi.AddUser(string(oldInbound.Protocol), oldInbound.Tag, map[string]any{
				"email":    clients[0].Email,
				"id":       clients[0].ID,
				"security": clients[0].Security,
				"flow":     clients[0].Flow,
				"auth":     clients[0].Auth,
				"password": clients[0].Password,
				"username": clients[0].Username,
				"cipher":   cipher,
			})
			if err1 == nil {
				logger.Debug("Client edited by api:", clients[0].Email)
			} else {
				logger.Debug("Error in adding client by api:", err1)
				needRestart = true
			}
		}
		s.xrayApi.Close()
	} else {
		logger.Debug("Client old email not found")
		needRestart = true
	}
	return needRestart, tx.Save(oldInbound).Error
}

// --- Bulk client operations ---------------------------------------------------

// BulkClientTarget identifies one client (by email, unique within an inbound) that a
// bulk operation should touch.
type BulkClientTarget struct {
	InboundId int    `json:"inboundId"`
	Email     string `json:"email"`
}

// BulkClientUpdateRequest describes a bulk operation applied to many clients across
// many inbounds. Op is one of addDays/subDays/addTraffic/subTraffic/enable/disable.
// Days is used by the day ops; AmountBytes by the traffic ops.
type BulkClientUpdateRequest struct {
	Op            string             `json:"op"`
	Days          int64              `json:"days"`
	AmountBytes   int64              `json:"amountBytes"`
	SkipFirstUse  bool               `json:"skipFirstUse"`
	SkipUnlimited bool               `json:"skipUnlimited"`
	SkipDisabled  bool               `json:"skipDisabled"`
	Targets       []BulkClientTarget `json:"targets"`
}

// BulkClientUpdateResult reports how many targeted clients were changed vs skipped
// (by a skip toggle, a no-op op, or because the client wasn't found).
type BulkClientUpdateResult struct {
	Applied int `json:"applied"`
	Skipped int `json:"skipped"`
}

const bulkMsPerDay = int64(86400000)

// bulkNumToInt64 coerces a JSON-decoded numeric field (float64 by default) to int64.
func bulkNumToInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

// BulkUpdateClients applies one operation to every targeted client, honouring the
// skip toggles. It mutates each affected inbound's settings JSON in place and saves
// it inside a single transaction. Returns the applied/skipped counts and the set of
// protocols touched, so the caller can regenerate the right subsystems once.
func (s *InboundService) BulkUpdateClients(req BulkClientUpdateRequest) (BulkClientUpdateResult, map[string]bool, error) {
	result := BulkClientUpdateResult{}
	touched := map[string]bool{}

	switch req.Op {
	case "addDays", "subDays", "addTraffic", "subTraffic", "enable", "disable", "delete", "freeze", "unfreeze":
	default:
		return result, touched, common.NewError("unknown bulk operation:", req.Op)
	}

	// Group targeted emails by inbound so each inbound is loaded and saved once.
	byInbound := map[int]map[string]bool{}
	for _, t := range req.Targets {
		if t.Email == "" {
			continue
		}
		if byInbound[t.InboundId] == nil {
			byInbound[t.InboundId] = map[string]bool{}
		}
		byInbound[t.InboundId][t.Email] = true
	}

	now := time.Now().Unix() * 1000
	db := database.GetDB()
	tx := db.Begin()
	var err error
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	for inboundId, emails := range byInbound {
		var inbound *model.Inbound
		inbound, err = s.GetInbound(inboundId)
		if err != nil {
			return result, touched, err
		}
		var settings map[string]any
		if err = json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			return result, touched, err
		}
		clientsAny, ok := settings["clients"].([]any)
		if !ok {
			continue
		}
		changed := false
		if req.Op == "delete" {
			// Delete removes targeted clients entirely (honouring the skip toggles) and
			// cleans up their stats + saved IPs. Never empty an inbound — an inbound must
			// keep >=1 client — so if every client is targeted, one is retained (skipped).
			del := map[string]bool{}
			total := 0
			for i := range clientsAny {
				cm, ok := clientsAny[i].(map[string]any)
				if !ok {
					continue
				}
				total++
				email, _ := cm["email"].(string)
				if email != "" && emails[email] && !bulkClientSkipped(cm, req) {
					del[email] = true
				}
			}
			if total > 0 && len(del) >= total {
				for e := range del { // keep one client back so the inbound isn't emptied
					delete(del, e)
					break
				}
			}
			var kept []any
			for i := range clientsAny {
				cm, _ := clientsAny[i].(map[string]any)
				email, _ := cm["email"].(string)
				if email != "" && del[email] {
					if err = s.DelClientStat(tx, email); err != nil {
						return result, touched, err
					}
					if err = s.DelClientIPs(tx, email); err != nil {
						return result, touched, err
					}
					result.Applied++
					changed = true
				} else {
					kept = append(kept, clientsAny[i])
					if email != "" && emails[email] {
						result.Skipped++ // targeted but retained (skip toggle or last-client guard)
					}
				}
			}
			clientsAny = kept
		} else {
			for i := range clientsAny {
				cm, ok := clientsAny[i].(map[string]any)
				if !ok {
					continue
				}
				email, _ := cm["email"].(string)
				if email == "" || !emails[email] {
					continue
				}
				// Single filtering point: every op (incl. freeze/unfreeze) honours the
				// skip toggles here, so all operations are filtered uniformly.
				if bulkClientSkipped(cm, req) {
					result.Skipped++
					continue
				}
				if applyBulkClientOp(cm, req, now) {
					cm["updated_at"] = now
					clientsAny[i] = cm
					changed = true
					result.Applied++
					// Keep the enforcement table (client_traffics) in sync with the new
					// limit/expiry/enable. The auto-disable check (disableInvalidClients)
					// reads client_traffics.total/expiry_time/enable, and those are
					// otherwise only written by add/updateClient — NOT by a whole-inbound
					// save — so without this a bulk limit/expiry change would be cosmetic.
					if e := tx.Model(&xray.ClientTraffic{}).Where("email = ?", email).
						Updates(map[string]any{
							"enable":      cm["enable"],
							"total":       bulkNumToInt64(cm["totalGB"]),
							"expiry_time": bulkNumToInt64(cm["expiryTime"]),
						}).Error; e != nil {
						err = e
						return result, touched, err
					}
				} else {
					result.Skipped++
				}
			}
		}
		if !changed {
			continue
		}
		settings["clients"] = clientsAny
		var newSettings []byte
		if newSettings, err = json.MarshalIndent(settings, "", "  "); err != nil {
			return result, touched, err
		}
		inbound.Settings = string(newSettings)
		if err = tx.Save(inbound).Error; err != nil {
			return result, touched, err
		}
		touched[string(inbound.Protocol)] = true
	}
	return result, touched, nil
}

// bulkClientSkipped reports whether a client is excluded by the request's skip
// toggles. It is the SINGLE filtering point for every bulk op (the update ops,
// freeze/unfreeze, and delete) so that every operation honours every toggle
// uniformly: a never-used (delayed start), disabled, or "unlimited" account is
// skipped. skipUnlimited is dimension-aware — day ops treat "unlimited" as
// no-expiry (expiryTime==0) so a lifetime account is never stamped with a
// deadline; every other op treats it as unlimited traffic (totalGB==0).
func bulkClientSkipped(cm map[string]any, req BulkClientUpdateRequest) bool {
	expiry := bulkNumToInt64(cm["expiryTime"])
	total := bulkNumToInt64(cm["totalGB"])
	enable, _ := cm["enable"].(bool)

	if req.SkipFirstUse && expiry < 0 {
		return true
	}
	if req.SkipDisabled && !enable {
		return true
	}
	if req.SkipUnlimited {
		switch req.Op {
		case "addDays", "subDays":
			if expiry == 0 { // unlimited time (lifetime): don't stamp a deadline
				return true
			}
		default: // traffic ops, enable/disable, freeze/unfreeze, delete: unlimited traffic
			if total == 0 {
				return true
			}
		}
	}
	return false
}

// applyBulkClientOp mutates one client map per the request, returning false when the
// op is a no-op for that client. Skip-toggle filtering is done by the caller via
// bulkClientSkipped, so every op is filtered uniformly. Semantics:
//   - addDays/subDays adjust expiryTime: >0 absolute (ms), <0 delayed "start after
//     first use" (grow the delay when adding), ==0 no expiry (addDays anchors from now).
//   - subTraffic floors totalGB at 1 byte so a subtract never flips a limited account
//     to unlimited (totalGB==0 means unlimited).
func applyBulkClientOp(cm map[string]any, req BulkClientUpdateRequest, now int64) bool {
	expiry := bulkNumToInt64(cm["expiryTime"])
	total := bulkNumToInt64(cm["totalGB"])
	enable, _ := cm["enable"].(bool)

	// Skip-toggle filtering happens in the caller (bulkClientSkipped). Freeze disables
	// the account and LOCKS its remaining time: a running (absolute) expiry is stored as
	// its negative remaining — the panel's "delayed start" form, which does not tick down
	// or trigger the auto-disable/expire check while the account is off. GB is locked for
	// free (a disabled account passes no traffic). Unfreeze re-enables and resumes the
	// clock immediately, converting the locked remaining back to an absolute deadline from
	// now. A frozen account is thus recognisable as (enable=false AND expiryTime<0).
	// frozenNoExpiry marks a frozen account that had NO expiry to lock (unlimited
	// duration). A frozen account must be recognisable as (enable=false AND
	// expiryTime<0); a no-expiry account has expiryTime==0, so without this sentinel
	// freezing it would leave expiryTime==0 and it would read as a plain disable, not
	// frozen (no cross icon / no "Frozen" badge, and it could never be unfrozen). The
	// magnitude 1(ms) can't collide with a real locked remaining (always a multi-day
	// duration) or a real delayed-start value, so unfreeze restores it to 0.
	const frozenNoExpiry int64 = -1
	switch req.Op {
	case "freeze":
		if !enable && expiry < 0 {
			return false // already frozen (disabled + locked) -> no-op
		}
		switch {
		case expiry > 0:
			cm["expiryTime"] = now - expiry // = -(remaining): a non-ticking delayed value
		case expiry == 0:
			cm["expiryTime"] = frozenNoExpiry // no expiry to lock: mark frozen via sentinel
			// expiry < 0 (a delayed-start account being frozen): keep its value as-is.
		}
		cm["enable"] = false
		return true
	case "unfreeze":
		if enable {
			return false // already active -> nothing to unfreeze
		}
		switch {
		case expiry == frozenNoExpiry:
			cm["expiryTime"] = int64(0) // had no expiry -> restore unlimited
		case expiry < 0:
			cm["expiryTime"] = now - expiry // = now + remaining: resume from this moment
		}
		cm["enable"] = true
		return true
	}

	switch req.Op {
	case "addDays":
		ms := req.Days * bulkMsPerDay
		if expiry > 0 {
			expiry += ms
		} else if expiry < 0 {
			expiry -= ms
		} else {
			expiry = now + ms
		}
		cm["expiryTime"] = expiry
	case "subDays":
		if expiry == 0 {
			return false // nothing to shorten on a no-expiry account
		}
		ms := req.Days * bulkMsPerDay
		if expiry > 0 {
			expiry -= ms
		} else { // delayed start: shrink the delay, clamped at 0
			expiry += ms
			if expiry > 0 {
				expiry = 0
			}
		}
		cm["expiryTime"] = expiry
	case "addTraffic":
		cm["totalGB"] = total + req.AmountBytes
	case "subTraffic":
		if total <= 0 {
			return false // unlimited: nothing to subtract
		}
		total -= req.AmountBytes
		if total < 1 {
			total = 1
		}
		cm["totalGB"] = total
	case "enable":
		if enable {
			return false
		}
		cm["enable"] = true
	case "disable":
		if !enable {
			return false
		}
		cm["enable"] = false
	}
	return true
}

func (s *InboundService) AddTraffic(inboundTraffics []*xray.Traffic, clientTraffics []*xray.ClientTraffic) (error, bool, []string, []string, []string) {
	var err error
	db := database.GetDB()
	tx := db.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()
	err = s.addInboundTraffic(tx, inboundTraffics)
	if err != nil {
		return err, false, nil, nil, nil
	}
	err = s.addClientTraffic(tx, clientTraffics)
	if err != nil {
		return err, false, nil, nil, nil
	}

	needRestart0, count, err := s.autoRenewClients(tx)
	if err != nil {
		logger.Warning("Error in renew clients:", err)
	} else if count > 0 {
		logger.Debugf("%v clients renewed", count)
	}

	needRestart1, count, l2tpDisabledEmails, pptpDisabledEmails, ovpnDisabledEmails, err := s.disableInvalidClients(tx)
	if err != nil {
		logger.Warning("Error in disabling invalid clients:", err)
	} else if count > 0 {
		logger.Debugf("%v clients disabled", count)
	}

	needRestart2, count, err := s.disableInvalidInbounds(tx)
	if err != nil {
		logger.Warning("Error in disabling invalid inbounds:", err)
	} else if count > 0 {
		logger.Debugf("%v inbounds disabled", count)
	}
	return nil, (needRestart0 || needRestart1 || needRestart2), l2tpDisabledEmails, pptpDisabledEmails, ovpnDisabledEmails
}

func (s *InboundService) addInboundTraffic(tx *gorm.DB, traffics []*xray.Traffic) error {
	if len(traffics) == 0 {
		return nil
	}

	var err error

	for _, traffic := range traffics {
		if traffic.IsInbound {
			err = tx.Model(&model.Inbound{}).Where("tag = ?", traffic.Tag).
				Updates(map[string]any{
					"up":       gorm.Expr("up + ?", traffic.Up),
					"down":     gorm.Expr("down + ?", traffic.Down),
					"all_time": gorm.Expr("COALESCE(all_time, 0) + ?", traffic.Up+traffic.Down),
				}).Error
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *InboundService) addClientTraffic(tx *gorm.DB, traffics []*xray.ClientTraffic) (err error) {
	if len(traffics) == 0 {
		// Empty onlineUsers
		if p != nil {
			p.SetOnlineClients(make([]string, 0))
			p.SetOnlineMarks(make([]xray.OnlineMark, 0))
		}
		return nil
	}

	onlineClients := make([]string, 0)

	// Inbound attribution per email. The VPN daemons and the relays stamp the
	// inbound a record came from; Xray-native counters cannot, so those fall
	// through to access-log hints and then to the home inbound (see below).
	srcInboundByEmail := make(map[string][]int)
	for _, t := range traffics {
		if t.InboundId > 0 && t.Email != "" && !slices.Contains(srcInboundByEmail[t.Email], t.InboundId) {
			srcInboundByEmail[t.Email] = append(srcInboundByEmail[t.Email], t.InboundId)
		}
	}

	type movedRow struct {
		email  string
		homeId int
	}
	movedRows := make([]movedRow, 0, 8)

	emails := make([]string, 0, len(traffics))
	for _, traffic := range traffics {
		emails = append(emails, traffic.Email)
	}
	dbClientTraffics := make([]*xray.ClientTraffic, 0, len(traffics))
	err = tx.Model(xray.ClientTraffic{}).Where("email IN (?)", emails).Find(&dbClientTraffics).Error
	if err != nil {
		return err
	}

	// Avoid empty slice error
	if len(dbClientTraffics) == 0 {
		return nil
	}

	dbClientTraffics, err = s.adjustTraffics(tx, dbClientTraffics)
	if err != nil {
		return err
	}

	// Inbounds for the traffic-multiplier policy. Two id sources plus, ONLY when it
	// is actually needed, the account's memberships: the inbound that BILLS a byte
	// is no longer necessarily the one on the client's row, since a collected
	// record may name the inbound it really came from and an account can be a
	// member of several. A failure here must not cost us the tick's traffic, so it
	// falls back to billing everything 1:1.
	homeIds := make([]int, 0, len(dbClientTraffics))
	for _, ct := range dbClientTraffics {
		homeIds = append(homeIds, ct.InboundId)
	}
	sourceIds := make([]int, 0, len(traffics))
	unattributed := false
	for _, t := range traffics {
		sourceIds = append(sourceIds, t.InboundId)
		if t.InboundId == 0 {
			unattributed = true
		}
	}

	multiplierInbounds, err := loadMultiplierInbounds(tx, homeIds, sourceIds)
	if err != nil {
		logger.Warning("traffic multiplier: cannot load inbounds, counting raw: ", err)
		multiplierInbounds = nil
	}
	if multiplierInbounds == nil {
		// loadMultiplierInbounds returns nil both on error and when there was
		// nothing to load, and the merge below writes into this map. Writing to a
		// nil map panics, and it would take the whole 10s traffic job down.
		multiplierInbounds = map[int]*model.Inbound{}
	}

	// Resolving memberships means scanning every inbound's settings JSON, and this
	// runs every 10 seconds on a panel that can hold thousands of accounts. It is
	// therefore done ONLY when it can change an answer: when some record could not
	// be attributed to a source inbound AND some inbound actually has a multiplier
	// enabled. On the overwhelmingly common panel (no multiplier configured at all)
	// this is skipped entirely and the tick costs exactly what it did before.
	memberIdsByEmail := map[string][]int{}
	if unattributed && anyMultiplierEnabled(tx) {
		billedEmails := make([]string, 0, len(dbClientTraffics))
		for _, ct := range dbClientTraffics {
			billedEmails = append(billedEmails, ct.Email)
		}
		memberRows, merr := s.inboundsServingEmails(tx, billedEmails)
		if merr != nil {
			logger.Warning("traffic multiplier: cannot resolve memberships, using the home inbound: ", merr)
		}
		memberIds := make([]int, 0, len(memberRows))
		for _, row := range memberRows {
			memberIds = append(memberIds, row.Id)
			key := accountKey(row.Email)
			memberIdsByEmail[key] = append(memberIdsByEmail[key], row.Id)
		}
		// Second pass now that the membership ids are known: those inbounds' own
		// multiplier columns still have to be loaded to be compared.
		if extra, eerr := loadMultiplierInbounds(tx, memberIds); eerr == nil {
			for id, inb := range extra {
				multiplierInbounds[id] = inb
			}
		}
	}

	// Every record matching an email is applied, not just the first. A tick can legitimately
	// carry more than one record for an account (a client billed under two protocols, or a
	// relay reporting alongside Xray), and stopping at the first silently threw the rest
	// away: the bytes were collected, the source counter was reset, and nobody was charged.
	// Callers that must not double-report the same bytes de-duplicate before they get here
	// (see the relay handling in web/job/xray_traffic_job.go).
	for dbTraffic_index := range dbClientTraffics {
		moved := int64(0)
		for traffic_index := range traffics {
			if dbClientTraffics[dbTraffic_index].Email == traffics[traffic_index].Email {
				rawUp := traffics[traffic_index].Up
				rawDown := traffics[traffic_index].Down
				// Bill at the multiplier of the inbound the bytes CAME FROM, which
				// the collector stamps on the record when it can be known (the nine
				// pool VPN protocols count per tunnel address, the two relays count
				// per account inside one daemon). When it cannot be known, the max
				// across the account's memberships is used, so the ambiguity can only
				// over-bill and never hand out free traffic.
				//
				// It genuinely cannot be known for the Xray-native protocols, and
				// that is a property of the core rather than something this code can
				// plumb: Xray's counter is named "user>>><email>>>>traffic" with NO
				// inbound component, so an account on vless AND trojan gets one number
				// covering both, with nothing to attribute it by.
				source := billingInbound(
					multiplierInbounds,
					traffics[traffic_index].InboundId,
					memberIdsByEmail[accountKey(dbClientTraffics[dbTraffic_index].Email)],
				)
				// Weight the delta against the client's quota. Computed rather than
				// mutated in place: the same slice is broadcast over the websocket and
				// posted to the external traffic API, which must report measured bytes.
				billedUp, billedDown := multiplyDelta(
					source,
					dbClientTraffics[dbTraffic_index].Up+dbClientTraffics[dbTraffic_index].Down,
					rawUp, rawDown,
				)
				dbClientTraffics[dbTraffic_index].Up += billedUp
				dbClientTraffics[dbTraffic_index].Down += billedDown
				// AllTime stays raw: it's the lifetime record of bytes actually moved,
				// and survives the resets that up/down don't.
				dbClientTraffics[dbTraffic_index].AllTime += (rawUp + rawDown)
				moved += rawUp + rawDown
			}
		}
		// Online is a property of the client, not of each record: marked once here so a
		// client carrying two records in one tick is not listed twice.
		if moved > 0 {
			onlineClients = append(onlineClients, dbClientTraffics[dbTraffic_index].Email)
			movedRows = append(movedRows, movedRow{
				email:  dbClientTraffics[dbTraffic_index].Email,
				homeId: dbClientTraffics[dbTraffic_index].InboundId,
			})
			dbClientTraffics[dbTraffic_index].LastOnline = time.Now().UnixMilli()
		}
	}

	// Per-inbound online marks. A panel-wide email list lights up EVERY inbound
	// sharing an account the moment one of them moves a byte; these marks carry
	// which inbound the bytes really came through, best signal first: a stamped
	// source inbound (VPN daemons, relays), then fresh access-log observations
	// (the only per-inbound signal Xray-native protocols expose), then the home
	// inbound as a stand-in that degrades to the old behaviour instead of
	// inventing a worse answer.
	nowSec := time.Now().Unix()
	var tagToId map[string]int
	for _, row := range movedRows {
		if len(srcInboundByEmail[row.email]) == 0 && len(xray.RecentOnlineSources(row.email, nowSec, xray.OnlineSourceTTL)) > 0 {
			tagToId = s.inboundTagIdMap(tx)
			break
		}
	}
	onlineMarks := make([]xray.OnlineMark, 0, len(movedRows))
	for _, row := range movedRows {
		ids := srcInboundByEmail[row.email]
		if len(ids) == 0 {
			for _, tag := range xray.RecentOnlineSources(row.email, nowSec, xray.OnlineSourceTTL) {
				if id, ok := tagToId[tag]; ok && !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		if len(ids) == 0 {
			ids = []int{row.homeId}
		}
		for _, id := range ids {
			onlineMarks = append(onlineMarks, xray.OnlineMark{InboundId: id, Email: row.email})
		}
	}

	// Set onlineUsers. Nil-checked like the empty-traffics path above: the VPN
	// protocols report traffic through this same tick even when Xray never started,
	// and an unguarded call there takes the whole traffic job down.
	if p != nil {
		p.SetOnlineClients(onlineClients)
		p.SetOnlineMarks(xray.DedupMarks(onlineMarks))
	}

	err = tx.Save(dbClientTraffics).Error
	if err != nil {
		logger.Warning("AddClientTraffic update data ", err)
	}

	return nil
}

func (s *InboundService) adjustTraffics(tx *gorm.DB, dbClientTraffics []*xray.ClientTraffic) ([]*xray.ClientTraffic, error) {
	// Which ACCOUNTS are converting a "N days from first use" expiry into an
	// absolute deadline, and then every inbound serving them.
	//
	// This used to collect inbound ids from dbClientTraffic.InboundId, which names
	// only the account's home inbound. The absolute deadline was therefore written
	// into that one inbound's settings while every other member kept the NEGATIVE
	// value forever, which the client table renders as "delayed start" on an
	// account whose clock has actually been running since its first connection.
	pendingEmails := make([]string, 0, len(dbClientTraffics))
	for _, dbClientTraffic := range dbClientTraffics {
		if dbClientTraffic.ExpiryTime < 0 {
			pendingEmails = append(pendingEmails, dbClientTraffic.Email)
		}
	}

	if len(pendingEmails) > 0 {
		inboundIds, err := s.inboundIdsServingEmails(tx, pendingEmails)
		if err != nil {
			return nil, err
		}
		if len(inboundIds) == 0 {
			return dbClientTraffics, nil
		}
		var inbounds []*model.Inbound
		err = tx.Model(model.Inbound{}).Where("id IN (?)", inboundIds).Find(&inbounds).Error
		if err != nil {
			return nil, err
		}
		// The deadline is computed ONCE PER ACCOUNT, before any inbound is
		// rewritten, and read from the traffic row rather than from each inbound's
		// settings. Both details matter now that an account can be on several
		// inbounds: computing it inside the loop would convert the first inbound,
		// flip the row positive, and then skip every remaining member (leaving
		// exactly the negative values this fix exists to remove), and taking the
		// base from each inbound's own JSON would give one account a different
		// deadline per inbound.
		now := time.Now().Unix() * 1000
		newExpiryByEmail := make(map[string]int64, len(pendingEmails))
		for traffic_index := range dbClientTraffics {
			if dbClientTraffics[traffic_index].ExpiryTime >= 0 {
				continue
			}
			// The stored value is negative and means "this many ms from first use".
			newExpiry := now - dbClientTraffics[traffic_index].ExpiryTime
			newExpiryByEmail[accountKey(dbClientTraffics[traffic_index].Email)] = newExpiry
			dbClientTraffics[traffic_index].ExpiryTime = newExpiry
		}

		for inbound_index := range inbounds {
			settings := map[string]any{}
			json.Unmarshal([]byte(inbounds[inbound_index].Settings), &settings)
			clients, ok := settings["clients"].([]any)
			if ok {
				var newClients []any
				for client_index := range clients {
					c, ok := clients[client_index].(map[string]any)
					if !ok {
						newClients = append(newClients, clients[client_index])
						continue
					}
					email, _ := c["email"].(string)
					if newExpiry, converting := newExpiryByEmail[accountKey(email)]; converting {
						c["expiryTime"] = newExpiry
					}
					// Backfill created_at and updated_at
					if _, ok := c["created_at"]; !ok {
						c["created_at"] = now
					}
					c["updated_at"] = now
					newClients = append(newClients, any(c))
				}
				settings["clients"] = newClients
				modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
				if err != nil {
					return nil, err
				}

				inbounds[inbound_index].Settings = string(modifiedSettings)
			}
		}
		err = tx.Save(inbounds).Error
		if err != nil {
			logger.Warning("AddClientTraffic update inbounds ", err)
			logger.Error(inbounds)
		}
	}

	return dbClientTraffics, nil
}

func (s *InboundService) autoRenewClients(tx *gorm.DB) (bool, int64, error) {
	// check for time expired
	var traffics []*xray.ClientTraffic
	now := time.Now().Unix() * 1000
	var err, err1 error

	err = tx.Model(xray.ClientTraffic{}).Where("reset > 0 and expiry_time > 0 and expiry_time <= ?", now).Find(&traffics).Error
	if err != nil {
		return false, 0, err
	}
	// return if there is no client to renew
	if len(traffics) == 0 {
		return false, 0, nil
	}

	var inbound_ids []int
	var inbounds []*model.Inbound
	needRestart := false
	var clientsToAdd []struct {
		protocol string
		tag      string
		client   map[string]any
	}

	// Every inbound serving a renewing account, not just the one its traffic row
	// names. Renewing on the home inbound alone left the other members holding the
	// OLD, already-passed expiry in their settings, so the account read as expired
	// wherever it had actually been renewed.
	renewEmails := make([]string, 0, len(traffics))
	for _, traffic := range traffics {
		renewEmails = append(renewEmails, traffic.Email)
	}
	inbound_ids, err = s.inboundIdsServingEmails(tx, renewEmails)
	if err != nil {
		return false, 0, err
	}
	if len(inbound_ids) == 0 {
		return false, 0, nil
	}
	err = tx.Model(model.Inbound{}).Where("id IN ?", inbound_ids).Find(&inbounds).Error
	if err != nil {
		return false, 0, err
	}

	// One new deadline per ACCOUNT, computed before any inbound is touched, so
	// every membership lands on the same date and a second inbound cannot
	// re-advance a deadline the first already moved.
	renewedByEmail := make(map[string]int64, len(traffics))
	// Whether the account was disabled BEFORE this renewal, captured up front.
	// Read inside the inbound loop instead, the first membership would flip the
	// flag to true and every later membership would then look "already enabled",
	// so the account would be re-added to one inbound's tag and silently left out
	// of the rest.
	wasDisabled := make(map[string]bool, len(traffics))
	for traffic_index, traffic := range traffics {
		newExpiryTime := traffic.ExpiryTime
		for newExpiryTime < now {
			newExpiryTime += (int64(traffic.Reset) * 86400000)
		}
		renewedByEmail[accountKey(traffic.Email)] = newExpiryTime
		wasDisabled[accountKey(traffic.Email)] = !traffic.Enable
		traffics[traffic_index].ExpiryTime = newExpiryTime
		traffics[traffic_index].Down = 0
		traffics[traffic_index].Up = 0
		traffics[traffic_index].Enable = true
	}

	for inbound_index := range inbounds {
		settings := map[string]any{}
		json.Unmarshal([]byte(inbounds[inbound_index].Settings), &settings)
		clients, ok := settings["clients"].([]any)
		if !ok {
			continue
		}
		for client_index := range clients {
			c, ok := clients[client_index].(map[string]any)
			if !ok {
				continue
			}
			email, _ := c["email"].(string)
			newExpiryTime, renewing := renewedByEmail[accountKey(email)]
			if !renewing {
				continue
			}
			c["expiryTime"] = newExpiryTime
			if wasDisabled[accountKey(email)] {
				// One entry per MEMBERSHIP: the account has to be re-added to
				// every inbound tag it serves on, not just to one of them.
				clientsToAdd = append(clientsToAdd,
					struct {
						protocol string
						tag      string
						client   map[string]any
					}{
						protocol: string(inbounds[inbound_index].Protocol),
						tag:      inbounds[inbound_index].Tag,
						client:   c,
					})
			}
			clients[client_index] = any(c)
		}
		settings["clients"] = clients
		newSettings, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return false, 0, err
		}
		inbounds[inbound_index].Settings = string(newSettings)
	}
	err = tx.Save(inbounds).Error
	if err != nil {
		return false, 0, err
	}
	// Write ONLY the columns a renewal owns. tx.Save would write the whole row back from
	// the copy read at the top of this function, silently rolling back anything the 10s
	// accounting job committed in between -- most damagingly all_time, the lifetime byte
	// record that deliberately survives resets, and last_online. Traffic going BACKWARDS
	// on an account is exactly what that looks like from the panel.
	for _, t := range traffics {
		err = tx.Model(xray.ClientTraffic{}).Where("id = ?", t.Id).Updates(map[string]any{
			"expiry_time": t.ExpiryTime,
			"up":          0,
			"down":        0,
			"enable":      t.Enable,
		}).Error
		if err != nil {
			return false, 0, err
		}
	}
	if p != nil {
		err1 = s.xrayApi.Init(p.GetAPIPort())
		if err1 != nil {
			return true, int64(len(traffics)), nil
		}
		for _, clientToAdd := range clientsToAdd {
			err1 = s.xrayApi.AddUser(clientToAdd.protocol, clientToAdd.tag, clientToAdd.client)
			if err1 != nil {
				needRestart = true
			}
		}
		s.xrayApi.Close()
	}
	return needRestart, int64(len(traffics)), nil
}

func (s *InboundService) disableInvalidInbounds(tx *gorm.DB) (bool, int64, error) {
	now := time.Now().Unix() * 1000
	needRestart := false

	if p != nil {
		var tags []string
		err := tx.Table("inbounds").
			Select("inbounds.tag").
			Where("((total > 0 and up + down >= total) or (expiry_time > 0 and expiry_time <= ?)) and enable = ?", now, true).
			Scan(&tags).Error
		if err != nil {
			return false, 0, err
		}
		s.xrayApi.Init(p.GetAPIPort())
		for _, tag := range tags {
			err1 := s.xrayApi.DelInbound(tag)
			if err1 == nil {
				logger.Debug("Inbound disabled by api:", tag)
			} else {
				logger.Debug("Error in disabling inbound by api:", err1)
				needRestart = true
			}
		}
		s.xrayApi.Close()
	}

	result := tx.Model(model.Inbound{}).
		Where("((total > 0 and up + down >= total) or (expiry_time > 0 and expiry_time <= ?)) and enable = ?", now, true).
		Update("enable", false)
	err := result.Error
	count := result.RowsAffected
	return needRestart, count, err
}

func (s *InboundService) disableInvalidClients(tx *gorm.DB) (bool, int64, []string, []string, []string, error) {
	now := time.Now().Unix() * 1000
	needRestart := false
	var l2tpDisabledEmails []string
	var pptpDisabledEmails []string
	var ovpnDisabledEmails []string

	if p != nil {
		// Which accounts are depleted, and then SEPARATELY which inbounds each of
		// them is served on.
		//
		// This used to be one query joining inbounds to client_traffics on
		// inbound_id. That join can only ever return ONE row per account, because
		// client_traffics.Email is unique panel-wide and its inbound_id names a
		// single inbound. So RemoveUser fired for exactly one tag and an account
		// that had exhausted its quota kept passing traffic on every other inbound
		// serving it, while still billing into the same row: up+down grows past
		// total forever with enable already false. Free traffic, silently.
		var depletedEmails []string
		err := tx.Model(xray.ClientTraffic{}).
			Where("((total > 0 AND up + down >= total) OR (expiry_time > 0 AND expiry_time <= ?)) AND enable = ?", now, true).
			Pluck("email", &depletedEmails).Error
		if err != nil {
			return false, 0, nil, nil, nil, err
		}

		results, err := s.inboundsServingEmails(tx, depletedEmails)
		if err != nil {
			return false, 0, nil, nil, nil, err
		}
		s.xrayApi.Init(p.GetAPIPort())
		for _, result := range results {
			if result.Protocol == "l2tp" {
				l2tpDisabledEmails = append(l2tpDisabledEmails, result.Email)
				continue
			}
			if result.Protocol == "pptp" {
				pptpDisabledEmails = append(pptpDisabledEmails, result.Email)
				continue
			}
			if result.Protocol == "openvpn" {
				ovpnDisabledEmails = append(ovpnDisabledEmails, result.Email)
				continue
			}
			err1 := s.xrayApi.RemoveUser(result.Tag, result.Email)
			if err1 == nil {
				logger.Debug("Client disabled by api:", result.Email)
			} else {
				if strings.Contains(err1.Error(), fmt.Sprintf("User %s not found.", result.Email)) {
					logger.Debug("User is already disabled. Nothing to do more...")
				} else {
					if strings.Contains(err1.Error(), fmt.Sprintf("User %s not found.", result.Email)) {
						logger.Debug("User is already disabled. Nothing to do more...")
					} else {
						logger.Debug("Error in disabling client by api:", err1)
						needRestart = true
					}
				}
			}
		}
		s.xrayApi.Close()
	}
	result := tx.Model(xray.ClientTraffic{}).
		Where("((total > 0 and up + down >= total) or (expiry_time > 0 and expiry_time <= ?)) and enable = ?", now, true).
		Update("enable", false)
	err := result.Error
	count := result.RowsAffected
	return needRestart, count, l2tpDisabledEmails, pptpDisabledEmails, ovpnDisabledEmails, err
}

// inboundServingEmail is one (account, inbound) pair the enforcement paths have
// to act on: an account is disabled on EVERY inbound serving it, not just on the
// one its client_traffics row happens to name.
type inboundServingEmail struct {
	Id       int
	Tag      string
	Email    string
	Protocol string
}

// inboundIdsServingEmails is inboundsServingEmails reduced to distinct inbound
// ids, for the paths that rewrite settings rather than call the Xray API.
func (s *InboundService) inboundIdsServingEmails(tx *gorm.DB, emails []string) ([]int, error) {
	rows, err := s.inboundsServingEmails(tx, emails)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	out := make([]int, 0, len(rows))
	for _, row := range rows {
		if seen[row.Id] {
			continue
		}
		seen[row.Id] = true
		out = append(out, row.Id)
	}
	return out, nil
}

// inboundsServingEmails resolves emails to every inbound that actually serves
// them, by reading settings.clients.
//
// settings.clients is used rather than the account_inbounds table on purpose:
// it is the source of truth in BOTH worlds, so this is correct before the
// accounts migration has run, after it, and on an inbound added by an older
// binary in between. An enforcement path is the last place that should depend
// on a backfill having completed.
func (s *InboundService) inboundsServingEmails(tx *gorm.DB, emails []string) ([]inboundServingEmail, error) {
	if len(emails) == 0 {
		return nil, nil
	}
	wanted := make(map[string]string, len(emails))
	for _, email := range emails {
		// Keyed on the normalized form, valued with the original, because the
		// original is what RemoveUser and the RADIUS-side disable lists must carry.
		wanted[accountKey(email)] = email
	}

	var inbounds []*model.Inbound
	if err := tx.Model(&model.Inbound{}).
		Select("id", "tag", "protocol", "settings").
		Order("id ASC").Find(&inbounds).Error; err != nil {
		return nil, err
	}

	var out []inboundServingEmail
	for _, inbound := range inbounds {
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		for _, entry := range clients {
			entryEmail, _ := entry["email"].(string)
			original, hit := wanted[accountKey(entryEmail)]
			if !hit {
				continue
			}
			out = append(out, inboundServingEmail{
				Id:       inbound.Id,
				Tag:      inbound.Tag,
				Email:    original,
				Protocol: string(inbound.Protocol),
			})
		}
	}
	return out, nil
}

// SingleInboundIdByEmail maps each account served by a protocol to the inbound
// serving it, keyed by normalized email, for the traffic collectors to stamp the
// SOURCE of the bytes they report.
//
// An email served by TWO inbounds of the same protocol is deliberately mapped to
// 0 rather than to either of them. Zero means "source unknown", which makes the
// billing take the max across the account's memberships: over-billing a rare,
// genuinely ambiguous case is the safe direction, where guessing one of the two
// would silently bill half a customer's traffic at the wrong rate.
//
// This is only reachable for openvpn, openconnect and sstp; l2tp, pptp and ikev2
// refuse a second same-protocol membership outright (see ValidateMembershipSet).
func (s *InboundService) SingleInboundIdByEmail(protocol string) map[string]int {
	var inbounds []*model.Inbound
	if err := database.GetDB().Model(&model.Inbound{}).
		Select("id", "protocol", "settings").
		Where("protocol = ? AND enable = ?", protocol, true).
		Find(&inbounds).Error; err != nil {
		logger.Warning("resolving the traffic source inbound for ", protocol, ": ", err)
		return nil
	}

	out := map[string]int{}
	seen := map[string]bool{}
	for _, inbound := range inbounds {
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			key := accountKey(email)
			if key == "" {
				continue
			}
			if seen[key] {
				out[key] = 0 // ambiguous: two inbounds of this protocol serve it
				continue
			}
			seen[key] = true
			out[key] = inbound.Id
		}
	}
	return out
}

// EnableStateByEmail returns every account's enable state, keyed by normalized
// email. Panel-wide and NOT scoped to an inbound: depletion is a property of the
// account, and one account can be served on many inbounds.
func (s *InboundService) EnableStateByEmail() (map[string]bool, error) {
	var rows []xray.ClientTraffic
	if err := database.GetDB().Model(xray.ClientTraffic{}).
		Select("email", "enable").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(rows))
	for _, row := range rows {
		out[accountKey(row.Email)] = row.Enable
	}
	return out, nil
}

func (s *InboundService) GetInboundTags() (string, error) {
	db := database.GetDB()
	var inboundTags []string
	err := db.Model(model.Inbound{}).Select("tag").Find(&inboundTags).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return "", err
	}
	tags, _ := json.Marshal(inboundTags)
	return string(tags), nil
}

func (s *InboundService) MigrationRemoveOrphanedTraffics() {
	db := database.GetDB()
	db.Exec(`
		DELETE FROM client_traffics
		WHERE email NOT IN (
			SELECT JSON_EXTRACT(client.value, '$.email')
			FROM inbounds,
				JSON_EACH(JSON_EXTRACT(inbounds.settings, '$.clients')) AS client
		)
	`)
}

func (s *InboundService) AddClientStat(tx *gorm.DB, inboundId int, client *model.Client) error {
	clientTraffic := xray.ClientTraffic{}
	clientTraffic.InboundId = inboundId
	clientTraffic.Email = client.Email
	clientTraffic.Total = client.TotalGB
	clientTraffic.ExpiryTime = client.ExpiryTime
	clientTraffic.Enable = client.Enable
	clientTraffic.Up = 0
	clientTraffic.Down = 0
	clientTraffic.Reset = client.Reset
	result := tx.Create(&clientTraffic)
	err := result.Error
	return err
}

func (s *InboundService) UpdateClientStat(tx *gorm.DB, email string, client *model.Client) error {
	result := tx.Model(xray.ClientTraffic{}).
		Where("email = ?", email).
		Updates(map[string]any{
			"enable":      client.Enable,
			"email":       client.Email,
			"total":       client.TotalGB,
			"expiry_time": client.ExpiryTime,
			"reset":       client.Reset,
		})
	err := result.Error
	return err
}

func (s *InboundService) UpdateClientIPs(tx *gorm.DB, oldEmail string, newEmail string) error {
	return tx.Model(model.InboundClientIps{}).Where("client_email = ?", oldEmail).Update("client_email", newEmail).Error
}

func (s *InboundService) DelClientStat(tx *gorm.DB, email string) error {
	return tx.Where("email = ?", email).Delete(xray.ClientTraffic{}).Error
}

func (s *InboundService) DelClientIPs(tx *gorm.DB, email string) error {
	return tx.Where("client_email = ?", email).Delete(model.InboundClientIps{}).Error
}

func (s *InboundService) GetClientInboundByTrafficID(trafficId int) (traffic *xray.ClientTraffic, inbound *model.Inbound, err error) {
	db := database.GetDB()
	var traffics []*xray.ClientTraffic
	err = db.Model(xray.ClientTraffic{}).Where("id = ?", trafficId).Find(&traffics).Error
	if err != nil {
		logger.Warningf("Error retrieving ClientTraffic with trafficId %d: %v", trafficId, err)
		return nil, nil, err
	}
	if len(traffics) > 0 {
		inbound, err = s.GetInbound(traffics[0].InboundId)
		return traffics[0], inbound, err
	}
	return nil, nil, nil
}

func (s *InboundService) GetClientInboundByEmail(email string) (traffic *xray.ClientTraffic, inbound *model.Inbound, err error) {
	db := database.GetDB()
	var traffics []*xray.ClientTraffic
	err = db.Model(xray.ClientTraffic{}).Where("email = ?", email).Find(&traffics).Error
	if err != nil {
		logger.Warningf("Error retrieving ClientTraffic with email %s: %v", email, err)
		return nil, nil, err
	}
	if len(traffics) > 0 {
		inbound, err = s.GetInbound(traffics[0].InboundId)
		return traffics[0], inbound, err
	}
	return nil, nil, nil
}

func (s *InboundService) GetClientByEmail(clientEmail string) (*xray.ClientTraffic, *model.Client, error) {
	traffic, inbound, err := s.GetClientInboundByEmail(clientEmail)
	if err != nil {
		return nil, nil, err
	}
	if inbound == nil {
		return nil, nil, common.NewError("Inbound Not Found For Email:", clientEmail)
	}

	clients, err := s.GetClients(inbound)
	if err != nil {
		return nil, nil, err
	}

	for _, client := range clients {
		if client.Email == clientEmail {
			return traffic, &client, nil
		}
	}

	return nil, nil, common.NewError("Client Not Found In Inbound For Email:", clientEmail)
}

func (s *InboundService) SetClientTelegramUserID(trafficId int, tgId int64) (bool, error) {
	traffic, inbound, err := s.GetClientInboundByTrafficID(trafficId)
	if err != nil {
		return false, err
	}
	if inbound == nil {
		return false, common.NewError("Inbound Not Found For Traffic ID:", trafficId)
	}

	clientEmail := traffic.Email

	oldClients, err := s.GetClients(inbound)
	if err != nil {
		return false, err
	}

	clientId := ""

	for _, oldClient := range oldClients {
		if oldClient.Email == clientEmail {
			clientId = clientIdentity(inbound.Protocol, oldClient)
			break
		}
	}

	if len(clientId) == 0 {
		return false, common.NewError("Client Not Found For Email:", clientEmail)
	}

	var settings map[string]any
	err = json.Unmarshal([]byte(inbound.Settings), &settings)
	if err != nil {
		return false, err
	}
	clients := settings["clients"].([]any)
	var newClients []any
	for client_index := range clients {
		c := clients[client_index].(map[string]any)
		if c["email"] == clientEmail {
			c["tgId"] = tgId
			c["updated_at"] = time.Now().Unix() * 1000
			newClients = append(newClients, any(c))
		}
	}
	settings["clients"] = newClients
	modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}
	inbound.Settings = string(modifiedSettings)
	needRestart, err := s.UpdateInboundClient(inbound, clientId)
	return needRestart, err
}

func (s *InboundService) checkIsEnabledByEmail(clientEmail string) (bool, error) {
	_, inbound, err := s.GetClientInboundByEmail(clientEmail)
	if err != nil {
		return false, err
	}
	if inbound == nil {
		return false, common.NewError("Inbound Not Found For Email:", clientEmail)
	}

	clients, err := s.GetClients(inbound)
	if err != nil {
		return false, err
	}

	isEnable := false

	for _, client := range clients {
		if client.Email == clientEmail {
			isEnable = client.Enable
			break
		}
	}

	return isEnable, err
}

func (s *InboundService) ToggleClientEnableByEmail(clientEmail string) (bool, bool, error) {
	_, inbound, err := s.GetClientInboundByEmail(clientEmail)
	if err != nil {
		return false, false, err
	}
	if inbound == nil {
		return false, false, common.NewError("Inbound Not Found For Email:", clientEmail)
	}

	oldClients, err := s.GetClients(inbound)
	if err != nil {
		return false, false, err
	}

	clientId := ""
	clientOldEnabled := false

	for _, oldClient := range oldClients {
		if oldClient.Email == clientEmail {
			clientId = clientIdentity(inbound.Protocol, oldClient)
			clientOldEnabled = oldClient.Enable
			break
		}
	}

	if len(clientId) == 0 {
		return false, false, common.NewError("Client Not Found For Email:", clientEmail)
	}

	var settings map[string]any
	err = json.Unmarshal([]byte(inbound.Settings), &settings)
	if err != nil {
		return false, false, err
	}
	clients := settings["clients"].([]any)
	var newClients []any
	for client_index := range clients {
		c := clients[client_index].(map[string]any)
		if c["email"] == clientEmail {
			c["enable"] = !clientOldEnabled
			c["updated_at"] = time.Now().Unix() * 1000
			newClients = append(newClients, any(c))
		}
	}
	settings["clients"] = newClients
	modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, false, err
	}
	inbound.Settings = string(modifiedSettings)

	needRestart, err := s.UpdateInboundClient(inbound, clientId)
	if err != nil {
		return false, needRestart, err
	}

	return !clientOldEnabled, needRestart, nil
}

// SetClientEnableByEmail sets client enable state to desired value; returns (changed, needRestart, error)
func (s *InboundService) SetClientEnableByEmail(clientEmail string, enable bool) (bool, bool, error) {
	current, err := s.checkIsEnabledByEmail(clientEmail)
	if err != nil {
		return false, false, err
	}
	if current == enable {
		return false, false, nil
	}
	newEnabled, needRestart, err := s.ToggleClientEnableByEmail(clientEmail)
	if err != nil {
		return false, needRestart, err
	}
	return newEnabled == enable, needRestart, nil
}

func (s *InboundService) ResetClientIpLimitByEmail(clientEmail string, count int) (bool, error) {
	_, inbound, err := s.GetClientInboundByEmail(clientEmail)
	if err != nil {
		return false, err
	}
	if inbound == nil {
		return false, common.NewError("Inbound Not Found For Email:", clientEmail)
	}

	oldClients, err := s.GetClients(inbound)
	if err != nil {
		return false, err
	}

	clientId := ""

	for _, oldClient := range oldClients {
		if oldClient.Email == clientEmail {
			clientId = clientIdentity(inbound.Protocol, oldClient)
			break
		}
	}

	if len(clientId) == 0 {
		return false, common.NewError("Client Not Found For Email:", clientEmail)
	}

	var settings map[string]any
	err = json.Unmarshal([]byte(inbound.Settings), &settings)
	if err != nil {
		return false, err
	}
	clients := settings["clients"].([]any)
	var newClients []any
	for client_index := range clients {
		c := clients[client_index].(map[string]any)
		if c["email"] == clientEmail {
			c["limitIp"] = count
			c["updated_at"] = time.Now().Unix() * 1000
			newClients = append(newClients, any(c))
		}
	}
	settings["clients"] = newClients
	modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}
	inbound.Settings = string(modifiedSettings)
	needRestart, err := s.UpdateInboundClient(inbound, clientId)
	return needRestart, err
}

func (s *InboundService) ResetClientExpiryTimeByEmail(clientEmail string, expiry_time int64) (bool, error) {
	_, inbound, err := s.GetClientInboundByEmail(clientEmail)
	if err != nil {
		return false, err
	}
	if inbound == nil {
		return false, common.NewError("Inbound Not Found For Email:", clientEmail)
	}

	oldClients, err := s.GetClients(inbound)
	if err != nil {
		return false, err
	}

	clientId := ""

	for _, oldClient := range oldClients {
		if oldClient.Email == clientEmail {
			clientId = clientIdentity(inbound.Protocol, oldClient)
			break
		}
	}

	if len(clientId) == 0 {
		return false, common.NewError("Client Not Found For Email:", clientEmail)
	}

	var settings map[string]any
	err = json.Unmarshal([]byte(inbound.Settings), &settings)
	if err != nil {
		return false, err
	}
	clients := settings["clients"].([]any)
	var newClients []any
	for client_index := range clients {
		c := clients[client_index].(map[string]any)
		if c["email"] == clientEmail {
			c["expiryTime"] = expiry_time
			c["updated_at"] = time.Now().Unix() * 1000
			newClients = append(newClients, any(c))
		}
	}
	settings["clients"] = newClients
	modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}
	inbound.Settings = string(modifiedSettings)
	needRestart, err := s.UpdateInboundClient(inbound, clientId)
	return needRestart, err
}

func (s *InboundService) ResetClientTrafficLimitByEmail(clientEmail string, totalGB int) (bool, error) {
	if totalGB < 0 {
		return false, common.NewError("totalGB must be >= 0")
	}
	_, inbound, err := s.GetClientInboundByEmail(clientEmail)
	if err != nil {
		return false, err
	}
	if inbound == nil {
		return false, common.NewError("Inbound Not Found For Email:", clientEmail)
	}

	oldClients, err := s.GetClients(inbound)
	if err != nil {
		return false, err
	}

	clientId := ""

	for _, oldClient := range oldClients {
		if oldClient.Email == clientEmail {
			clientId = clientIdentity(inbound.Protocol, oldClient)
			break
		}
	}

	if len(clientId) == 0 {
		return false, common.NewError("Client Not Found For Email:", clientEmail)
	}

	var settings map[string]any
	err = json.Unmarshal([]byte(inbound.Settings), &settings)
	if err != nil {
		return false, err
	}
	clients := settings["clients"].([]any)
	var newClients []any
	for client_index := range clients {
		c := clients[client_index].(map[string]any)
		if c["email"] == clientEmail {
			c["totalGB"] = totalGB * 1024 * 1024 * 1024
			c["updated_at"] = time.Now().Unix() * 1000
			newClients = append(newClients, any(c))
		}
	}
	settings["clients"] = newClients
	modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}
	inbound.Settings = string(modifiedSettings)
	needRestart, err := s.UpdateInboundClient(inbound, clientId)
	return needRestart, err
}

func (s *InboundService) ResetClientTrafficByEmail(clientEmail string) error {
	db := database.GetDB()

	// Reset traffic stats in ClientTraffic table
	result := db.Model(xray.ClientTraffic{}).
		Where("email = ?", clientEmail).
		Updates(map[string]any{"enable": true, "up": 0, "down": 0})

	err := result.Error
	if err != nil {
		return err
	}

	return nil
}

func (s *InboundService) ResetClientTraffic(id int, clientEmail string) (bool, error) {
	needRestart := false

	traffic, err := s.GetClientTrafficByEmail(clientEmail)
	if err != nil {
		return false, err
	}

	if !traffic.Enable {
		inbound, err := s.GetInbound(id)
		if err != nil {
			return false, err
		}
		clients, err := s.GetClients(inbound)
		if err != nil {
			return false, err
		}
		for _, client := range clients {
			if client.Email == clientEmail && client.Enable {
				s.xrayApi.Init(p.GetAPIPort())
				cipher := ""
				if string(inbound.Protocol) == "shadowsocks" {
					var oldSettings map[string]any
					err = json.Unmarshal([]byte(inbound.Settings), &oldSettings)
					if err != nil {
						return false, err
					}
					cipher = oldSettings["method"].(string)
				}
				err1 := s.xrayApi.AddUser(string(inbound.Protocol), inbound.Tag, map[string]any{
					"email":    client.Email,
					"id":       client.ID,
					"auth":     client.Auth,
					"security": client.Security,
					"flow":     client.Flow,
					"password": client.Password,
					"username": client.Username,
					"cipher":   cipher,
				})
				if err1 == nil {
					logger.Debug("Client enabled due to reset traffic:", clientEmail)
				} else {
					logger.Debug("Error in enabling client by api:", err1)
					needRestart = true
				}
				s.xrayApi.Close()
				break
			}
		}
	}

	// Targeted update, not db.Save(traffic): `traffic` was read at the top of this
	// function, so saving the whole struct would also write back the all_time and
	// last_online it held then, discarding whatever the 10s accounting job committed
	// meanwhile. A reset zeroes up/down and re-enables; it must not rewind the lifetime
	// counter. Mirrors ResetClientTrafficByEmail, which already updates by column.
	db := database.GetDB()
	err = db.Model(xray.ClientTraffic{}).Where("id = ?", traffic.Id).Updates(map[string]any{
		"up":     0,
		"down":   0,
		"enable": true,
	}).Error
	if err != nil {
		return false, err
	}

	return needRestart, nil
}

func (s *InboundService) ResetAllClientTraffics(id int) error {
	db := database.GetDB()
	now := time.Now().Unix() * 1000

	return db.Transaction(func(tx *gorm.DB) error {
		whereText := "inbound_id "
		if id == -1 {
			whereText += " > ?"
		} else {
			whereText += " = ?"
		}

		// Reset client traffics
		result := tx.Model(xray.ClientTraffic{}).
			Where(whereText, id).
			Updates(map[string]any{"enable": true, "up": 0, "down": 0})

		if result.Error != nil {
			return result.Error
		}

		// Update lastTrafficResetTime for the inbound(s)
		inboundWhereText := "id "
		if id == -1 {
			inboundWhereText += " > ?"
		} else {
			inboundWhereText += " = ?"
		}

		result = tx.Model(model.Inbound{}).
			Where(inboundWhereText, id).
			Update("last_traffic_reset_time", now)

		return result.Error
	})
}

// ResetAllTraffics zeroes inbound counters. ownerId scopes it to one admin's
// inbounds; 0 means every owner, which only a super admin may ask for.
func (s *InboundService) ResetAllTraffics(ownerId int) error {
	db := database.GetDB()

	q := db.Model(model.Inbound{}).Where("user_id > ?", 0)
	if ownerId > 0 {
		q = q.Where("user_id = ?", ownerId)
	}
	result := q.Updates(map[string]any{"up": 0, "down": 0})

	err := result.Error
	return err
}

func (s *InboundService) ResetInboundTraffic(id int) error {
	db := database.GetDB()

	result := db.Model(model.Inbound{}).
		Where("id = ?", id).
		Updates(map[string]any{"up": 0, "down": 0})

	return result.Error
}

func (s *InboundService) DelDepletedClients(id int) error {
	_, err := s.DelDepletedClientsScoped(id, nil)
	return err
}

// DelDepletedClientsScoped is the same sweep narrowed to a set of accounts, and
// returns the emails it actually deleted so the caller can settle up for them.
//
// A nil onlyEmails is the admin case: every depleted client goes, exactly as
// DelDepletedClients has always behaved. A non-nil set is a reseller's own accounts,
// and it has to exist because the route this serves is gated on PermDeleteClient plus
// access to the INBOUND. A reseller holds both on an inbound it shares with an admin,
// so unscoped, one click deletes that admin's depleted accounts as well.
func (s *InboundService) DelDepletedClientsScoped(id int, onlyEmails map[string]bool) (deleted []string, err error) {
	db := database.GetDB()
	tx := db.Begin()
	defer func() {
		if err == nil {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()

	whereText := "reset = 0 and inbound_id "
	if id < 0 {
		whereText += "> ?"
	} else {
		whereText += "= ?"
	}
	// Only consider truly depleted clients: expired OR traffic exhausted
	depletedWhere := whereText + " and ((total > 0 and up + down >= total) or (expiry_time > 0 and expiry_time <= ?))"

	now := time.Now().Unix() * 1000
	depletedClients := []xray.ClientTraffic{}
	err = db.Model(xray.ClientTraffic{}).
		Where(depletedWhere, id, now).
		Select("inbound_id, GROUP_CONCAT(email) as email").
		Group("inbound_id").
		Find(&depletedClients).Error
	if err != nil {
		return nil, err
	}

	deleted = []string{}
	for _, depletedClient := range depletedClients {
		emails := []string{}
		for _, email := range strings.Split(depletedClient.Email, ",") {
			if onlyEmails == nil || ResellerOwnsEmail(onlyEmails, email) {
				emails = append(emails, email)
			}
		}
		// Every depleted account on this inbound belongs to someone else.
		if len(emails) == 0 {
			continue
		}
		oldInbound, err := s.GetInbound(depletedClient.InboundId)
		if err != nil {
			return nil, err
		}
		var oldSettings map[string]any
		err = json.Unmarshal([]byte(oldInbound.Settings), &oldSettings)
		if err != nil {
			return nil, err
		}

		// Comma-ok on both asserts: a settings blob shaped unexpectedly is a bad row
		// to skip, not a panic to take the whole request down with, and this path is
		// now reachable by a role that does not own the inbound it is sweeping.
		oldClients, _ := oldSettings["clients"].([]any)
		var newClients []any
		for _, client := range oldClients {
			c, ok := client.(map[string]any)
			if !ok {
				newClients = append(newClients, client)
				continue
			}
			cEmail, _ := c["email"].(string)
			deplete := false
			for _, email := range emails {
				if email == cEmail {
					deplete = true
					break
				}
			}
			if !deplete {
				newClients = append(newClients, client)
			}
		}
		// Delete inbound if no client remains. Never on a scoped sweep: the reseller
		// owns accounts, not the inbound, and emptying their last one must not take
		// an object shared with the admin who does own it.
		if len(newClients) == 0 && onlyEmails == nil {
			s.DelInbound(depletedClient.InboundId)
			deleted = append(deleted, emails...)
			continue
		}
		if newClients == nil {
			newClients = []any{}
		}
		oldSettings["clients"] = newClients

		newSettings, err := json.MarshalIndent(oldSettings, "", "  ")
		if err != nil {
			return nil, err
		}

		oldInbound.Settings = string(newSettings)
		err = tx.Save(oldInbound).Error
		if err != nil {
			return nil, err
		}
		deleted = append(deleted, emails...)
	}

	// Delete stats only for truly depleted clients, and on a scoped sweep only for
	// the ones just taken out of the settings: the predicate alone matches every
	// admin's depleted accounts too.
	if onlyEmails == nil {
		err = tx.Where(depletedWhere, id, now).Delete(xray.ClientTraffic{}).Error
	} else if len(deleted) > 0 {
		err = tx.Where(depletedWhere, id, now).Where("email IN ?", deleted).Delete(xray.ClientTraffic{}).Error
	}
	if err != nil {
		return nil, err
	}

	return deleted, nil
}

func (s *InboundService) GetClientTrafficTgBot(tgId int64) ([]*xray.ClientTraffic, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound

	// Retrieve inbounds where settings contain the given tgId
	err := db.Model(model.Inbound{}).Where("settings LIKE ?", fmt.Sprintf(`%%"tgId": %d%%`, tgId)).Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Errorf("Error retrieving inbounds with tgId %d: %v", tgId, err)
		return nil, err
	}

	var emails []string
	for _, inbound := range inbounds {
		clients, err := s.GetClients(inbound)
		if err != nil {
			logger.Errorf("Error retrieving clients for inbound %d: %v", inbound.Id, err)
			continue
		}
		for _, client := range clients {
			if client.TgID == tgId {
				emails = append(emails, client.Email)
			}
		}
	}

	var traffics []*xray.ClientTraffic
	err = db.Model(xray.ClientTraffic{}).Where("email IN ?", emails).Find(&traffics).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Warning("No ClientTraffic records found for emails:", emails)
			return nil, nil
		}
		logger.Errorf("Error retrieving ClientTraffic for emails %v: %v", emails, err)
		return nil, err
	}

	// Populate UUID and other client data for each traffic record
	for i := range traffics {
		if ct, client, e := s.GetClientByEmail(traffics[i].Email); e == nil && ct != nil && client != nil {
			traffics[i].Enable = client.Enable
			traffics[i].UUID = client.ID
			traffics[i].SubId = client.SubID
		}
	}

	return traffics, nil
}

func (s *InboundService) GetClientTrafficByEmail(email string) (traffic *xray.ClientTraffic, err error) {
	// Prefer retrieving along with client to reflect actual enabled state from inbound settings
	t, client, err := s.GetClientByEmail(email)
	if err != nil {
		logger.Warningf("Error retrieving ClientTraffic with email %s: %v", email, err)
		return nil, err
	}
	if t != nil && client != nil {
		t.UUID = client.ID
		t.SubId = client.SubID
		return t, nil
	}
	return nil, nil
}

func (s *InboundService) UpdateClientTrafficByEmail(email string, upload int64, download int64) error {
	db := database.GetDB()

	result := db.Model(xray.ClientTraffic{}).
		Where("email = ?", email).
		Updates(map[string]any{"up": upload, "down": download})

	err := result.Error
	if err != nil {
		logger.Warningf("Error updating ClientTraffic with email %s: %v", email, err)
		return err
	}
	return nil
}

func (s *InboundService) GetClientTrafficByID(id string) ([]xray.ClientTraffic, error) {
	db := database.GetDB()
	var traffics []xray.ClientTraffic

	err := db.Model(xray.ClientTraffic{}).Where(`email IN(
		SELECT JSON_EXTRACT(client.value, '$.email') as email
		FROM inbounds,
	  	JSON_EACH(JSON_EXTRACT(inbounds.settings, '$.clients')) AS client
		WHERE
	  	JSON_EXTRACT(client.value, '$.id') in (?)
		)`, id).Find(&traffics).Error

	if err != nil {
		logger.Debug(err)
		return nil, err
	}
	// Reconcile enable flag with client settings per email to avoid stale DB value
	for i := range traffics {
		if ct, client, e := s.GetClientByEmail(traffics[i].Email); e == nil && ct != nil && client != nil {
			traffics[i].Enable = client.Enable
			traffics[i].UUID = client.ID
			traffics[i].SubId = client.SubID
		}
	}
	return traffics, err
}

func (s *InboundService) SearchClientTraffic(query string) (traffic *xray.ClientTraffic, err error) {
	db := database.GetDB()
	inbound := &model.Inbound{}
	traffic = &xray.ClientTraffic{}

	// Search for inbound settings that contain the query
	err = db.Model(model.Inbound{}).Where("settings LIKE ?", "%\""+query+"\"%").First(inbound).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Warningf("Inbound settings containing query %s not found: %v", query, err)
			return nil, err
		}
		logger.Errorf("Error searching for inbound settings with query %s: %v", query, err)
		return nil, err
	}

	traffic.InboundId = inbound.Id

	// Unmarshal settings to get clients
	settings := map[string][]model.Client{}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		logger.Errorf("Error unmarshalling inbound settings for inbound ID %d: %v", inbound.Id, err)
		return nil, err
	}

	clients := settings["clients"]
	for _, client := range clients {
		if (client.ID == query || client.Password == query) && client.Email != "" {
			traffic.Email = client.Email
			break
		}
	}

	if traffic.Email == "" {
		logger.Warningf("No client found with query %s in inbound ID %d", query, inbound.Id)
		return nil, gorm.ErrRecordNotFound
	}

	// Retrieve ClientTraffic based on the found email
	err = db.Model(xray.ClientTraffic{}).Where("email = ?", traffic.Email).First(traffic).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Warningf("ClientTraffic for email %s not found: %v", traffic.Email, err)
			return nil, err
		}
		logger.Errorf("Error retrieving ClientTraffic for email %s: %v", traffic.Email, err)
		return nil, err
	}

	return traffic, nil
}

func (s *InboundService) GetInboundClientIps(clientEmail string) (string, error) {
	db := database.GetDB()
	InboundClientIps := &model.InboundClientIps{}
	err := db.Model(model.InboundClientIps{}).Where("client_email = ?", clientEmail).First(InboundClientIps).Error
	if err != nil {
		return "", err
	}

	if InboundClientIps.Ips == "" {
		return "", nil
	}

	// Try to parse as new format (with timestamps)
	type IPWithTimestamp struct {
		IP        string `json:"ip"`
		Timestamp int64  `json:"timestamp"`
	}

	var ipsWithTime []IPWithTimestamp
	err = json.Unmarshal([]byte(InboundClientIps.Ips), &ipsWithTime)

	// If successfully parsed as new format, return with timestamps
	if err == nil && len(ipsWithTime) > 0 {
		return InboundClientIps.Ips, nil
	}

	// Otherwise, assume it's old format (simple string array)
	// Try to parse as simple array and convert to new format
	var oldIps []string
	err = json.Unmarshal([]byte(InboundClientIps.Ips), &oldIps)
	if err == nil && len(oldIps) > 0 {
		// Convert old format to new format with current timestamp
		newIpsWithTime := make([]IPWithTimestamp, len(oldIps))
		for i, ip := range oldIps {
			newIpsWithTime[i] = IPWithTimestamp{
				IP:        ip,
				Timestamp: time.Now().Unix(),
			}
		}
		result, _ := json.Marshal(newIpsWithTime)
		return string(result), nil
	}

	// Return as-is if parsing fails
	return InboundClientIps.Ips, nil
}

func (s *InboundService) ClearClientIps(clientEmail string) error {
	db := database.GetDB()

	result := db.Model(model.InboundClientIps{}).
		Where("client_email = ?", clientEmail).
		Update("ips", "")
	err := result.Error
	if err != nil {
		return err
	}
	return nil
}

func (s *InboundService) SearchInbounds(query string) ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Preload("ClientStats").Where("remark like ?", "%"+query+"%").Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return inbounds, nil
}

func (s *InboundService) MigrationRequirements() {
	db := database.GetDB()
	tx := db.Begin()
	var err error
	defer func() {
		if err == nil {
			tx.Commit()
			if dbErr := db.Exec(`VACUUM "main"`).Error; dbErr != nil {
				logger.Warningf("VACUUM failed: %v", dbErr)
			}
		} else {
			tx.Rollback()
		}
	}()

	// Calculate and backfill all_time from up+down for inbounds and clients
	err = tx.Exec(`
		UPDATE inbounds
		SET all_time = IFNULL(up, 0) + IFNULL(down, 0)
		WHERE IFNULL(all_time, 0) = 0 AND (IFNULL(up, 0) + IFNULL(down, 0)) > 0
	`).Error
	if err != nil {
		return
	}
	err = tx.Exec(`
		UPDATE client_traffics
		SET all_time = IFNULL(up, 0) + IFNULL(down, 0)
		WHERE IFNULL(all_time, 0) = 0 AND (IFNULL(up, 0) + IFNULL(down, 0)) > 0
	`).Error

	if err != nil {
		return
	}

	// Fix inbounds based problems
	var inbounds []*model.Inbound
	err = tx.Model(model.Inbound{}).Where("protocol IN (?)", []string{"vmess", "vless", "trojan"}).Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return
	}
	for inbound_index := range inbounds {
		settings := map[string]any{}
		json.Unmarshal([]byte(inbounds[inbound_index].Settings), &settings)
		clients, ok := settings["clients"].([]any)
		if ok {
			// Fix Client configuration problems
			var newClients []any
			for client_index := range clients {
				c := clients[client_index].(map[string]any)

				// Add email='' if it is not exists
				if _, ok := c["email"]; !ok {
					c["email"] = ""
				}

				// Convert string tgId to int64
				if _, ok := c["tgId"]; ok {
					var tgId any = c["tgId"]
					if tgIdStr, ok2 := tgId.(string); ok2 {
						tgIdInt64, err := strconv.ParseInt(strings.ReplaceAll(tgIdStr, " ", ""), 10, 64)
						if err == nil {
							c["tgId"] = tgIdInt64
						}
					}
				}

				// Remove "flow": "xtls-rprx-direct"
				if _, ok := c["flow"]; ok {
					if c["flow"] == "xtls-rprx-direct" {
						c["flow"] = ""
					}
				}
				// Backfill created_at and updated_at
				if _, ok := c["created_at"]; !ok {
					c["created_at"] = time.Now().Unix() * 1000
				}
				c["updated_at"] = time.Now().Unix() * 1000
				newClients = append(newClients, any(c))
			}
			settings["clients"] = newClients
			modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return
			}

			inbounds[inbound_index].Settings = string(modifiedSettings)
		}

		// Add client traffic row for all clients which has email
		modelClients, err := s.GetClients(inbounds[inbound_index])
		if err != nil {
			return
		}
		for _, modelClient := range modelClients {
			if len(modelClient.Email) > 0 {
				var count int64
				tx.Model(xray.ClientTraffic{}).Where("email = ?", modelClient.Email).Count(&count)
				if count == 0 {
					s.AddClientStat(tx, inbounds[inbound_index].Id, &modelClient)
				}
			}
		}
	}
	tx.Save(inbounds)

	// Remove orphaned traffics
	tx.Where("inbound_id = 0").Delete(xray.ClientTraffic{})

	// Migrate old MultiDomain to External Proxy
	var externalProxy []struct {
		Id             int
		Port           int
		StreamSettings []byte
	}
	err = tx.Raw(`select id, port, stream_settings
	from inbounds
	WHERE protocol in ('vmess','vless','trojan')
	  AND json_extract(stream_settings, '$.security') = 'tls'
	  AND json_extract(stream_settings, '$.tlsSettings.settings.domains') IS NOT NULL`).Scan(&externalProxy).Error
	if err != nil || len(externalProxy) == 0 {
		return
	}

	for _, ep := range externalProxy {
		var reverses any
		var stream map[string]any
		json.Unmarshal(ep.StreamSettings, &stream)
		if tlsSettings, ok := stream["tlsSettings"].(map[string]any); ok {
			if settings, ok := tlsSettings["settings"].(map[string]any); ok {
				if domains, ok := settings["domains"].([]any); ok {
					for _, domain := range domains {
						if domainMap, ok := domain.(map[string]any); ok {
							domainMap["forceTls"] = "same"
							domainMap["port"] = ep.Port
							domainMap["dest"] = domainMap["domain"].(string)
							delete(domainMap, "domain")
						}
					}
				}
				reverses = settings["domains"]
				delete(settings, "domains")
			}
		}
		stream["externalProxy"] = reverses
		newStream, _ := json.MarshalIndent(stream, " ", "  ")
		tx.Model(model.Inbound{}).Where("id = ?", ep.Id).Update("stream_settings", newStream)
	}

	err = tx.Raw(`UPDATE inbounds
	SET tag = REPLACE(tag, '0.0.0.0:', '')
	WHERE INSTR(tag, '0.0.0.0:') > 0;`).Error
	if err != nil {
		return
	}
}

func (s *InboundService) MigrateDB() {
	s.MigrationRequirements()
	s.MigrationSubIds()
	s.MigrationAccountSlots()
	s.MigrationRemoveOrphanedTraffics()
}

// MigrationAccountSlots stamps every pool-protocol account with the slot it is effectively
// using today: its position in clients[]. Nothing moves on upgrade, and from then on the
// address survives a delete somewhere earlier in the list.
//
// Must run before the servers start, so no allocator can read a half-stamped inbound (see
// the call in runWebServer). Idempotent: an account that already has a slot is left alone.
func (s *InboundService) MigrationAccountSlots() {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol IN (?)", slotPoolProtocols).Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Warning("MigrationAccountSlots - reading inbounds failed: ", err)
		return
	}

	for _, inbound := range inbounds {
		settings := map[string]any{}
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		clients, ok := settings["clients"].([]any)
		if !ok {
			continue
		}
		changed := false
		for i := range clients {
			c, ok := clients[i].(map[string]any)
			if !ok {
				continue
			}
			if v, has := c["slot"]; has {
				if f, ok := v.(float64); ok && f >= 0 {
					continue
				}
			}
			c["slot"] = i // exactly the address it is on now
			clients[i] = c
			changed = true
		}
		if !changed {
			continue
		}
		settings["clients"] = clients
		modified, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			continue
		}
		if err := db.Model(model.Inbound{}).Where("id = ?", inbound.Id).
			Update("settings", string(modified)).Error; err != nil {
			logger.Warningf("MigrationAccountSlots - inbound %d: %v", inbound.Id, err)
		}
	}
}

// subBackfillProtocols are the VPN protocols the subscription service started serving
// after their accounts already existed. Their stored clients therefore predate the subId
// the panel now mints for every account, and a client with no subId has no subscription
// link at all: it is invisible to the sub endpoints and gets no link in the panel.
//
// The Xray protocols are deliberately absent. Their clients have always been given a
// subId on creation, so an empty one there is an admin who cleared the field in the
// client form, and minting one would undo that choice.
var subBackfillProtocols = []string{"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wg-c", "awg", "gre", "mtproto", "ssh"}

// MigrationSubIds gives every VPN-protocol account that has none its own subscription
// id. One id per client (clients that share a subId share one subscription link, which
// is a choice the admin makes, not something a backfill should impose), and a row is only
// rewritten when a client was actually missing one, so the pass is idempotent.
func (s *InboundService) MigrationSubIds() {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol IN (?)", subBackfillProtocols).Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		logger.Warning("MigrationSubIds - reading inbounds failed: ", err)
		return
	}

	for _, inbound := range inbounds {
		settings := map[string]any{}
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		clients, ok := settings["clients"].([]any)
		if !ok {
			continue
		}
		changed := false
		for i := range clients {
			c, ok := clients[i].(map[string]any)
			if !ok {
				continue
			}
			// No email means no account identity, so nothing for a subscription to
			// report usage or expiry for.
			if email, _ := c["email"].(string); strings.TrimSpace(email) == "" {
				continue
			}
			if subId, _ := c["subId"].(string); strings.TrimSpace(subId) != "" {
				continue
			}
			c["subId"] = random.Seq(16)
			clients[i] = c
			changed = true
		}
		if !changed {
			continue
		}
		settings["clients"] = clients
		modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			continue
		}
		if err := db.Model(model.Inbound{}).Where("id = ?", inbound.Id).
			Update("settings", string(modifiedSettings)).Error; err != nil {
			logger.Warningf("MigrationSubIds - inbound %d: %v", inbound.Id, err)
		}
	}
}

// ClientStatsSummary is the overview's account roll-up: how many accounts the
// caller owns, how many are connected right now, how many have run out of traffic
// or time, and how many are close to it.
type ClientStatsSummary struct {
	Total    int `json:"total"`
	Online   int `json:"online"`
	Depleted int `json:"depleted"`
	Expiring int `json:"expiring"`
}

// GetClientStatsFor counts the caller's accounts by state. It is the server-side
// twin of the tally the inbounds page builds in the browser, and follows the same
// rules so the two pages cannot disagree:
//
//   - clients on a DISABLED inbound still count towards the total, but are neither
//     online, depleted nor expiring;
//   - depleted wins over expiring, so the two never double-count the same account;
//   - the warning windows come from the expireDiff/trafficDiff settings, in the
//     days and GB the settings form stores them as.
//
// Scoping is inherited from GetInboundsFor, so an admin sees only their own
// accounts. That also scopes "online": the panel-wide online list is narrowed to
// the emails on the inbounds the caller can see.
func (s *InboundService) GetClientStatsFor(user *model.User) (*ClientStatsSummary, error) {
	inbounds, err := s.GetInboundsFor(user)
	if err != nil {
		return nil, err
	}

	var settingService SettingService
	expireDiff, err := settingService.GetExpireDiff()
	if err != nil {
		return nil, err
	}
	trafficDiff, err := settingService.GetTrafficDiff()
	if err != nil {
		return nil, err
	}
	expireWindow := int64(expireDiff) * 86400000     // days -> milliseconds
	trafficWindow := int64(trafficDiff) * 1073741824 // GB -> bytes

	online := make(map[string]bool)
	for _, email := range s.GetOnlineClients() {
		online[email] = true
	}

	summary := &ClientStatsSummary{}
	now := time.Now().UnixMilli()
	for _, inbound := range inbounds {
		clients, err := s.GetClients(inbound)
		if err != nil {
			// One inbound with unparsable settings must not blank the whole roll-up.
			logger.Warning("get clients for stats failed on inbound", inbound.Id, ":", err)
			continue
		}
		summary.Total += len(clients)
		if !inbound.Enable {
			continue
		}
		for _, client := range clients {
			if client.Enable && online[client.Email] {
				summary.Online++
			}
		}
		for _, stat := range inbound.ClientStats {
			exhausted := stat.Total > 0 && (stat.Up+stat.Down) >= stat.Total
			expired := stat.ExpiryTime > 0 && stat.ExpiryTime <= now
			if exhausted || expired {
				summary.Depleted++
				continue
			}
			nearExpiry := stat.ExpiryTime > 0 && stat.ExpiryTime-now < expireWindow
			nearQuota := stat.Total > 0 && stat.Total-(stat.Up+stat.Down) < trafficWindow
			if nearExpiry || nearQuota {
				summary.Expiring++
			}
		}
	}
	return summary, nil
}

func (s *InboundService) GetOnlineClients() []string {
	// Nil-checked like the other p accesses: Xray may never have started (a
	// VPN-only deployment, or a failed core), and an unguarded deref panics the
	// request rather than reporting an empty list.
	if p == nil {
		return []string{}
	}
	return p.GetOnlineClients()
}

// GetOnlineMarks returns this tick's online observations with their inbound
// attribution. Empty, never nil-panicking, when no core is running.
func (s *InboundService) GetOnlineMarks() []xray.OnlineMark {
	if p == nil {
		return []xray.OnlineMark{}
	}
	marks := p.GetOnlineMarks()
	if marks == nil {
		return []xray.OnlineMark{}
	}
	return marks
}

// inboundTagIdMap maps running-config inbound tags to database ids, so an
// access-log observation ("[vless-ws -> user]") can be turned into the row id
// the panel keys everything else by. Tags are unique across the config, so the
// map loses nothing.
func (s *InboundService) inboundTagIdMap(tx *gorm.DB) map[string]int {
	rows := []struct {
		Id  int
		Tag string
	}{}
	if err := tx.Model(&model.Inbound{}).Select("id, tag").Scan(&rows).Error; err != nil {
		logger.Warning("inbound tag map load failed:", err)
		return nil
	}
	m := make(map[string]int, len(rows))
	for _, r := range rows {
		if r.Tag != "" {
			m[r.Tag] = r.Id
		}
	}
	return m
}

func (s *InboundService) GetClientsLastOnline() (map[string]int64, error) {
	db := database.GetDB()
	var rows []xray.ClientTraffic
	err := db.Model(&xray.ClientTraffic{}).Select("email, last_online").Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	result := make(map[string]int64, len(rows))
	for _, r := range rows {
		result[r.Email] = r.LastOnline
	}
	return result, nil
}

func (s *InboundService) FilterAndSortClientEmails(emails []string) ([]string, []string, error) {
	db := database.GetDB()

	// Step 1: Get ClientTraffic records for emails in the input list
	var clients []xray.ClientTraffic
	err := db.Where("email IN ?", emails).Find(&clients).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, nil, err
	}

	// Step 2: Sort clients by (Up + Down) descending
	sort.Slice(clients, func(i, j int) bool {
		return (clients[i].Up + clients[i].Down) > (clients[j].Up + clients[j].Down)
	})

	// Step 3: Extract sorted valid emails and track found ones
	validEmails := make([]string, 0, len(clients))
	found := make(map[string]bool)
	for _, client := range clients {
		validEmails = append(validEmails, client.Email)
		found[client.Email] = true
	}

	// Step 4: Identify emails that were not found in the database
	extraEmails := make([]string, 0)
	for _, email := range emails {
		if !found[email] {
			extraEmails = append(extraEmails, email)
		}
	}

	return validEmails, extraEmails, nil
}
func (s *InboundService) DelInboundClientByEmail(inboundId int, email string) (bool, error) {
	oldInbound, err := s.GetInbound(inboundId)
	if err != nil {
		logger.Error("Load Old Data Error")
		return false, err
	}

	var settings map[string]any
	if err := json.Unmarshal([]byte(oldInbound.Settings), &settings); err != nil {
		return false, err
	}

	interfaceClients, ok := settings["clients"].([]any)
	if !ok {
		return false, common.NewError("invalid clients format in inbound settings")
	}

	var newClients []any
	needApiDel := false
	found := false

	for _, client := range interfaceClients {
		c, ok := client.(map[string]any)
		if !ok {
			continue
		}
		if cEmail, ok := c["email"].(string); ok && cEmail == email {
			// matched client, drop it
			found = true
			needApiDel, _ = c["enable"].(bool)
		} else {
			newClients = append(newClients, client)
		}
	}

	if !found {
		return false, common.NewError(fmt.Sprintf("client with email %s not found", email))
	}
	if len(newClients) == 0 {
		return false, common.NewError("no client remained in Inbound")
	}

	settings["clients"] = newClients
	newSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}

	oldInbound.Settings = string(newSettings)

	db := database.GetDB()

	// remove IP bindings
	if err := s.DelClientIPs(db, email); err != nil {
		logger.Error("Error in delete client IPs")
		return false, err
	}

	needRestart := false

	// remove stats too
	if len(email) > 0 {
		// Counted directly rather than read through GetClientTrafficByEmail. That one
		// resolves the account's inbound (to attach a uuid this path never uses) and
		// reports a MISSING row as a hard error, "Inbound Not Found For Email".
		//
		// A missing row is not an error here, it is "no stats to delete", and it is
		// the ordinary state of the SECOND membership of one account: an account on
		// N inbounds has ONE traffic row, the first delete takes it, and every
		// remaining membership then failed outright and could never be removed. That
		// left a deleted account still serving on every inbound but the first.
		var stats int64
		if err := db.Model(xray.ClientTraffic{}).Where("email = ?", email).Count(&stats).Error; err != nil {
			return false, err
		}
		if stats > 0 {
			if err := s.DelClientStat(db, email); err != nil {
				logger.Error("Delete stats Data Error")
				return false, err
			}
		}

		if needApiDel {
			s.xrayApi.Init(p.GetAPIPort())
			if err1 := s.xrayApi.RemoveUser(oldInbound.Tag, email); err1 == nil {
				logger.Debug("Client deleted by api:", email)
				needRestart = false
			} else {
				if strings.Contains(err1.Error(), fmt.Sprintf("User %s not found.", email)) {
					logger.Debug("User is already deleted. Nothing to do more...")
				} else {
					logger.Debug("Error in deleting client by api:", err1)
					needRestart = true
				}
			}
			s.xrayApi.Close()
		}
	}

	return needRestart, db.Save(oldInbound).Error
}
