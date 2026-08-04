package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"gorm.io/gorm"
)

// ResellerService is everything a reseller account is: the balance an admin
// grants it, the accounts it owns, and the arithmetic that moves bytes between
// the two.
//
// The role itself is model.User.IsReseller (see database/model/model.go for why
// it is a role and not a permission bit). This service owns the two tables that
// hang off it, ResellerProfile and ResellerClient.
type ResellerService struct{}

const oneGB = int64(1024 * 1024 * 1024)

var (
	ErrNotAReseller         = errors.New("that account is not a reseller")
	ErrResellerNotFound     = errors.New("reseller not found")
	ErrResellerNameTaken    = errors.New("that username is already taken")
	ErrInsufficientBalance  = errors.New("not enough traffic left on your balance")
	ErrResetNotOwned        = errors.New("you can only reset accounts you created")
	ErrBelowMinCreate       = errors.New("below the minimum traffic you may create an account with")
	ErrBelowMinAdd          = errors.New("below the minimum traffic you may add in one edit")
	ErrUnlimitedAccount     = errors.New("you cannot create an account with unlimited traffic")
	ErrInvalidQuota         = errors.New("that traffic quota is not a number of bytes an account can hold")
	ErrClientNotOwned       = errors.New("not found")
	ErrResellerHasClients   = errors.New("this reseller still owns accounts; delete them first")
	ErrInboundNotAssignable = errors.New("you can only assign inbounds you have access to")
)

// gbToBytes converts a whole-GB operator setting. The levers an admin types are
// in GB; everything downstream of them is bytes.
func gbToBytes(gb int) int64 {
	if gb <= 0 {
		return 0
	}
	// Saturate rather than wrap. The product overflows above about 8 billion GB,
	// and a wrapped negative reads as "no floor set", so an absurd number typed
	// into a minimum would SILENTLY DISABLE the very limit it was setting.
	if int64(gb) > math.MaxInt64/oneGB {
		return math.MaxInt64
	}
	return int64(gb) * oneGB
}

// AvailableBytes is what a reseller may still commit. Zero for an unlimited one,
// who never has a balance to check against, so callers must test Unlimited before
// reading anything into this.
//
// Both ends are clamped. An admin who lowers an allowance below what is already
// spent leaves a reseller who can sell nothing more rather than one who owes
// negative traffic, and a SpentBytes that somehow went negative must not read as
// balance on top of the allowance.
func AvailableBytes(p model.ResellerProfile) int64 {
	if p.Unlimited {
		return 0
	}
	spent := p.SpentBytes
	if spent < 0 {
		spent = 0
	}
	available := p.AllowanceBytes - spent
	if available < 0 {
		return 0
	}
	return available
}

// shortBy names the exact deficit, because "not enough traffic" leaves a reseller
// guessing how much to ask an admin for. The shortfall, not the price: they can
// see what they asked for, what they cannot see is the gap.
func shortBy(want, available int64) error {
	short := want - available
	if short < 0 {
		short = 0
	}
	return fmt.Errorf("%w: you are short %s", ErrInsufficientBalance, common.FormatTraffic(short))
}

// --- balance arithmetic ---------------------------------------------------------
//
// This section is deliberately free of database access. It is where the money
// is, so it is a pure function of its inputs and can be proven on its own.

// QuoteInput is everything one client mutation needs to be priced.
type QuoteInput struct {
	Profile model.ResellerProfile
	// Create distinguishes a new account from an edit of an existing one.
	Create bool
	// OldTotal and NewTotal are the account's traffic quota in BYTES, before and
	// after. model.Client.TotalGB is a byte count despite its name.
	OldTotal int64
	NewTotal int64
	// OldCharged is ResellerClient.ChargedBytes, what this account currently
	// holds against the reseller's balance. Consumed is AllTime - AllTimeBase,
	// the traffic this account has moved SINCE it was charged.
	OldCharged int64
	Consumed   int64
	// CurrentExpiry is the account's expiry in ms since epoch, 0 for none.
	CurrentExpiry int64
	NowMillis     int64

	// Reset prices a traffic-counter reset rather than a quota change, and
	// ClearedBytes is the up+down about to be zeroed.
	//
	// A reset is a PURCHASE, not an adjustment. Zeroing the counters lets the
	// account move ClearedBytes again against the same quota, so the reseller is
	// buying that traffic a second time and their balance has to pay for it.
	// Without this a reset would be an unlimited-traffic button: set 1 GB, sell
	// it, reset, repeat, all for one gigabyte of balance.
	Reset        bool
	ClearedBytes int64
}

// ChargeQuote is the decided effect of one mutation, computed before anything
// is written.
type ChargeQuote struct {
	// DeltaSpent is added to ResellerProfile.SpentBytes. Positive debits the
	// reseller, negative refunds them.
	DeltaSpent int64
	// NewCharged is what ResellerClient.ChargedBytes becomes.
	NewCharged int64
	// ForceExpiry reports whether ExpiryTime must overwrite whatever the form
	// posted. False when the reseller has no days-per-GB coupling, in which case
	// they pick the expiry themselves.
	ForceExpiry bool
	ExpiryTime  int64
}

// Quote prices one client mutation against a reseller's limits.
//
// The refund rule is the whole feature: bytes already moved are gone, so a
// deduct or a delete can only return the UNUSED part of what was charged.
// Consumed is measured from ClientTraffic.AllTime, which is monotonic across a
// traffic reset, so resetting an account cannot turn spent bytes back into
// refundable balance.
func Quote(in QuoteInput) (ChargeQuote, error) {
	p := in.Profile
	available := AvailableBytes(p)

	// Priced before the quota rules below, and deliberately outside them: a reset
	// does not change NewTotal, so running it through the zero-quota and minimum
	// checks would judge it against a quota nobody is editing.
	if in.Reset {
		cleared := in.ClearedBytes
		if cleared < 0 {
			cleared = 0
		}
		if !p.Unlimited && cleared > available {
			return ChargeQuote{}, shortBy(cleared, available)
		}
		q := ChargeQuote{DeltaSpent: cleared, NewCharged: in.OldCharged + cleared}
		// AllTimeBase is deliberately NOT advanced by the caller: AllTime is
		// monotonic across a reset, so consumption keeps counting from the
		// original charge and the extra bytes show up as the account's new
		// headroom rather than as a refund.
		q.ForceExpiry, q.ExpiryTime = forcedExpiry(p, in, q.DeltaSpent)
		return q, nil
	}

	// NewTotal is jsonInt64(cm["totalGB"]) straight off the request body, so it is
	// the caller's to choose. A negative one prices as a NEGATIVE charge, which
	// reserve() writes into SpentBytes: the account creation would pay the
	// reseller. Refused before anything else looks at it.
	if in.NewTotal < 0 {
		return ChargeQuote{}, ErrInvalidQuota
	}

	// An unlimited ACCOUNT out of a limited balance is the whole feature bypassed
	// in one click, and it is the first thing anyone will try.
	//
	// The second clause matters as much as the first. Unlimited is read at quote
	// time, so keying only on the flag would let an account SOLD out of a limited
	// balance be uncapped during any window in which its reseller is unlimited:
	// the full unused refund lands AND the customer keeps a now-unlimited
	// account, and flipping the flag back leaves the reseller holding both. An
	// account that carries a charge can never be zeroed, whatever the flag says.
	if in.NewTotal == 0 && (!p.Unlimited || in.OldCharged > 0) {
		return ChargeQuote{}, ErrUnlimitedAccount
	}

	var q ChargeQuote
	switch {
	case in.Create:
		if min := gbToBytes(p.MinCreateGB); min > 0 && in.NewTotal < min {
			return ChargeQuote{}, fmt.Errorf("%w: %d GB", ErrBelowMinCreate, p.MinCreateGB)
		}
		if !p.Unlimited && in.NewTotal > available {
			return ChargeQuote{}, shortBy(in.NewTotal, available)
		}
		q.DeltaSpent = in.NewTotal
		q.NewCharged = in.NewTotal

	case in.NewTotal > in.OldTotal: // top up
		delta := in.NewTotal - in.OldTotal
		if min := gbToBytes(p.MinAddGB); min > 0 && delta < min {
			return ChargeQuote{}, fmt.Errorf("%w: %d GB", ErrBelowMinAdd, p.MinAddGB)
		}
		if !p.Unlimited && delta > available {
			return ChargeQuote{}, shortBy(delta, available)
		}
		q.DeltaSpent = delta
		q.NewCharged = in.OldCharged + delta

	case in.NewTotal < in.OldTotal: // deduct
		// Refund only what has not been used. The clamp at Consumed is the rule:
		// a reseller cannot claw back bytes the customer already moved.
		newCharged := in.NewTotal
		if in.Consumed > newCharged {
			newCharged = in.Consumed
		}
		// A deduct must never RAISE the charge, which it otherwise would on an
		// account that has already overshot what it was charged for.
		if newCharged > in.OldCharged {
			newCharged = in.OldCharged
		}
		q.DeltaSpent = newCharged - in.OldCharged // <= 0
		q.NewCharged = newCharged

	default: // quota unchanged
		q.NewCharged = in.OldCharged
	}

	q.ForceExpiry, q.ExpiryTime = forcedExpiry(p, in, q.DeltaSpent)
	return q, nil
}

// forcedExpiry derives an account's deadline from the traffic just moved, when
// the reseller has a days-per-GB factor.
//
// One rule covers create, top-up and deduct: the new deadline is the CURRENT one
// (or now, whichever is later) shifted by the days the charge change buys. An
// expired account therefore restarts from now while a live one extends, and a
// deduct gives back the time it gives back the traffic.
//
// Absolute, never the panel's negative "delayed start" form: that encoding is
// also what freeze writes (a frozen account is enable=false AND expiryTime<0),
// so borrowing it here would make forced-expiry accounts indistinguishable from
// frozen ones.
func forcedExpiry(p model.ResellerProfile, in QuoteInput, deltaSpent int64) (bool, int64) {
	if p.DaysPerGB <= 0 || deltaSpent == 0 {
		return false, 0
	}
	// An account with unlimited traffic has no GB to derive days from.
	if in.NewTotal <= 0 {
		return false, 0
	}
	base := in.CurrentExpiry
	if base < in.NowMillis {
		base = in.NowMillis
	}
	// float64 rather than integer arithmetic: bytes * days * ms-per-day overflows
	// int64 well inside the range of a real account, and a 53-bit mantissa is
	// far more precision than a millisecond deadline needs.
	days := float64(deltaSpent) / float64(oneGB) * float64(p.DaysPerGB)
	ms := days * 24 * 60 * 60 * 1000

	// Saturate the offset. A quota big enough to push the deadline past int64 is
	// a typo rather than a plan, and converting an out-of-range float64 to int64
	// is undefined in Go: in practice it wraps, so the account would come out
	// ALREADY EXPIRED, which is the opposite of what the operator asked for.
	const maxOffsetMs = int64(100*365*24) * 60 * 60 * 1000 // a century
	var out int64
	switch {
	case ms > float64(maxOffsetMs):
		out = base + maxOffsetMs
	case ms < float64(-maxOffsetMs):
		out = base - maxOffsetMs
	default:
		out = base + int64(ms)
	}
	if out < in.NowMillis {
		out = in.NowMillis
	}
	return true, out
}

// --- profile lookup -------------------------------------------------------------

// ProfileFor loads a reseller's profile. Returns ErrNotAReseller for an account
// that is not one, so a caller cannot accidentally price an admin's action.
func (s *ResellerService) ProfileFor(userId int) (*model.ResellerProfile, error) {
	p := &model.ResellerProfile{}
	err := database.GetDB().Model(&model.ResellerProfile{}).
		Where("user_id = ?", userId).First(p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotAReseller
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// --- client ownership -----------------------------------------------------------
//
// Every one of these fails CLOSED, matching AdminService's inbound access: an
// ownership question we cannot answer must never resolve to "allowed".

// OwnsClientEmail reports whether this reseller created that account.
func (s *ResellerService) OwnsClientEmail(email string, userId int) (bool, error) {
	var n int64
	err := database.GetDB().Model(&model.ResellerClient{}).
		Where("email = ? AND user_id = ?", email, userId).Count(&n).Error
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// OwnedEmails is the set of accounts this reseller created, for scoping a
// panel-wide payload down to them. Lower-cased, because client emails are
// compared case-insensitively across the panel.
func (s *ResellerService) OwnedEmails(userId int) (map[string]bool, error) {
	var emails []string
	err := database.GetDB().Model(&model.ResellerClient{}).
		Where("user_id = ?", userId).Pluck("email", &emails).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(emails))
	for _, e := range emails {
		out[strings.ToLower(e)] = true
	}
	return out, nil
}

// ClientOwner returns the reseller row for an account, or nil when the house
// owns it. Absence is the admin case and is not an error.
func (s *ResellerService) ClientOwner(email string) (*model.ResellerClient, error) {
	rc := &model.ResellerClient{}
	err := database.GetDB().Model(&model.ResellerClient{}).
		Where("email = ?", email).First(rc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// RenameClient carries ownership across an email change.
//
// Without it a rename orphans the row: the reseller loses the account from their
// own view and the refund path can never find it again, because the ledger is
// keyed on the panel-wide email identity.
func (s *ResellerService) RenameClient(oldEmail, newEmail string) error {
	if oldEmail == "" || newEmail == "" || oldEmail == newEmail {
		return nil
	}
	return database.GetDB().Model(&model.ResellerClient{}).
		Where("email = ?", oldEmail).Update("email", newEmail).Error
}

// DropInbound settles the ledger after an inbound has been deleted. It removes a
// MEMBERSHIP, never an account.
//
// The distinction is the whole function. An account is one identity on N inbounds
// with ONE quota and ONE charge, so deleting one inbound it sits on does not end
// the sale: the other memberships keep serving it against the same charge. Keying
// this on ResellerClient.InboundId got both halves wrong at once. Delete inbound B
// while the row named A and nothing was refunded, the client vanished from B and
// the ledger kept charging; delete A and the whole charge came back while the
// account carried on selling on B and C.
//
// emails is the reseller-owned accounts that were SERVED BY that inbound and usage
// is UsageSnapshot over them. Both are parameters because both are unanswerable by
// now: the inbound's settings and its client_traffics rows went with it, and
// pricing from that wreckage reads every account as untouched and refunds the lot.
//
// Only the LAST membership going is a delete, and that one is refunded for what the
// account had left: an admin deleting the inbound out from under a reseller is not
// a sale they chose to unwind, but the bytes their customers already moved are
// still spent.
func (s *ResellerService) DropInbound(inboundId int, emails []string, usage map[string]int64) error {
	db := database.GetDB()

	// Two sets. The accounts the inbound served are the sale to settle; the rows
	// whose HOME pointer named it are only a column to repair, and are usually a
	// subset of the first.
	candidates := make([]string, 0, len(emails))
	seen := map[string]bool{}
	add := func(email string) {
		key := emailKey(email)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, email)
	}
	for _, email := range emails {
		add(email)
	}
	var homed []string
	if err := db.Model(&model.ResellerClient{}).
		Where("inbound_id = ?", inboundId).Pluck("email", &homed).Error; err != nil {
		return err
	}
	for _, email := range homed {
		add(email)
	}

	for _, email := range candidates {
		ids, err := servingInboundIds(db, email)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			// Still served elsewhere: the account survives the inbound, so the charge
			// stands and the row stays. All that moves is the home pointer, and only
			// when it named the inbound that just went, so the column keeps naming an
			// inbound the account is really on.
			if err := db.Model(&model.ResellerClient{}).
				Where("email = ? AND inbound_id = ?", email, inboundId).
				Update("inbound_id", ids[0]).Error; err != nil {
				return err
			}
			continue
		}
		used, known := usage[emailKey(email)]
		if err := s.RefundDeleted(email, used, known); err != nil {
			return err
		}
	}
	return nil
}

// --- charging -------------------------------------------------------------------

// ChargeTicket is a reservation taken against a reseller's balance, held while
// the client write it paid for is attempted.
type ChargeTicket struct {
	// Active is false for an admin or super admin: they have no balance, so
	// there is nothing to reserve and nothing to roll back.
	Active    bool
	UserId    int
	Email     string
	InboundId int
	Quote     ChargeQuote
	Create    bool
	// PrevCharged is what to restore on rollback.
	PrevCharged int64
}

// postedClient pulls the single client out of a client-mutating request body.
//
// Exactly one, always: every one of those routes posts one, and more than one
// would let a single reservation pay for several accounts.
func postedClient(data *model.Inbound) (map[string]any, map[string]any, []any, error) {
	settings := map[string]any{}
	if err := json.Unmarshal([]byte(data.Settings), &settings); err != nil {
		return nil, nil, nil, err
	}
	clients, _ := settings["clients"].([]any)
	if len(clients) != 1 {
		return nil, nil, nil, errors.New("expected exactly one client in the request")
	}
	cm, ok := clients[0].(map[string]any)
	if !ok {
		return nil, nil, nil, errors.New("malformed client in the request")
	}
	return cm, settings, clients, nil
}

// applyToSettings writes the priced decisions back into the request body.
//
// The blob has to be patched before InboundService parses it, and doing the
// surgery in one place beats repeating it at every call site.
func applyToSettings(data *model.Inbound, profile *model.ResellerProfile, q ChargeQuote,
	cm map[string]any, settings map[string]any, clients []any) error {
	// Overwrite rather than validate: the form is the reseller's, and a posted
	// expiry that disagrees with the factor is not an error to report back, it is
	// a field they should never have had.
	if q.ForceExpiry {
		cm["expiryTime"] = q.ExpiryTime
	}
	if !profile.AllowExternalProxy {
		delete(cm, "externalProxy")
	}
	// SECURITY: strip the auto-renew period. `reset` is a number of DAYS after
	// which autoRenewClients (web/service/inbound.go) zeroes an account's up and
	// down counters, re-enables it, and pushes its deadline forward, on a timer,
	// forever. Nothing in that job consults a balance.
	//
	// Left settable, it is an unlimited-traffic switch: a reseller sells one
	// gigabyte, sets reset=1, and the account is handed a fresh gigabyte every
	// day for as long as it exists, charged once. Every other way of giving an
	// account more traffic goes through Quote; this one bypassed it entirely.
	//
	// Resellers top up manually instead, which IS priced, and a reset they ask
	// for by hand is priced too (PrepareClientReset).
	delete(cm, "reset")
	clients[0] = cm
	settings["clients"] = clients
	patched, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	data.Settings = string(patched)
	return nil
}

// PrepareClientCreate prices a new account, rewrites the posted client to match
// the reseller's limits, and RESERVES the balance.
//
// The reservation happens before the client is written on purpose. A crash
// between the two loses the reseller balance an admin can recharge; the reverse
// order loses the panel real traffic with no record of it. Both directions of
// failure exist, and this is the one an operator can fix.
//
// Returns an inactive ticket for an admin or super admin: they have no balance,
// so there is nothing to price and nothing to roll back.
func (s *ResellerService) PrepareClientCreate(user *model.User, data *model.Inbound) (ChargeTicket, error) {
	if user == nil || !user.IsReseller {
		return ChargeTicket{}, nil
	}
	profile, err := s.ProfileFor(user.Id)
	if err != nil {
		return ChargeTicket{}, err
	}
	cm, settings, clients, err := postedClient(data)
	if err != nil {
		return ChargeTicket{}, err
	}
	email, _ := cm["email"].(string)
	if email == "" {
		return ChargeTicket{}, errors.New("client email is required")
	}

	// SECURITY: refuse an email that already belongs to someone, BEFORE reserving.
	//
	// AddInboundClient rejects duplicate emails too, but it runs after this, and
	// the reservation writes a ResellerClient row keyed on the email in between.
	// That row is what OwnsClientEmail answers from, so for the width of the
	// failed create the reseller genuinely owned an ADMIN's account: long enough
	// for a second, concurrent request to edit or delete it. Rollback closes the
	// window afterwards, and "afterwards" is not a security boundary.
	//
	// The same check the create path itself uses, so the two cannot disagree
	// about what "taken" means.
	var inboundService InboundService
	if taken, terr := inboundService.checkEmailsExistForClients([]model.Client{{Email: email}}); terr != nil {
		return ChargeTicket{}, terr
	} else if taken != "" {
		return ChargeTicket{}, duplicateEmailError(taken)
	}

	q, err := Quote(QuoteInput{
		Profile:   *profile,
		Create:    true,
		NewTotal:  jsonInt64(cm["totalGB"]),
		NowMillis: time.Now().UnixMilli(),
	})
	if err != nil {
		return ChargeTicket{}, err
	}
	if err := applyToSettings(data, profile, q, cm, settings, clients); err != nil {
		return ChargeTicket{}, err
	}

	ticket := ChargeTicket{
		Active: true, UserId: user.Id, Email: email,
		InboundId: data.Id, Quote: q, Create: true,
	}
	if err := s.reserve(ticket); err != nil {
		return ChargeTicket{}, err
	}
	return ticket, nil
}

// PrepareClientUpdate prices an edit of an existing account.
//
// Keyed on clientId, the route's path parameter, NOT on the posted email: the
// panel lets an account be renamed, so the email in the body may be one the
// ledger has never seen. Resolving the stored client first is what makes a
// rename priceable at all, and the caller finishes the job with RenameClient
// once the write has landed.
func (s *ResellerService) PrepareClientUpdate(user *model.User, data *model.Inbound, clientId string) (ChargeTicket, error) {
	if user == nil || !user.IsReseller {
		return ChargeTicket{}, nil
	}
	profile, err := s.ProfileFor(user.Id)
	if err != nil {
		return ChargeTicket{}, err
	}
	cm, settings, clients, err := postedClient(data)
	if err != nil {
		return ChargeTicket{}, err
	}

	oldEmail, err := s.storedClientEmail(data.Id, clientId)
	if err != nil {
		return ChargeTicket{}, err
	}
	// The account being edited must already be theirs. The route middleware only
	// proves they can reach the INBOUND, which they share with admins, so it
	// cannot answer this.
	owner, err := s.ClientOwner(oldEmail)
	if err != nil {
		return ChargeTicket{}, err
	}
	if owner == nil || owner.UserId != user.Id {
		return ChargeTicket{}, ErrClientNotOwned
	}

	ct := &xray.ClientTraffic{}
	err = database.GetDB().Model(&xray.ClientTraffic{}).Where("email = ?", oldEmail).First(ct).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return ChargeTicket{}, err
	}
	in := QuoteInput{
		Profile:       *profile,
		NewTotal:      jsonInt64(cm["totalGB"]),
		OldTotal:      ct.Total,
		OldCharged:    owner.ChargedBytes,
		CurrentExpiry: ct.ExpiryTime,
		NowMillis:     time.Now().UnixMilli(),
	}
	if consumed := ct.AllTime - owner.AllTimeBase; consumed > 0 {
		in.Consumed = consumed
	}

	q, err := Quote(in)
	if err != nil {
		return ChargeTicket{}, err
	}
	// SECURITY: a reseller cannot switch a depleted account back on without
	// paying for the traffic that would let it run.
	//
	// disableInvalidClients turns depleted accounts off, but it is a cron job on
	// a 10 second tick, so a manual re-enable buys 10 seconds of unmetered
	// traffic and a script that re-enables on a loop keeps a paid-out account
	// alive indefinitely. The ledger stays perfectly correct while the customer
	// keeps browsing, which is the worst shape a bypass can take.
	//
	// Forced off rather than refused: the job would reach the same state within
	// the tick, so this only stops the window being useful, and it leaves a
	// legitimate edit (raising the quota, which lands above) working normally.
	if enable, _ := cm["enable"].(bool); enable && depletedAfter(ct, in.NewTotal) {
		cm["enable"] = false
	}
	if err := applyToSettings(data, profile, q, cm, settings, clients); err != nil {
		return ChargeTicket{}, err
	}

	ticket := ChargeTicket{
		Active: true, UserId: user.Id, Email: oldEmail, InboundId: data.Id,
		Quote: q, Create: false, PrevCharged: owner.ChargedBytes,
	}
	if err := s.reserve(ticket); err != nil {
		return ChargeTicket{}, err
	}
	return ticket, nil
}

// PrepareClientReset prices a traffic-counter reset and reserves the balance it
// costs. Inactive for an admin, whose resets are free.
//
// Allowed for a reseller, not refused, but never free: see QuoteInput.Reset for
// why zeroing the counters is a purchase.
func (s *ResellerService) PrepareClientReset(user *model.User, email string) (ChargeTicket, error) {
	if user == nil || !user.IsReseller {
		return ChargeTicket{}, nil
	}
	profile, err := s.ProfileFor(user.Id)
	if err != nil {
		return ChargeTicket{}, err
	}
	owner, err := s.ClientOwner(email)
	if err != nil {
		return ChargeTicket{}, err
	}
	if owner == nil || owner.UserId != user.Id {
		return ChargeTicket{}, ErrResetNotOwned
	}

	ct := &xray.ClientTraffic{}
	err = database.GetDB().Model(&xray.ClientTraffic{}).Where("email = ?", email).First(ct).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return ChargeTicket{}, err
	}

	q, err := Quote(QuoteInput{
		Profile:       *profile,
		Reset:         true,
		ClearedBytes:  ct.Up + ct.Down,
		OldCharged:    owner.ChargedBytes,
		NewTotal:      ct.Total,
		CurrentExpiry: ct.ExpiryTime,
		NowMillis:     time.Now().UnixMilli(),
	})
	if err != nil {
		return ChargeTicket{}, err
	}

	ticket := ChargeTicket{
		Active: true, UserId: user.Id, Email: email, InboundId: owner.InboundId,
		Quote: q, Create: false, PrevCharged: owner.ChargedBytes,
	}
	if err := s.reserve(ticket); err != nil {
		return ChargeTicket{}, err
	}
	return ticket, nil
}

// Balance is a reseller's own standing, for the chip on their inbounds page.
type Balance struct {
	IsReseller     bool  `json:"isReseller"`
	Unlimited      bool  `json:"unlimited"`
	AllowanceBytes int64 `json:"allowanceBytes"`
	SpentBytes     int64 `json:"spentBytes"`
	AvailableBytes int64 `json:"availableBytes"`
}

// BalanceFor reports what this caller has left. Not a reseller reports
// IsReseller false and zeroes, so the endpoint is safe to call from every page
// without the frontend branching first.
func (s *ResellerService) BalanceFor(user *model.User) Balance {
	if user == nil || !user.IsReseller {
		return Balance{}
	}
	p, err := s.ProfileFor(user.Id)
	if err != nil {
		return Balance{IsReseller: true}
	}
	return Balance{
		IsReseller:     true,
		Unlimited:      p.Unlimited,
		AllowanceBytes: p.AllowanceBytes,
		SpentBytes:     p.SpentBytes,
		AvailableBytes: AvailableBytes(*p),
	}
}

// depletedAfter reports whether an account has already moved everything a given
// quota would allow it, and so must not be running.
//
// Reads Up+Down rather than AllTime, deliberately: this asks the same question
// the enforcement job asks (`up + down >= total`), and answering it any other
// way would let the two disagree about which accounts are alive. Total 0 is
// unlimited and never depleted.
func depletedAfter(ct *xray.ClientTraffic, total int64) bool {
	if ct == nil || total <= 0 {
		return false
	}
	return ct.Up+ct.Down >= total
}

// storedClientEmail resolves a route's :clientId back to the email the ledger
// keys on, using the same protocol-dependent identity field the inbound service
// matches with.
func (s *ResellerService) storedClientEmail(inboundId int, clientId string) (string, error) {
	if clientId == "" {
		return "", ErrClientNotOwned
	}
	var inboundService InboundService
	inbound, err := inboundService.GetInbound(inboundId)
	if err != nil || inbound == nil {
		return "", ErrClientNotOwned
	}
	clients, err := inboundService.GetClients(inbound)
	if err != nil {
		return "", err
	}
	for _, c := range clients {
		if clientIdentity(inbound.Protocol, c) == clientId {
			return c.Email, nil
		}
	}
	return "", ErrClientNotOwned
}

// reserve applies the quote: the balance move and the ownership row, in one
// transaction so no state exists where one landed and the other did not.
func (s *ResellerService) reserve(t ChargeTicket) error {
	if !t.Active {
		return nil
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := addSpent(tx, t.UserId, t.Quote.DeltaSpent); err != nil {
			return err
		}
		if t.Create {
			// A same-email account may have existed before and been deleted; its
			// ClientTraffic row is what AllTimeBase must start from, so consumption
			// is never counted twice.
			var base int64
			ct := &xray.ClientTraffic{}
			if err := tx.Model(&xray.ClientTraffic{}).Where("email = ?", t.Email).First(ct).Error; err == nil {
				base = ct.AllTime
			}
			return tx.Create(&model.ResellerClient{
				Email:        t.Email,
				InboundId:    t.InboundId,
				UserId:       t.UserId,
				ChargedBytes: t.Quote.NewCharged,
				AllTimeBase:  base,
			}).Error
		}
		// charged_bytes alone, and InboundId deliberately left where the create put
		// it: it is the HOME inbound, a display value, and an edit does not move an
		// account's home. There is nothing to keep in step here because nothing
		// decides by that column any more; the questions it used to answer ("which
		// inbound is this on") are resolved from the memberships instead, since one
		// account is served on N of them and this row can only hold one. Writing the
		// edited inbound here would be strictly worse than leaving it: the value
		// would swing to whichever membership was edited last while still describing
		// only one of them.
		return tx.Model(&model.ResellerClient{}).Where("email = ?", t.Email).
			Update("charged_bytes", t.Quote.NewCharged).Error
	})
}

// Rollback undoes a reservation whose client write failed.
func (s *ResellerService) Rollback(t ChargeTicket) error {
	if !t.Active {
		return nil
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := restoreSpent(tx, t.UserId, -t.Quote.DeltaSpent); err != nil {
			return err
		}
		if t.Create {
			return tx.Where("email = ?", t.Email).Delete(&model.ResellerClient{}).Error
		}
		return tx.Model(&model.ResellerClient{}).Where("email = ?", t.Email).
			Update("charged_bytes", t.PrevCharged).Error
	})
}

// UsageSnapshot records how much each named account has moved in its lifetime,
// for refunding after it is deleted.
//
// MUST be called BEFORE the delete. Deleting a client runs DelClientStat, which
// removes the client_traffics row that holds AllTime, so a refund computed
// afterwards reads consumption as ZERO and hands back the entire charge. That is
// the whole balance system defeated by one button: sell an account, let the
// customer spend all of it, delete it, get every byte back.
//
// This is why no refund helper reads AllTime for itself any more. The consumed
// figure has to be captured while the row that proves it still exists, so it is
// a parameter, and the caller cannot forget to take it without the compiler
// asking where it is.
func (s *ResellerService) UsageSnapshot(emails []string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(emails) == 0 {
		return out, nil
	}
	var rows []xray.ClientTraffic
	if err := database.GetDB().Model(&xray.ClientTraffic{}).
		Where("email IN (?)", emails).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, ct := range rows {
		out[emailKey(ct.Email)] = ct.AllTime
	}
	return out, nil
}

// UsageOf is the single-account form of UsageSnapshot, with the same rule: call
// it before the delete, not after.
func (s *ResellerService) UsageOf(email string) (int64, bool, error) {
	snap, err := s.UsageSnapshot([]string{email})
	if err != nil {
		return 0, false, err
	}
	used, known := snap[emailKey(email)]
	return used, known, nil
}

// OwnedEmailsOnInbound lists the reseller-owned accounts one inbound SERVES, so a
// caller about to delete that inbound can snapshot their usage first and hand both
// to DropInbound.
//
// Resolved from what the inbound actually holds and not from
// ResellerClient.InboundId: that column names the account's home inbound, exactly
// one of the N it may be on, so keying on it both missed accounts really served
// here (their home is elsewhere, so their usage was never snapshotted and their
// refund was silently withheld) and listed accounts that are not.
//
// Returns the LEDGER's spelling of each email, because that is what ClientOwner and
// the refund path match on.
func (s *ResellerService) OwnedEmailsOnInbound(inboundId int) ([]string, error) {
	db := database.GetDB()
	served, err := inboundAccountEmails(db, inboundId)
	if err != nil {
		return nil, err
	}
	if len(served) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(served))
	for _, email := range served {
		keys = append(keys, emailKey(email))
	}
	var emails []string
	err = db.Model(&model.ResellerClient{}).
		Where("LOWER(TRIM(email)) IN (?)", keys).Pluck("email", &emails).Error
	return emails, err
}

// addSpent moves a reseller's spent counter. Expressed as a SQL expression
// rather than read-modify-write so two concurrent client creates cannot both
// read the same value and lose one of the debits.
//
// SECURITY: a DEBIT also re-checks the balance in the same statement, and fails
// when it no longer fits. Quote's check happens against a profile read earlier
// in the request, so two concurrent creates can both see the same headroom and
// both pass: with 10 GB free, two 6 GB accounts are approved independently and
// the reseller sells 12. The WHERE clause below is the only place that decision
// is made atomically with the write, so it is the one that has to be right.
//
// Refunds are never blocked. Giving balance back must not depend on there being
// room for it, or an over-sold reseller could never be unwound.
func addSpent(tx *gorm.DB, userId int, delta int64) error {
	if delta == 0 {
		return nil
	}
	q := tx.Model(&model.ResellerProfile{}).Where("user_id = ?", userId)
	if delta > 0 {
		q = q.Where("unlimited = ? OR spent_bytes + ? <= allowance_bytes", true, delta)
	}
	res := q.Update("spent_bytes", gorm.Expr("spent_bytes + ?", delta))
	if res.Error != nil {
		return res.Error
	}
	if delta > 0 && res.RowsAffected == 0 {
		// Either the row vanished or the headroom did. Both mean this charge must
		// not stand, and the caller's reservation fails with it.
		return ErrInsufficientBalance
	}
	return nil
}

// restoreSpent moves the counter WITHOUT the headroom check, for undoing a move
// that already happened.
//
// A rollback is a correction, not a purchase, and it must never be refused. The
// case that needs it is undoing a DEDUCT: that refunded, so unwinding it debits,
// and routing that debit through the guard means an allowance an admin lowered
// in between can block the unwind. The reseller would keep the refund for a
// deduct that never landed, which is the guard causing the exact leak it exists
// to stop.
func restoreSpent(tx *gorm.DB, userId int, delta int64) error {
	if delta == 0 {
		return nil
	}
	return tx.Model(&model.ResellerProfile{}).Where("user_id = ?", userId).
		Update("spent_bytes", gorm.Expr("spent_bytes + ?", delta)).Error
}

// jsonInt64 reads a number out of an unmarshalled settings blob, which decodes
// every number as float64.
func jsonInt64(v any) int64 {
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

// --- profile CRUD ---------------------------------------------------------------

// ResellerView is a reseller as the Resellers page shows it. Hand-built rather
// than returning model.User so the password hash and TOTP secret can never be
// serialized.
type ResellerView struct {
	Id              int    `json:"id"`
	Username        string `json:"username"`
	Nickname        string `json:"nickname"`
	Enable          bool   `json:"enable"`
	TwoFactorEnable bool   `json:"twoFactorEnable"`

	AllowanceBytes int64 `json:"allowanceBytes"`
	SpentBytes     int64 `json:"spentBytes"`
	AvailableBytes int64 `json:"availableBytes"`
	Unlimited      bool  `json:"unlimited"`

	DaysPerGB           int  `json:"daysPerGb"`
	MinCreateGB         int  `json:"minCreateGb"`
	MinAddGB            int  `json:"minAddGb"`
	AllowExternalProxy  bool `json:"allowExternalProxy"`
	AllowOverview       bool `json:"allowOverview"`
	AllowOverviewManage bool `json:"allowOverviewManage"`

	InboundIds  []int `json:"inboundIds"`
	ClientCount int64 `json:"clientCount"`
	CreatedBy   int   `json:"createdBy"`
}

// ResellerSpec is the mutable shape of a reseller as the UI submits it.
type ResellerSpec struct {
	Username string
	// Password empty on update means "keep the existing one".
	Password string
	Nickname string
	Enable   bool

	// AllowanceGB seeds the balance on CREATE and is ignored on update, where
	// Recharge is the only way to move it: an admin typing over the total would
	// silently rewrite history and either free or strand every outstanding
	// account.
	AllowanceGB int
	Unlimited   bool

	DaysPerGB           int
	MinCreateGB         int
	MinAddGB            int
	AllowExternalProxy  bool
	AllowOverview       bool
	AllowOverviewManage bool

	// InboundIds is the exact set this reseller may sell on. Replaces whatever
	// they had; empty means none, which is a legitimate state.
	InboundIds []int
}

// GetResellers lists the resellers this caller may manage. A super admin sees
// every one; anyone else sees only those they created.
func (s *ResellerService) GetResellers(caller *model.User) ([]ResellerView, error) {
	if caller == nil {
		return []ResellerView{}, nil
	}
	db := database.GetDB()

	var profiles []model.ResellerProfile
	q := db.Model(&model.ResellerProfile{})
	if !caller.IsSuperAdmin {
		q = q.Where("created_by = ?", caller.Id)
	}
	if err := q.Find(&profiles).Error; err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return []ResellerView{}, nil
	}

	ids := make([]int, 0, len(profiles))
	byUser := make(map[int]model.ResellerProfile, len(profiles))
	for _, p := range profiles {
		ids = append(ids, p.UserId)
		byUser[p.UserId] = p
	}

	var users []*model.User
	if err := db.Model(model.User{}).Where("id IN (?) AND is_reseller = ?", ids, true).
		Order("id asc").Find(&users).Error; err != nil {
		return nil, err
	}

	// One query each for grants and account counts, rather than one per reseller.
	var grants []model.InboundAccess
	if err := db.Model(&model.InboundAccess{}).Where("user_id IN (?)", ids).Find(&grants).Error; err != nil {
		return nil, err
	}
	grantsBy := make(map[int][]int, len(users))
	for _, g := range grants {
		grantsBy[g.UserId] = append(grantsBy[g.UserId], g.InboundId)
	}

	type countRow struct {
		UserId int
		N      int64
	}
	var counts []countRow
	if err := db.Model(&model.ResellerClient{}).Where("user_id IN (?)", ids).
		Select("user_id as user_id, count(*) as n").Group("user_id").Scan(&counts).Error; err != nil {
		return nil, err
	}
	countBy := make(map[int]int64, len(counts))
	for _, c := range counts {
		countBy[c.UserId] = c.N
	}

	out := make([]ResellerView, 0, len(users))
	for _, u := range users {
		p := byUser[u.Id]
		gs := grantsBy[u.Id]
		if gs == nil {
			gs = []int{} // marshal as [], not null: the UI ticks against it
		}
		available := p.AllowanceBytes - p.SpentBytes
		if available < 0 {
			available = 0
		}
		out = append(out, ResellerView{
			Id:                  u.Id,
			Username:            u.Username,
			Nickname:            u.Nickname,
			Enable:              u.Enable,
			TwoFactorEnable:     u.TwoFactorEnable,
			AllowanceBytes:      p.AllowanceBytes,
			SpentBytes:          p.SpentBytes,
			AvailableBytes:      available,
			Unlimited:           p.Unlimited,
			DaysPerGB:           p.DaysPerGB,
			MinCreateGB:         p.MinCreateGB,
			MinAddGB:            p.MinAddGB,
			AllowExternalProxy:  p.AllowExternalProxy,
			AllowOverview:       p.AllowOverview,
			AllowOverviewManage: p.AllowOverviewManage,
			InboundIds:          gs,
			ClientCount:         countBy[u.Id],
			CreatedBy:           p.CreatedBy,
		})
	}
	return out, nil
}

// assertAssignable refuses inbounds the caller does not hold themselves.
//
// This is the clamp that closes the escalation: without it an admin holding
// manageResellers creates a reseller on ANOTHER admin's inbound, sets its
// password, logs in as it, and is now looking at inbounds they were never
// granted. A checklist that only renders the intersection is cosmetic; the save
// is one crafted form away, so the check has to be here.
func (s *ResellerService) assertAssignable(caller *model.User, inboundIds []int) error {
	if caller == nil {
		return ErrInboundNotAssignable
	}
	if caller.IsSuperAdmin || len(inboundIds) == 0 {
		return nil
	}
	var adminService AdminService
	ok, err := adminService.CanAccessAllInbounds(inboundIds, caller.Id)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInboundNotAssignable
	}
	return nil
}

// AssignableInbounds is the checklist a caller may pick from: every inbound for
// a super admin, only their own for anyone else.
func (s *ResellerService) AssignableInbounds(caller *model.User) ([]InboundBrief, error) {
	var adminService AdminService
	all, err := adminService.AllInboundsBrief()
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return []InboundBrief{}, nil
	}
	if caller.IsSuperAdmin {
		return all, nil
	}
	ids, err := adminService.AccessibleInboundIds(caller.Id)
	if err != nil {
		return nil, err
	}
	allowed := make(map[int]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}
	out := make([]InboundBrief, 0, len(all))
	for _, b := range all {
		if allowed[b.Id] {
			out = append(out, b)
		}
	}
	return out, nil
}

// AddReseller creates a reseller and its profile.
func (s *ResellerService) AddReseller(caller *model.User, spec ResellerSpec) (*model.User, error) {
	spec.Username = normalizeUsername(spec.Username)
	if spec.Username == "" {
		return nil, errors.New("username is required")
	}
	if spec.Password == "" {
		return nil, errors.New("password is required")
	}
	if err := s.assertAssignable(caller, spec.InboundIds); err != nil {
		return nil, err
	}

	db := database.GetDB()
	var adminService AdminService
	taken, err := adminService.usernameTaken(db, spec.Username, 0)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrResellerNameTaken
	}
	hash, err := crypto.HashPasswordAsBcrypt(spec.Password)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Username: spec.Username,
		Password: hash,
		Nickname: strings.TrimSpace(spec.Nickname),
		Enable:   spec.Enable,
		// Never a super admin, and the stored mask stays 0: the role derives it
		// (see model.Can), so a future demotion lands them with nothing rather
		// than with a stale grant.
		IsSuperAdmin: false,
		IsReseller:   true,
		Permissions:  0,
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		// Enable carries gorm:"default:1", and GORM omits a zero-valued field with
		// a default from the INSERT, so a reseller created DISABLED would be stored
		// enabled and could log in. Same trap AddAdmin documents.
		if !spec.Enable {
			if err := tx.Model(model.User{}).Where("id = ?", user.Id).
				Update("enable", false).Error; err != nil {
				return err
			}
		}
		return tx.Create(&model.ResellerProfile{
			UserId:              user.Id,
			AllowanceBytes:      gbToBytes(spec.AllowanceGB),
			Unlimited:           spec.Unlimited,
			DaysPerGB:           spec.DaysPerGB,
			MinCreateGB:         spec.MinCreateGB,
			MinAddGB:            spec.MinAddGB,
			AllowExternalProxy:  spec.AllowExternalProxy,
			AllowOverview:       spec.AllowOverview,
			AllowOverviewManage: spec.AllowOverviewManage,
			CreatedBy:           caller.Id,
		}).Error
	})
	if err != nil {
		return nil, err
	}
	user.Enable = spec.Enable
	if err := adminService.SetInboundAccess(user.Id, spec.InboundIds); err != nil {
		return nil, err
	}
	return user, nil
}

// manageable loads a reseller the caller is allowed to touch, or reports it as
// not found. Not-found rather than forbidden, so the endpoint cannot be used to
// enumerate other admins' resellers.
func (s *ResellerService) manageable(caller *model.User, id int) (*model.User, *model.ResellerProfile, error) {
	if caller == nil {
		return nil, nil, ErrResellerNotFound
	}
	user := &model.User{}
	if err := database.GetDB().Model(model.User{}).Where("id = ?", id).First(user).Error; err != nil {
		return nil, nil, ErrResellerNotFound
	}
	if !user.IsReseller {
		return nil, nil, ErrResellerNotFound
	}
	profile, err := s.ProfileFor(id)
	if err != nil {
		return nil, nil, ErrResellerNotFound
	}
	if !caller.IsSuperAdmin && profile.CreatedBy != caller.Id {
		return nil, nil, ErrResellerNotFound
	}
	return user, profile, nil
}

// UpdateReseller edits a reseller. An empty password leaves the existing one
// alone. AllowanceGB is ignored here; see Recharge.
func (s *ResellerService) UpdateReseller(caller *model.User, id int, spec ResellerSpec) error {
	user, _, err := s.manageable(caller, id)
	if err != nil {
		return err
	}
	spec.Username = normalizeUsername(spec.Username)
	if spec.Username == "" {
		return errors.New("username is required")
	}
	if err := s.assertAssignable(caller, spec.InboundIds); err != nil {
		return err
	}

	db := database.GetDB()
	var adminService AdminService
	taken, err := adminService.usernameTaken(db, spec.Username, id)
	if err != nil {
		return err
	}
	if taken {
		return ErrResellerNameTaken
	}

	updates := map[string]any{
		"username": spec.Username,
		"nickname": strings.TrimSpace(spec.Nickname),
		"enable":   spec.Enable,
		// Re-asserted on every save so a row that acquired a mask some other way
		// cannot keep it.
		"permissions":    model.Permission(0),
		"is_super_admin": false,
		"is_reseller":    true,
	}
	if spec.Password != "" {
		hash, err := crypto.HashPasswordAsBcrypt(spec.Password)
		if err != nil {
			return err
		}
		updates["password"] = hash
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(model.User{}).Where("id = ?", user.Id).Updates(updates).Error; err != nil {
			return err
		}
		return tx.Model(&model.ResellerProfile{}).Where("user_id = ?", user.Id).
			Updates(map[string]any{
				"unlimited":             spec.Unlimited,
				"days_per_gb":           spec.DaysPerGB,
				"min_create_gb":         spec.MinCreateGB,
				"min_add_gb":            spec.MinAddGB,
				"allow_external_proxy":  spec.AllowExternalProxy,
				"allow_overview":        spec.AllowOverview,
				"allow_overview_manage": spec.AllowOverviewManage,
			}).Error
	})
	if err != nil {
		return err
	}
	return adminService.SetInboundAccess(user.Id, spec.InboundIds)
}

// Recharge moves a reseller's allowance. Positive tops them up; negative takes
// back, clamped so an allowance never goes below zero.
func (s *ResellerService) Recharge(caller *model.User, id int, deltaBytes int64) error {
	_, profile, err := s.manageable(caller, id)
	if err != nil {
		return err
	}
	next := profile.AllowanceBytes + deltaBytes
	if next < 0 {
		next = 0
	}
	return database.GetDB().Model(&model.ResellerProfile{}).
		Where("user_id = ?", id).Update("allowance_bytes", next).Error
}

// Delete modes decide the fate of a reseller's accounts when it still owns some.
const (
	DeleteModeKeep    = "keep"    // drop the reseller, hand its accounts to the house
	DeleteModeCascade = "cascade" // drop the reseller and delete its accounts
)

// DeleteResult reports what a delete touched so the controller can reconfigure
// the daemons whose clients a cascade removed. Zero-valued for a keep or a
// childless reseller: nothing on the data plane changed, nothing to regenerate.
type DeleteResult struct {
	Protocols       map[model.Protocol]bool // VPN daemon protocols to regenerate, deduped
	NeedXrayRestart bool                    // a native client the live Xray API could not drop
	Deleted         int                     // accounts the cascade removed
	Kept            int                     // last-on-inbound / stale accounts handed to the house
}

// DeleteReseller removes a reseller. With accounts still owned, mode decides
// their fate: "cascade" deletes them the same way the per-account delete route
// does, "keep" hands them to the house (absence of a ResellerClient row is
// exactly "the admin owns this account"). An empty mode with accounts present
// refuses, as it always has, so the destructive path is never the default and an
// old client or a script cannot silently destroy or orphan accounts.
//
// On cascade the accounts are removed BEFORE the reseller, so a mid-cascade
// failure leaves "some accounts gone, reseller still owns the rest" (retryable)
// rather than a deleted reseller with live accounts nobody bills.
func (s *ResellerService) DeleteReseller(caller *model.User, id int, mode string) (DeleteResult, error) {
	user, _, err := s.manageable(caller, id)
	if err != nil {
		return DeleteResult{}, err
	}
	db := database.GetDB()
	var rows []model.ResellerClient
	if err := db.Where("user_id = ?", id).Find(&rows).Error; err != nil {
		return DeleteResult{}, err
	}
	if len(rows) == 0 {
		return DeleteResult{}, s.dropReseller(user.Id) // childless: mode is moot
	}
	switch mode {
	case DeleteModeKeep:
		// The accounts stay byte-for-byte; only the ownership ledger goes, which
		// makes them house-owned and visible to the inbound's admin.
		if err := db.Where("user_id = ?", id).Delete(&model.ResellerClient{}).Error; err != nil {
			return DeleteResult{}, err
		}
		return DeleteResult{}, s.dropReseller(user.Id)
	case DeleteModeCascade:
		res, err := s.cascadeClients(rows)
		if err != nil {
			return res, err // stop before dropping the reseller so a retry is possible
		}
		return res, s.dropReseller(user.Id)
	default:
		return DeleteResult{}, fmt.Errorf("%w (%d)", ErrResellerHasClients, len(rows))
	}
}

// dropReseller removes the reseller row, its profile and its inbound grants once
// the accounts have been dealt with. The balance vanishes with the profile: a
// deleted reseller has nothing to refund to.
func (s *ResellerService) dropReseller(userId int) error {
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userId).Delete(&model.ResellerProfile{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userId).Delete(&model.InboundAccess{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", userId).Delete(&model.User{}).Error
	})
}

// cascadeClients deletes every VPN account a reseller owns the same way the
// single-account delete route does (settings surgery, IP release, traffic-row
// removal, live Xray RemoveUser) and drops each ledger row. It returns the set
// of daemon protocols it touched so the caller can regenerate their configs.
//
// EVERY membership of each account, not the one its ledger row names. An account
// is one identity on N inbounds, and deleting it from the single inbound recorded
// in ResellerClient.InboundId left N-1 live memberships behind with no ledger row,
// which by this table's own rule means the house owns them: a working account,
// serving traffic, that nobody is billed for and no reseller page shows.
//
// Two accounts are handed to the house instead of deleted: one whose last client on
// an admin's inbound cannot be removed (an inbound may not be emptied, and is not
// ours to destroy) and one that is already gone (stale ledger). Neither aborts the
// cascade, and the ledger row goes either way, because the reseller it belongs to
// is being deleted and a charge against a user that no longer exists can never be
// settled.
func (s *ResellerService) cascadeClients(rows []model.ResellerClient) (DeleteResult, error) {
	res := DeleteResult{Protocols: map[model.Protocol]bool{}}
	db := database.GetDB()
	var inboundService InboundService
	dropLedger := func(email string) error {
		return db.Where("email = ?", email).Delete(&model.ResellerClient{}).Error
	}
	for _, rc := range rows {
		ids, err := servingInboundIds(db, rc.Email)
		if err != nil {
			return res, err
		}
		removed, survived := 0, 0
		for _, id := range ids {
			inbound, err := inboundService.GetInbound(id)
			if err != nil || inbound == nil {
				continue // gone between resolving and now: nothing left to remove
			}
			// The settings' own spelling of the email, not the ledger's. Identity is
			// case-insensitive across the panel and these two tables are written by
			// different paths, but DelInboundClientByEmail matches the settings entry
			// EXACTLY: handed the ledger's spelling of an account stored mixed-case, it
			// reports "not found" and the account survives the cascade as a live,
			// unbilled client.
			email := rc.Email
			if clients, cerr := inboundService.GetClients(inbound); cerr == nil {
				for _, c := range clients {
					if accountKey(c.Email) == accountKey(rc.Email) {
						email = c.Email
						break
					}
				}
			}
			needRestart, err := inboundService.DelInboundClientByEmail(id, email)
			if err != nil {
				msg := err.Error()
				switch {
				case strings.Contains(msg, "no client remained"):
					// Last client on the inbound: the account keeps this membership
					// rather than the admin's inbound being destroyed under it.
					survived++
				case strings.Contains(msg, "not found"):
					// Already gone from this one. Neither a delete nor a survivor.
				default:
					return res, err
				}
				continue
			}
			res.Protocols[inbound.Protocol] = true
			res.NeedXrayRestart = res.NeedXrayRestart || needRestart
			removed++
		}
		if derr := dropLedger(rc.Email); derr != nil {
			return res, derr
		}
		// Reported by what became of the ACCOUNT, not by how many memberships moved:
		// one that still serves anywhere was handed to the house, whatever else the
		// cascade managed to remove.
		if survived > 0 || removed == 0 {
			res.Kept++
			continue
		}
		res.Deleted++
	}
	return res, nil
}
