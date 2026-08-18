package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

// Bulk is the one client path where the caller names their own targets. Every
// other route the reseller role touches identifies a single account in the URL,
// where a middleware can prove ownership before the handler runs; a bulk request
// carries an arbitrary list of (inbound, email) pairs in its body and
// InboundService.BulkUpdateClients trusts that list completely.
//
// So this file does two jobs, and the pricing is the second one. The first is
// SCOPING: the permission bit says a reseller may run bulk operations and the
// inbound grant says they may reach the inbound, and neither says a word about
// whose accounts are on it. Without scopeBulkTargets, one POST applies to every
// admin account on a shared inbound.
//
// The op table, and why each op is priced the way it is:
//
//	addTraffic   every surviving target gains AmountBytes, so the batch costs
//	             AmountBytes x N and the balance is checked ONCE against that
//	             total. Per-account checks would let a reseller with room for one
//	             account hand out fifty.
//	subTraffic   a refund per account, clamped at what that account has already
//	             CONSUMED and never above what it was charged. The same rule the
//	             single-account deduct runs, and literally the same code: bytes
//	             the customer already moved are gone.
//	delete       free here. The refund lands after the delete does, and only for
//	             the accounts that really went (see the controller).
//	enable, disable, freeze, unfreeze
//	             free. None of them changes a quota, so no byte moves either way.
//	             Freeze in particular is not a refund: the account keeps the quota
//	             its reseller paid for and can be unfrozen whenever they like.
//	addDays      free when the reseller sets duration themselves, refused under
//	             days-per-GB where duration is not theirs to set.
//	subDays      refused outright.

const (
	bulkOpEnable     = "enable"
	bulkOpUnfreeze   = "unfreeze"
	bulkOpAddTraffic = "addTraffic"
	bulkOpSubTraffic = "subTraffic"
	bulkOpAddDays    = "addDays"
	bulkOpSubDays    = "subDays"
	bulkOpDelete     = "delete"
	// The two membership operations. They do not run through BulkUpdateClients at
	// all (the controller routes them to the accounts layer instead), and are named
	// here so the reseller policy for every bulk op is stated in one table: an op
	// missing from bulkOpAllowed is silently ALLOWED.
	bulkOpAddInbounds    = "addInbounds"
	bulkOpRemoveInbounds = "removeInbounds"
)

var (
	// Refused on the operator's instruction, and the ledger has nothing to say
	// against it: days are not a currency this balance holds, so a bulk day cut
	// moves no bytes and leaves no trace any check in this file could read. A
	// reseller who wants one account shorter can still edit that account.
	ErrBulkNoSubDays = errors.New("resellers cannot take days off an account in bulk")
	// Under days-per-GB an account's duration IS its traffic times a factor, and
	// the reseller has no expiry field at all. A bulk day change would be
	// overwritten by the next edit that recomputes it, so it is not a shorter
	// account, it is a temporarily shorter one.
	ErrBulkDaysAreDerived = errors.New("your accounts' duration is set by their traffic, so days cannot be changed by hand")
	// The mirror of the above, and the reason it is a refusal rather than a
	// price: under days-per-GB, traffic and duration are ONE lever. The bulk
	// applier moves totalGB and nothing else, so a priced bulk top-up would sell
	// bytes while silently leaving the deadline where it was. Edit those accounts
	// one at a time, where PrepareClientUpdate derives the new expiry.
	ErrBulkTrafficIsCoupled = errors.New("your accounts' duration follows their traffic, so traffic cannot be changed in bulk; edit them one at a time")
	// A negative amount turns an op into its opposite: a negative addTraffic
	// takes bytes away while debiting a negative number, which CREDITS the
	// reseller. Same class of bug as the negative quota Quote refuses.
	ErrBulkAmount = errors.New("that is not an amount of traffic to add or subtract")
	// Which inbounds an account is served on is the ADMIN's decision, not a lever
	// a reseller holds. Their grant says which inbounds they may sell FROM; it
	// says nothing about moving a customer between them, and the move is not
	// priced in bytes so the ledger has no opinion either. Concretely, a reseller
	// re-homing accounts would spend another admin's IP pool and user-limit
	// capacity on a shared inbound, and could park an account on an inbound with
	// a laxer limit than the one it was sold on. Refused for now: allowing it
	// needs a rule for whose capacity is being spent, not just an ownership test.
	ErrBulkNoMembership = errors.New("only an admin can move accounts between inbounds")
)

// BulkCharge is one account's new standing under a priced batch.
type BulkCharge struct {
	// Email is the LEDGER's spelling of the account, not the request's, because
	// it is the key the charge is written back on.
	Email       string
	NewCharged  int64
	PrevCharged int64
	// SetTotal and NewTotal carry the quota this batch was priced for. The applier
	// works per (inbound, email) target and recomputes the new quota from each
	// membership's own settings entry, while the price is per ACCOUNT and quoted
	// once, so an account on three inbounds was charged for one gigabyte and handed
	// three, from three different starting points, in whatever order the applier's
	// map happened to iterate. Writing the priced figure onto every membership after
	// the fact makes the applied result equal the priced one by construction.
	//
	// A flag rather than a zero check: totalGB 0 means UNLIMITED in a settings blob,
	// so a charge that carried no quota would uncap the account it was written to.
	SetTotal bool
	NewTotal int64
	// ForceExpiry and ExpiryTime carry the deadline Quote derived for this
	// account under days-per-GB. The generic bulk applier moves totalGB and
	// nothing else, so without writing these back a bulk top-up would sell bytes
	// and silently leave the deadline where it was. Applied after the batch
	// lands, by ApplyBulkCharges.
	ForceExpiry bool
	ExpiryTime  int64
}

// BulkTicket is a reservation covering a whole batch. One ticket rather than N,
// because the balance check that matters is against the batch total and a
// half-applied batch must be undoable in one call.
type BulkTicket struct {
	// Active is false for an admin, and for any reseller op that moves no bytes.
	// Nothing to reserve means nothing to roll back.
	Active     bool
	UserId     int
	DeltaSpent int64
	Charges    []BulkCharge
}

// PrepareBulk scopes a bulk request down to the caller's own accounts and
// reserves what the operation costs them.
//
// Returns an INACTIVE ticket for anyone who is not a reseller, having touched
// neither the request nor the ledger: an admin's bulk operation behaves exactly
// as it did before this file existed.
//
// Reserve first, apply second, matching PrepareClientCreate. A crash between the
// two loses the reseller balance an admin can hand back; the other order hands
// out traffic with nothing charged for it, which no operator can find later.
func (s *ResellerService) PrepareBulk(user *model.User, req *BulkClientUpdateRequest) (BulkTicket, error) {
	if user == nil || req == nil || !user.IsReseller {
		return BulkTicket{}, nil
	}
	profile, err := s.ProfileFor(user.Id)
	if err != nil {
		return BulkTicket{}, err
	}
	if err := bulkOpAllowed(*profile, req); err != nil {
		return BulkTicket{}, err
	}

	// Before anything is priced, because until this runs the target list is
	// simply whatever the caller typed into it.
	owned, err := s.OwnedEmails(user.Id)
	if err != nil {
		return BulkTicket{}, err
	}
	scopeBulkTargets(req, owned)

	if req.Op != bulkOpAddTraffic && req.Op != bulkOpSubTraffic {
		// SECURITY: these two are free, and on a DEPLETED account either is also a
		// traffic grant. disableInvalidClients switches those off again, but on a
		// 10 second cron tick, so a loop keeps accounts that have spent everything
		// they were sold permanently online. Dropped from the batch rather than
		// refused, so a mixed selection still switches on the ones with traffic
		// left.
		//
		// unfreeze belongs here as much as enable does: it writes enable=true just
		// the same (see applyBulkClientOp), and nothing in it looks at the quota.
		// Exempting it because it "only restores a deadline" was wrong.
		if req.Op == bulkOpEnable || req.Op == bulkOpUnfreeze {
			if err := s.dropDepletedTargets(req); err != nil {
				return BulkTicket{}, err
			}
		}
		return BulkTicket{}, nil // scoped, and free
	}

	// The applier's own clock, mirrored. Irrelevant to the two ops that reach
	// here (only the day ops and freeze read it), but a divergent clock in a
	// pricing path is the kind of thing that is only wrong once.
	now := time.Now().Unix() * 1000
	items, err := s.bulkPriceables(user.Id, req, now)
	if err != nil {
		return BulkTicket{}, err
	}
	// The applier about to run iterates the REQUEST's targets; the pricing above is
	// per account. Narrowing the request to what was priced is what stops the two
	// acting on different sets.
	scopeBulkTargetsToPriced(req, items)
	ticket, err := priceBulk(*profile, req, items, now)
	if err != nil {
		return BulkTicket{}, err
	}
	ticket.UserId = user.Id
	if err := s.reserveBulk(ticket); err != nil {
		return BulkTicket{}, err
	}
	return ticket, nil
}

// dropDepletedTargets removes accounts that have already moved everything their
// quota allows, so a free "enable" cannot hand them more.
//
// Uses the enforcement job's own predicate (`up + down >= total`, unlimited
// exempt) so the two cannot disagree about which accounts are spent.
func (s *ResellerService) dropDepletedTargets(req *BulkClientUpdateRequest) error {
	if len(req.Targets) == 0 {
		return nil
	}
	emails := make([]string, 0, len(req.Targets))
	for _, t := range req.Targets {
		emails = append(emails, t.Email)
	}
	var spent []xray.ClientTraffic
	if err := database.GetDB().Model(&xray.ClientTraffic{}).
		Where("email IN (?) AND total > 0 AND up + down >= total", emails).
		Find(&spent).Error; err != nil {
		return err
	}
	if len(spent) == 0 {
		return nil
	}
	drop := make(map[string]bool, len(spent))
	for _, ct := range spent {
		drop[emailKey(ct.Email)] = true
	}
	kept := make([]BulkClientTarget, 0, len(req.Targets))
	for _, t := range req.Targets {
		if !drop[emailKey(t.Email)] {
			kept = append(kept, t)
		}
	}
	req.Targets = kept
	return nil
}

// bulkOpAllowed refuses the ops a reseller must not run at all, before the
// request is scoped or anything is read.
func bulkOpAllowed(p model.ResellerProfile, req *BulkClientUpdateRequest) error {
	switch req.Op {
	case bulkOpSubDays:
		return ErrBulkNoSubDays
	case bulkOpAddInbounds, bulkOpRemoveInbounds:
		// Belt and braces. The membership handler refuses a reseller before it
		// reads anything, and BulkUpdateClients does not know these ops, so this
		// arm is only reachable if one of them is ever wired through the shared
		// bulk endpoint. Stated here anyway, because silence in this table reads
		// as permission.
		return ErrBulkNoMembership
	case bulkOpAddDays:
		if p.DaysPerGB > 0 {
			return ErrBulkDaysAreDerived
		}
	case bulkOpAddTraffic, bulkOpSubTraffic:
		// Days-per-GB used to refuse these outright, on the grounds that the
		// generic applier moves totalGB alone and would sell bytes without
		// moving the deadline. That was the right diagnosis and the wrong cure:
		// Quote already derives the new deadline per account, so the batch
		// carries it and applyBulkExpiry writes it after the applier runs.
		if req.AmountBytes <= 0 {
			return ErrBulkAmount
		}
	}
	return nil
}

// scopeBulkTargets drops every target this reseller does not own, in place.
//
// Ownership is matched case-insensitively (OwnedEmails lower-cases its keys)
// because an email is the panel's case-insensitive account identity, so a
// case-sensitive comparison here would be a way to fall out of scope. Note the
// direction: matching loosely can only ever REMOVE a target from the batch,
// never add one, since a loose match still has to hit a row this reseller owns.
func scopeBulkTargets(req *BulkClientUpdateRequest, owned map[string]bool) {
	kept := make([]BulkClientTarget, 0, len(req.Targets))
	for _, t := range req.Targets {
		if owned[strings.ToLower(strings.TrimSpace(t.Email))] {
			kept = append(kept, t)
		}
	}
	req.Targets = kept
}

// scopeBulkTargetsToPriced drops every target whose account the pricer passed
// over, in place, so the applier is handed the priced list and not the raw request.
//
// A guard rather than a repair. bulkPriceables runs the applier's own rules over
// every targeted membership, so an account it prices nothing for is one the applier
// would skip anyway; what this pins is that the two can never come apart, because
// they are filtered by different code (one per account, one per membership) and a
// drift between them is a mutation nobody was charged for.
//
// Runs AFTER scopeBulkTargets and can only ever remove more, so it cannot widen
// what a reseller reaches. Every membership of an account that WAS priced is kept:
// they all have to end up holding the one figure the balance paid for, which
// ApplyBulkCharges writes onto them.
func scopeBulkTargetsToPriced(req *BulkClientUpdateRequest, items []bulkPriceable) {
	priced := make(map[string]bool, len(items))
	for _, it := range items {
		priced[emailKey(it.email)] = true
	}
	kept := make([]BulkClientTarget, 0, len(req.Targets))
	for _, t := range req.Targets {
		if priced[emailKey(t.Email)] {
			kept = append(kept, t)
		}
	}
	req.Targets = kept
}

// bulkPriceable is one target the applier will really change, with everything
// its price is computed from.
type bulkPriceable struct {
	// email is the ledger row's spelling; oldTotal and newTotal come from the
	// SETTINGS blob, which is what the applier reads and writes.
	email    string
	oldTotal int64
	newTotal int64
	charged  int64
	consumed int64
	expiry   int64
}

// bulkPriceables works out which targets the batch will actually change, and
// what each one costs.
//
// The two filters are the whole point of loading the settings at all. The
// applier honours the skip toggles and treats some ops as no-ops for some
// accounts, and every target it passes over must cost nothing: charging for a
// skipped account is an overcharge, and REFUNDING one is free balance. The
// second is the real hole, and it is reachable today: subTraffic is a no-op on
// an unlimited account (there is nothing to subtract from), so a naive refund
// would credit the reseller while the account keeps its unlimited quota.
//
// Rather than restate the applier's rules, this runs them: bulkClientSkipped and
// applyBulkClientOp, over a copy of the client. A second implementation of
// "what does subTraffic do to totalGB" is a second place for the floor-at-one
// rule to drift, and a drift here is money.
func (s *ResellerService) bulkPriceables(userId int, req *BulkClientUpdateRequest, now int64) ([]bulkPriceable, error) {
	db := database.GetDB()

	var rows []model.ResellerClient
	if err := db.Model(&model.ResellerClient{}).Where("user_id = ?", userId).Find(&rows).Error; err != nil {
		return nil, err
	}
	ledger := make(map[string]model.ResellerClient, len(rows))
	for _, rc := range rows {
		ledger[emailKey(rc.Email)] = rc
	}

	// Grouped exactly as BulkUpdateClients groups them, matching the target
	// string to the settings email EXACTLY. The applier does, and a looser match
	// here would price an account it then leaves alone.
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

	// Ascending inbound id, not map order. One account can be targeted on several
	// inbounds and only the first one reached prices it (see the dedup below), so
	// map order would pick the membership whose settings entry the whole batch is
	// priced from AT RANDOM. Two runs of the same request could quote different
	// numbers, and the preview a reseller confirmed would not be the batch they got.
	inboundIds := make([]int, 0, len(byInbound))
	for inboundId := range byInbound {
		inboundIds = append(inboundIds, inboundId)
	}
	sort.Ints(inboundIds)

	var inboundService InboundService
	out := make([]bulkPriceable, 0, len(req.Targets))
	seen := make(map[string]bool, len(req.Targets))
	for _, inboundId := range inboundIds {
		emails := byInbound[inboundId]
		inbound, err := inboundService.GetInbound(inboundId)
		if err != nil || inbound == nil {
			// An inbound the applier will not find either, so there is nothing
			// here to charge for.
			continue
		}
		var settings map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			return nil, err
		}
		clients, _ := settings["clients"].([]any)
		if len(clients) == 0 {
			continue
		}

		var traffics []xray.ClientTraffic
		if err := db.Model(&xray.ClientTraffic{}).Where("inbound_id = ?", inboundId).
			Find(&traffics).Error; err != nil {
			return nil, err
		}
		usage := make(map[string]xray.ClientTraffic, len(traffics))
		for _, ct := range traffics {
			usage[emailKey(ct.Email)] = ct
		}

		for _, raw := range clients {
			cm, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			email, _ := cm["email"].(string)
			if email == "" || !emails[email] {
				continue
			}
			key := emailKey(email)
			rc, owned := ledger[key]
			if !owned {
				continue // scoped out already; belt and braces
			}
			// One charge per account, whether the two entries are on the same
			// inbound or on two the batch names: an account is one ledger row, one
			// quota and one charge however many inbounds serve it, so pricing the
			// second membership would debit twice for a row that can only record
			// one charge. What the applier then does to those other memberships is
			// squared up by ApplyBulkCharges, which writes this one priced quota
			// onto all of them.
			if seen[key] {
				continue
			}
			if bulkClientSkipped(cm, *req) {
				continue
			}
			next := cloneClient(cm)
			if !applyBulkClientOp(next, *req, now) {
				continue // a no-op for this account: the applier changes nothing
			}
			seen[key] = true

			ct := usage[key]
			consumed := ct.AllTime - rc.AllTimeBase
			if consumed < 0 {
				consumed = 0
			}
			out = append(out, bulkPriceable{
				email:    rc.Email,
				oldTotal: bulkNumToInt64(cm["totalGB"]),
				newTotal: bulkNumToInt64(next["totalGB"]),
				charged:  rc.ChargedBytes,
				consumed: consumed,
				expiry:   ct.ExpiryTime,
			})
		}
	}
	return out, nil
}

// priceBulk turns the affected accounts into one reservation.
//
// The balance check is on the TOTAL and happens before any account is priced, so
// that the reseller is told the batch's real shortfall. Doing it per account
// would let a batch of fifty pass on a balance that fits one, and quoting first
// would report the shortfall of a single account, which is the wrong number to
// go and ask an admin for.
func priceBulk(p model.ResellerProfile, req *BulkClientUpdateRequest, items []bulkPriceable, now int64) (BulkTicket, error) {
	ticket := BulkTicket{}
	if len(items) == 0 {
		return ticket, nil
	}

	if req.Op == bulkOpAddTraffic {
		want, err := bulkTotalCost(req.AmountBytes, int64(len(items)))
		if err != nil {
			return BulkTicket{}, err
		}
		if available := AvailableBytes(p); !p.Unlimited && want > available {
			return BulkTicket{}, shortBy(want, available)
		}
	}

	for _, it := range items {
		// The single-account arithmetic, unchanged. Everything the refund rule
		// turns on (the clamp at consumed, the clamp at what was charged, the
		// refusal to price a negative quota) lives in Quote, and a bulk operation
		// is not a reason to own a second copy of it.
		//
		// Its per-account balance check cannot fire on this path: an addTraffic
		// delta is at most the batch total that was just checked, and a
		// subTraffic delta is a refund. ForceExpiry cannot fire either, because
		// days-per-GB refuses these ops outright above.
		q, err := Quote(QuoteInput{
			Profile:       p,
			OldTotal:      it.oldTotal,
			NewTotal:      it.newTotal,
			OldCharged:    it.charged,
			Consumed:      it.consumed,
			CurrentExpiry: it.expiry,
			NowMillis:     now,
		})
		if err != nil {
			return BulkTicket{}, err
		}
		if q.DeltaSpent == 0 && q.NewCharged == it.charged {
			continue // nothing to write for this account
		}
		ticket.DeltaSpent += q.DeltaSpent
		ticket.Charges = append(ticket.Charges, BulkCharge{
			Email: it.email, NewCharged: q.NewCharged, PrevCharged: it.charged,
			SetTotal: true, NewTotal: it.newTotal,
			ForceExpiry: q.ForceExpiry, ExpiryTime: q.ExpiryTime,
		})
	}
	ticket.Active = len(ticket.Charges) > 0
	return ticket, nil
}

// bulkTotalCost multiplies a per-account amount by an account count without
// wrapping. A wrapped product reads as a small debit, and a wrapped NEGATIVE one
// is paid to the reseller, so the multiply is refused rather than saturated:
// saturating would report a shortfall for an unlimited reseller who has no
// balance to be short of, and there is no honest price for this batch either way.
func bulkTotalCost(amount, n int64) (int64, error) {
	if amount <= 0 || n <= 0 {
		return 0, nil
	}
	if amount > math.MaxInt64/n {
		return 0, fmt.Errorf("%w: %d bytes across %d accounts", ErrInvalidQuota, amount, n)
	}
	return amount * n, nil
}

// reserveBulk moves the balance and every account's charge in ONE transaction.
// A batch that debited the balance but recorded the charge on half its accounts
// would leave the other half refundable for bytes they were never charged.
func (s *ResellerService) reserveBulk(t BulkTicket) error {
	if !t.Active {
		return nil
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := addSpent(tx, t.UserId, t.DeltaSpent); err != nil {
			return err
		}
		return writeBulkCharges(tx, t, false)
	})
}

// BulkPreview is what a batch WOULD do, priced without writing anything.
//
// It exists so a reseller who cannot afford the whole batch is offered the part
// they can, instead of a flat refusal that tells them nothing about the size of
// the gap.
type BulkPreview struct {
	IsReseller bool   `json:"isReseller"`
	Op         string `json:"op"`
	// TotalTargets is what was posted; Eligible is what survives ownership
	// scoping and the skip toggles. The difference is accounts that were never
	// going to be touched, and saying so avoids "why did it only do 3 of 10".
	TotalTargets int `json:"totalTargets"`
	Eligible     int `json:"eligible"`

	Affordable     bool  `json:"affordable"`
	CostBytes      int64 `json:"costBytes"`
	AvailableBytes int64 `json:"availableBytes"`
	ShortBytes     int64 `json:"shortBytes"`

	// CanProcess and ProcessEmails are the offer: exactly these accounts, in
	// exactly this order, fit inside the balance.
	CanProcess    int      `json:"canProcess"`
	ProcessEmails []string `json:"processEmails"`
}

// PreviewBulk prices a batch and reserves nothing.
//
// ADVICE, never authorization. The frontend re-posts the confirmed run narrowed
// to ProcessEmails and PrepareBulk prices it again from scratch, so a tampered
// or stale preview buys nothing: the second pricing is the one that spends.
func (s *ResellerService) PreviewBulk(user *model.User, req *BulkClientUpdateRequest) (BulkPreview, error) {
	out := BulkPreview{}
	if user == nil || req == nil || !user.IsReseller {
		return out, nil
	}
	out.IsReseller, out.Op = true, req.Op
	out.TotalTargets = len(req.Targets)

	profile, err := s.ProfileFor(user.Id)
	if err != nil {
		return out, err
	}
	if err := bulkOpAllowed(*profile, req); err != nil {
		return out, err
	}
	owned, err := s.OwnedEmails(user.Id)
	if err != nil {
		return out, err
	}
	// On a COPY of the targets: a preview that mutated the caller's request
	// would change what the confirmed run then posts.
	scoped := *req
	scoped.Targets = append([]BulkClientTarget(nil), req.Targets...)
	scopeBulkTargets(&scoped, owned)

	out.AvailableBytes = AvailableBytes(*profile)

	if scoped.Op != bulkOpAddTraffic && scoped.Op != bulkOpSubTraffic {
		// Free ops always fit. Eligible still means something (scoping dropped
		// what was not theirs), so it is reported rather than assumed.
		out.Eligible = len(scoped.Targets)
		out.CanProcess = out.Eligible
		out.Affordable = true
		out.ProcessEmails = bulkTargetEmails(scoped.Targets)
		return out, nil
	}

	now := time.Now().Unix() * 1000
	items, err := s.bulkPriceables(user.Id, &scoped, now)
	if err != nil {
		return out, err
	}
	// Sorted so the offer is STABLE. bulkPriceables walks inbounds and their
	// settings blobs, and nothing guarantees that order twice running; the user
	// must not confirm one set and have a different set applied.
	sort.Slice(items, func(i, j int) bool { return items[i].email < items[j].email })
	out.Eligible = len(items)

	// Accumulated in order rather than divided out, because per-account cost is
	// not uniform: a subTraffic refund is clamped at what each account has
	// consumed, so the batch total is not the amount times the count.
	var running int64
	for _, it := range items {
		q, qerr := Quote(QuoteInput{
			Profile: *profile, OldTotal: it.oldTotal, NewTotal: it.newTotal,
			OldCharged: it.charged, Consumed: it.consumed,
			CurrentExpiry: it.expiry, NowMillis: now,
		})
		if qerr != nil {
			return out, qerr
		}
		out.CostBytes += q.DeltaSpent
		if profile.Unlimited || running+q.DeltaSpent <= out.AvailableBytes {
			running += q.DeltaSpent
			out.CanProcess++
			out.ProcessEmails = append(out.ProcessEmails, it.email)
		}
	}
	out.Affordable = out.CanProcess == out.Eligible
	if short := out.CostBytes - out.AvailableBytes; short > 0 && !profile.Unlimited {
		out.ShortBytes = short
	}
	if out.ProcessEmails == nil {
		out.ProcessEmails = []string{} // marshal as [], not null: the UI iterates it
	}
	return out, nil
}

// bulkTargetEmails is the target list as plain emails, in order.
func bulkTargetEmails(targets []BulkClientTarget) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Email)
	}
	return out
}

// ApplyBulkCharges writes back what the quote decided, after the generic applier
// has run: the quota each account was priced for, and the deadline days-per-GB
// derived from it.
//
// Two things the applier cannot do, and both of them are money:
//
//   - It moves totalGB and nothing else, so under days-per-GB a bulk top-up would
//     sell bytes and leave the deadline exactly where it was.
//   - It works per (inbound, email) TARGET, recomputing the new quota from each
//     membership's own settings entry, while the price is per ACCOUNT and was
//     quoted once. An account on three inbounds is charged for one gigabyte and,
//     left alone, is handed three, from three different starting points. Writing
//     the priced figure onto every membership makes applied and priced the same
//     number by construction, whatever the entries held before.
//
// A second pass rather than a change to BulkUpdateClients: that function serves
// every admin and knows nothing about resellers, and teaching it a per-account
// override for one role would put reseller policy in the middle of the path every
// admin takes.
//
// Memberships are resolved from what really serves the account, NOT from the join
// this used to be (inbounds against client_traffics.inbound_id). That join names
// the one inbound the account's single traffic row happens to point at, so the
// write-back landed on the home inbound and left every other membership holding
// the applier's own arithmetic.
//
// Both places have to move together. The settings blob is what the panel renders
// and what regenerates daemon config; client_traffics is what the expiry job and
// the daemons' own accounting read. Writing one without the other leaves the
// panel and the data plane disagreeing about when an account dies, so this runs
// in a single transaction and reports failure rather than half-applying.
func (s *ResellerService) ApplyBulkCharges(t BulkTicket) error {
	if !t.Active {
		return nil
	}
	wanted := make(map[string]BulkCharge, len(t.Charges))
	emails := make([]string, 0, len(t.Charges))
	for _, c := range t.Charges {
		if !c.ForceExpiry && !c.SetTotal {
			continue
		}
		wanted[emailKey(c.Email)] = c
		emails = append(emails, c.Email)
	}
	if len(wanted) == 0 {
		return nil
	}

	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		ids, err := servingInboundIds(tx, emails...)
		if err != nil {
			return err
		}
		var inbounds []*model.Inbound
		if len(ids) > 0 {
			if err := tx.Model(&model.Inbound{}).Where("id IN (?)", ids).
				Find(&inbounds).Error; err != nil {
				return err
			}
		}

		for _, inbound := range inbounds {
			settings := map[string]any{}
			if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
				return err
			}
			clients, _ := settings["clients"].([]any)
			touched := false
			for _, raw := range clients {
				cm, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				email, _ := cm["email"].(string)
				charge, want := wanted[emailKey(email)]
				if !want {
					continue
				}
				if charge.SetTotal {
					cm["totalGB"] = charge.NewTotal
				}
				if charge.ForceExpiry {
					cm["expiryTime"] = charge.ExpiryTime
				}
				cm["updated_at"] = time.Now().UnixMilli()
				touched = true
			}
			if !touched {
				continue
			}
			patched, err := json.Marshal(settings)
			if err != nil {
				return err
			}
			if err := tx.Model(&model.Inbound{}).Where("id = ?", inbound.Id).
				Update("settings", string(patched)).Error; err != nil {
				return err
			}
		}

		for _, c := range wanted {
			updates := map[string]any{}
			if c.SetTotal {
				updates["total"] = c.NewTotal
			}
			if c.ForceExpiry {
				updates["expiry_time"] = c.ExpiryTime
			}
			if err := tx.Model(&xray.ClientTraffic{}).Where("email = ?", c.Email).
				Updates(updates).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// RollbackBulk undoes a reservation whose batch then failed to apply.
func (s *ResellerService) RollbackBulk(t BulkTicket) error {
	if !t.Active {
		return nil
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		// Unguarded: undoing a batch is a correction, not a commitment, and a
		// bulk deduct unwinds as a debit that the headroom check would refuse.
		if err := restoreSpent(tx, t.UserId, -t.DeltaSpent); err != nil {
			return err
		}
		return writeBulkCharges(tx, t, true)
	})
}

func writeBulkCharges(tx *gorm.DB, t BulkTicket, restore bool) error {
	for _, c := range t.Charges {
		charged := c.NewCharged
		if restore {
			charged = c.PrevCharged
		}
		if err := tx.Model(&model.ResellerClient{}).Where("email = ?", c.Email).
			Update("charged_bytes", charged).Error; err != nil {
			return err
		}
	}
	return nil
}

// --- deletes --------------------------------------------------------------------

// BulkUsageSnapshot records what each targeted account has moved all-time. Taken
// BEFORE a delete, because the delete is what destroys the record.
//
// Read by inbound rather than by the emails themselves, so that a target whose
// spelling differs in case from the stored row still finds its usage. Missing that
// row would read as an account that consumed nothing, which is the expensive
// direction to be wrong in.
func (s *ResellerService) BulkUsageSnapshot(targets []BulkClientTarget) (map[string]int64, error) {
	ids := make([]int, 0, len(targets))
	seen := make(map[int]bool, len(targets))
	for _, t := range targets {
		if t.Email == "" || seen[t.InboundId] {
			continue
		}
		seen[t.InboundId] = true
		ids = append(ids, t.InboundId)
	}
	if len(ids) == 0 {
		return map[string]int64{}, nil
	}
	var rows []xray.ClientTraffic
	if err := database.GetDB().Model(&xray.ClientTraffic{}).
		Where("inbound_id IN (?)", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, ct := range rows {
		out[emailKey(ct.Email)] = ct.AllTime
	}
	return out, nil
}

// RefundDeleted credits the unused part of a just-deleted account back to its
// reseller and forgets it, measuring consumption against a snapshot taken before
// the delete. A no-op for an account the house owns.
//
// A refund helper that looks the consumption up for itself cannot do this job,
// and the reason is worth writing down because
// it is invisible at the call site: it reads consumption out of client_traffics,
// and a delete drops that row as PART of itself (InboundService.DelClientStat).
// Run afterwards, it therefore sees an account that consumed nothing and hands the
// whole charge back. Sell 10 GB, let the customer move all ten, delete the
// account, collect 10 GB of balance.
//
// The ordering stays refund-after-delete for the usual reason: a
// refund that never runs leaves balance an admin can hand back, where one that ran
// ahead of a delete that then failed is balance paid out for an account still live
// and still selling. Only the usage figure is carried across the delete.
func (s *ResellerService) RefundDeleted(email string, allTimeAtDelete int64, known bool) error {
	owner, err := s.ClientOwner(email)
	if err != nil || owner == nil {
		return err
	}
	// SECURITY: removing one membership is not deleting the account.
	//
	// One account is one identity on N inbounds with ONE quota and ONE charge, so
	// taking it off the first of three inbounds leaves the other two serving it
	// against that same charge. Refunding there hands the reseller back the unused
	// part of a quota that is still being sold, and dropping the ledger row is worse
	// than the refund: absence of a row IS "the house owns this", so the account
	// would go on running with nobody billed for it and no page showing whose it is.
	//
	// Asked AFTER the delete deliberately, which is the only moment the answer is
	// the one that matters: what is left. The consumption figure is the only thing
	// that has to be carried across, and it already is.
	ids, err := servingInboundIds(database.GetDB(), email)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		return nil
	}
	// SECURITY: unknown consumption must WITHHOLD the refund, never assume zero.
	//
	// A missing snapshot arrives here as 0, which is indistinguishable from an
	// account that genuinely moved nothing, and that reads as "everything is
	// unused" and refunds the whole charge. The two failures are not
	// symmetrical: withholding costs the reseller balance an admin can hand
	// back, while granting hands out traffic nobody paid for and leaves no
	// record of it. The ownership row still goes, so the account is forgotten
	// either way.
	if !known {
		return database.GetDB().Where("email = ?", email).
			Delete(&model.ResellerClient{}).Error
	}
	consumed := allTimeAtDelete - owner.AllTimeBase
	if consumed < 0 {
		consumed = 0
	}
	refund := owner.ChargedBytes - consumed
	if refund < 0 {
		refund = 0
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := addSpent(tx, owner.UserId, -refund); err != nil {
			return err
		}
		return tx.Where("email = ?", email).Delete(&model.ResellerClient{}).Error
	})
}

// cloneClient copies a settings client shallowly, which is all applyBulkClientOp
// needs: it reads and writes scalar keys only, so the nested values shared with
// the original are never reached, let alone mutated.
func cloneClient(cm map[string]any) map[string]any {
	out := make(map[string]any, len(cm))
	for k, v := range cm {
		out[k] = v
	}
	return out
}

// emailKey normalizes an account identity for map lookup, the same way
// OwnedEmails and sameEmail do.
func emailKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
