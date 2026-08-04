package service

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// A bulk request is the only client operation whose targets the caller names, so
// these tests are written as attempts to point one at somebody else's accounts or
// to come out of it with traffic nobody paid for. Each one describes a way to do
// that and asserts it fails.
//
// Every fixture puts an admin's account and a reseller's on the SAME inbound,
// because that is the shape the role exists for: the inbound grant is shared and
// therefore cannot be what separates them.

// bulkAccount is one account on that inbound, as the three tables that describe
// it: the settings blob, client_traffics, and (for a reseller's) the ledger row.
type bulkAccount struct {
	email   string
	total   int64 // the quota in the settings blob, in bytes
	allTime int64
	expiry  int64
	enable  bool
	// owned marks the reseller's. charged and base are its ledger row: what it
	// currently costs them, and the AllTime the charge was measured from.
	owned   bool
	charged int64
	base    int64
}

type bulkFixture struct {
	svc      *InboundService
	rs       *ResellerService
	admin    *model.User
	reseller *model.User
	inbound  *model.Inbound
}

// bulkProfile is a reseller with a real balance and no derived duration, which is
// the shape every pricing test below wants. The days-per-GB variants set it
// explicitly.
func bulkProfile(allowance, spent int64) model.ResellerProfile {
	return model.ResellerProfile{AllowanceBytes: allowance, SpentBytes: spent}
}

func newBulkFixture(t *testing.T, profile model.ResellerProfile, accounts ...bulkAccount) *bulkFixture {
	t.Helper()
	svc := newInboundDB(t)
	db := database.GetDB()

	admin := &model.User{
		Username: "bulk-admin", Password: "x", Enable: true,
		Permissions: model.PermAccessInbounds | model.PermBulkOperation,
	}
	reseller := &model.User{Username: "bulk-reseller", Password: "x", Enable: true, IsReseller: true}
	for _, u := range []*model.User{admin, reseller} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user %s: %v", u.Username, err)
		}
	}
	profile.UserId = reseller.Id
	if err := db.Create(&profile).Error; err != nil {
		t.Fatalf("create reseller profile: %v", err)
	}

	clients := make([]map[string]any, 0, len(accounts))
	for _, a := range accounts {
		clients = append(clients, map[string]any{
			"id": "uuid-" + a.email, "email": a.email, "enable": a.enable,
			"totalGB": a.total, "expiryTime": a.expiry,
		})
	}
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	// Seeded disabled for the reason newInboundDB documents: the client paths push
	// to a live Xray over gRPC for an enabled row, and there is none here.
	inbound := &model.Inbound{
		UserId: admin.Id, Tag: "inbound-42001", Port: 42001,
		Protocol: model.VMESS, Enable: false, Settings: string(settings),
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	for _, a := range accounts {
		if err := db.Create(&xray.ClientTraffic{
			InboundId: inbound.Id, Email: a.email, Enable: a.enable,
			Total: a.total, AllTime: a.allTime, ExpiryTime: a.expiry,
		}).Error; err != nil {
			t.Fatalf("create client traffic %s: %v", a.email, err)
		}
		if !a.owned {
			continue
		}
		if err := db.Create(&model.ResellerClient{
			Email: a.email, InboundId: inbound.Id, UserId: reseller.Id,
			ChargedBytes: a.charged, AllTimeBase: a.base,
		}).Error; err != nil {
			t.Fatalf("create ownership row %s: %v", a.email, err)
		}
	}
	return &bulkFixture{svc: svc, rs: &ResellerService{}, admin: admin, reseller: reseller, inbound: inbound}
}

func (f *bulkFixture) targets(emails ...string) []BulkClientTarget {
	out := make([]BulkClientTarget, 0, len(emails))
	for _, e := range emails {
		out = append(out, BulkClientTarget{InboundId: f.inbound.Id, Email: e})
	}
	return out
}

// spent is the reseller's committed balance, the number every debit and refund
// has to land on.
func (f *bulkFixture) spent(t *testing.T) int64 {
	t.Helper()
	p := model.ResellerProfile{}
	if err := database.GetDB().Model(&model.ResellerProfile{}).
		Where("user_id = ?", f.reseller.Id).First(&p).Error; err != nil {
		t.Fatalf("read profile: %v", err)
	}
	return p.SpentBytes
}

// charged is one account's standing against that balance.
func (f *bulkFixture) charged(t *testing.T, email string) int64 {
	t.Helper()
	rc := model.ResellerClient{}
	if err := database.GetDB().Model(&model.ResellerClient{}).
		Where("email = ?", email).First(&rc).Error; err != nil {
		t.Fatalf("read ledger row %s: %v", email, err)
	}
	return rc.ChargedBytes
}

// quotaOf reads an account's quota back out of the stored settings, which is what
// the applier writes and therefore what the customer actually gets.
func (f *bulkFixture) quotaOf(t *testing.T, email string) int64 {
	t.Helper()
	inbound, err := f.svc.GetInbound(f.inbound.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	var root struct {
		Clients []struct {
			Email   string `json:"email"`
			TotalGB int64  `json:"totalGB"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &root); err != nil {
		t.Fatalf("settings are not readable JSON: %v", err)
	}
	for _, c := range root.Clients {
		if c.Email == email {
			return c.TotalGB
		}
	}
	t.Fatalf("account %s is not on the inbound any more", email)
	return 0
}

// --- scoping --------------------------------------------------------------------

// The body names its own targets and the applier trusts them, so this is the whole
// wall between a reseller and every admin account on an inbound they share.
func TestPrepareBulkDropsTargetsTheResellerDoesNotOwn(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 20*gb),
		bulkAccount{email: "admins-client", total: 5 * gb, enable: true},
		bulkAccount{email: "sold-one", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
		bulkAccount{email: "sold-two", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: gb,
		Targets: f.targets("admins-client", "sold-one", "sold-two"),
	}

	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if got := bulkTargetEmails(req.Targets); len(got) != 2 || got[0] != "sold-one" || got[1] != "sold-two" {
		t.Fatalf("targets = %v; the admin's account must be dropped before the applier sees it", got)
	}
	// Two survivors, so two gigabytes, not three.
	if ticket.DeltaSpent != 2*gb {
		t.Errorf("DeltaSpent = %d; want %d (the admin's account is not the reseller's to pay for)", ticket.DeltaSpent, 2*gb)
	}
	if got := f.spent(t); got != 22*gb {
		t.Errorf("SpentBytes = %d; want %d", got, 22*gb)
	}

	// And the applier really does leave it alone: the scoping is only worth
	// anything if it survives the round trip through BulkUpdateClients.
	if _, _, err := f.svc.BulkUpdateClients(*req); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	if got := f.quotaOf(t, "admins-client"); got != 5*gb {
		t.Errorf("the admin's quota moved to %d; a reseller's batch must not reach it", got)
	}
	for _, email := range []string{"sold-one", "sold-two"} {
		if got := f.quotaOf(t, email); got != 6*gb {
			t.Errorf("%s quota = %d; want %d", email, got, 6*gb)
		}
		if got := f.charged(t, email); got != 6*gb {
			t.Errorf("%s charged = %d; want %d", email, got, 6*gb)
		}
	}
}

// A target naming an account that exists but belongs to nobody the caller can
// reach is the same case as an admin's, and so is a target that does not exist.
func TestPrepareBulkDropsUnknownTargets(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 0),
		bulkAccount{email: "sold-one", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: gb,
		Targets: f.targets("no-such-account", "sold-one"),
	}
	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if got := bulkTargetEmails(req.Targets); len(got) != 1 || got[0] != "sold-one" {
		t.Fatalf("targets = %v; want only the account that exists and is theirs", got)
	}
	if ticket.DeltaSpent != gb {
		t.Errorf("DeltaSpent = %d; want %d", ticket.DeltaSpent, int64(gb))
	}
}

// --- addTraffic -----------------------------------------------------------------

func TestPrepareBulkAddTrafficDebitsEveryTarget(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 0),
		bulkAccount{email: "sold-one", total: gb, enable: true, owned: true, charged: gb},
		bulkAccount{email: "sold-two", total: 2 * gb, enable: true, owned: true, charged: 2 * gb},
		bulkAccount{email: "sold-three", total: 3 * gb, enable: true, owned: true, charged: 3 * gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: 4 * gb,
		Targets: f.targets("sold-one", "sold-two", "sold-three"),
	}

	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if ticket.DeltaSpent != 12*gb {
		t.Errorf("DeltaSpent = %d; want %d (4 GB x 3 accounts)", ticket.DeltaSpent, 12*gb)
	}
	if got := f.spent(t); got != 12*gb {
		t.Errorf("SpentBytes = %d; want %d", got, 12*gb)
	}
	// Each account's own standing moves too, because the refund on a later delete
	// is measured from it: a batch that debited the balance and left the rows alone
	// would hand the whole batch back the first time an account was deleted.
	for _, want := range []struct {
		email   string
		charged int64
	}{{"sold-one", 5 * gb}, {"sold-two", 6 * gb}, {"sold-three", 7 * gb}} {
		if got := f.charged(t, want.email); got != want.charged {
			t.Errorf("%s charged = %d; want %d", want.email, got, want.charged)
		}
	}
}

// The batch total is the only figure worth checking against the balance. Checking
// per account lets a reseller with room for one hand out fifty.
func TestPrepareBulkAddTrafficRefusesOnTheBatchTotalNotThePerAccountOne(t *testing.T) {
	// 5 GB left. Any ONE of these three accounts fits at 2 GB; together they do not.
	f := newBulkFixture(t, bulkProfile(100*gb, 95*gb),
		bulkAccount{email: "sold-one", total: gb, enable: true, owned: true, charged: gb},
		bulkAccount{email: "sold-two", total: gb, enable: true, owned: true, charged: gb},
		bulkAccount{email: "sold-three", total: gb, enable: true, owned: true, charged: gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: 2 * gb,
		Targets: f.targets("sold-one", "sold-two", "sold-three"),
	}

	_, err := f.rs.PrepareBulk(f.reseller, req)
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("err = %v; want ErrInsufficientBalance for a 6 GB batch on a 5 GB balance", err)
	}
	// The deficit is the batch's (6 - 5), not one account's: the reseller has to
	// know what to ask an admin for.
	if !strings.Contains(err.Error(), "1.00GB") {
		t.Errorf("message %q does not name the batch's 1 GB shortfall", err)
	}
	if got := f.spent(t); got != 95*gb {
		t.Errorf("SpentBytes = %d; a refused batch must move nothing", got)
	}
	for _, email := range []string{"sold-one", "sold-two", "sold-three"} {
		if got := f.charged(t, email); got != gb {
			t.Errorf("%s charged = %d; a refused batch must move nothing", email, got)
		}
	}

	// The same 2 GB against one account goes through, which is what makes the
	// refusal above a statement about the TOTAL and not about the amount.
	one := &BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 2 * gb, Targets: f.targets("sold-one")}
	if _, err := f.rs.PrepareBulk(f.reseller, one); err != nil {
		t.Fatalf("a single 2 GB top-up fits a 5 GB balance: %v", err)
	}
}

// An unlimited reseller has no balance to be short of, but the batch total still
// has to be a number: a wrapped one is a small (or negative) debit.
func TestPrepareBulkAddTrafficRefusesAnOverflowingBatch(t *testing.T) {
	f := newBulkFixture(t, model.ResellerProfile{Unlimited: true},
		bulkAccount{email: "sold-one", total: gb, enable: true, owned: true, charged: gb},
		bulkAccount{email: "sold-two", total: gb, enable: true, owned: true, charged: gb},
		bulkAccount{email: "sold-three", total: gb, enable: true, owned: true, charged: gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: math.MaxInt64 / 2,
		Targets: f.targets("sold-one", "sold-two", "sold-three"),
	}
	if _, err := f.rs.PrepareBulk(f.reseller, req); !errors.Is(err, ErrInvalidQuota) {
		t.Fatalf("err = %v; want ErrInvalidQuota for a batch total that does not fit int64", err)
	}
	if got := f.spent(t); got != 0 {
		t.Errorf("SpentBytes = %d; a refused batch must move nothing", got)
	}
}

// A negative amount is the same bug as a negative quota: it turns the op into its
// opposite and pays the reseller for running it.
func TestPrepareBulkRefusesANegativeAmount(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 50*gb),
		bulkAccount{email: "sold-one", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
	)
	for _, op := range []string{"addTraffic", "subTraffic"} {
		req := &BulkClientUpdateRequest{Op: op, AmountBytes: -10 * gb, Targets: f.targets("sold-one")}
		if _, err := f.rs.PrepareBulk(f.reseller, req); !errors.Is(err, ErrBulkAmount) {
			t.Errorf("%s: err = %v; want ErrBulkAmount", op, err)
		}
	}
	if got := f.spent(t); got != 50*gb {
		t.Errorf("SpentBytes = %d; want it untouched at %d", got, 50*gb)
	}
}

// --- subTraffic -----------------------------------------------------------------

// The refund rule, batched: bytes the customer already moved are gone, and a
// reseller can never get back more than they were charged.
func TestPrepareBulkSubTrafficRefundsOnlyUnusedBytes(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 30*gb),
		// Charged 10, used 4: dropping to 2 GB can only return the 6 unused.
		bulkAccount{email: "used-some", total: 10 * gb, enable: true, owned: true, charged: 10 * gb, allTime: 4 * gb},
		// Charged 10, used nothing: the whole 8 comes back.
		bulkAccount{email: "used-none", total: 10 * gb, enable: true, owned: true, charged: 10 * gb},
		// Quota 10 but only ever charged 1 (an admin raised the quota for free).
		// The refund is what THIS reseller paid, which is nothing left over.
		bulkAccount{email: "barely-charged", total: 10 * gb, enable: true, owned: true, charged: gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "subTraffic", AmountBytes: 8 * gb,
		Targets: f.targets("used-some", "used-none", "barely-charged"),
	}

	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if ticket.DeltaSpent != -14*gb {
		t.Errorf("DeltaSpent = %d; want %d (6 unused + 8 unused + 0)", ticket.DeltaSpent, -14*gb)
	}
	if got := f.spent(t); got != 16*gb {
		t.Errorf("SpentBytes = %d; want %d", got, 16*gb)
	}
	for _, want := range []struct {
		email   string
		charged int64
	}{
		{"used-some", 4 * gb},      // clamped at what the customer consumed
		{"used-none", 2 * gb},      // the new quota, all of it still unused
		{"barely-charged", 1 * gb}, // never more than this account was charged
	} {
		if got := f.charged(t, want.email); got != want.charged {
			t.Errorf("%s charged = %d; want %d", want.email, got, want.charged)
		}
	}
}

// subTraffic is a NO-OP on an account with no quota to subtract from, so refunding
// one is free balance: the reseller keeps the bytes and the customer keeps an
// account that is still unlimited.
func TestPrepareBulkSubTrafficRefundsNothingForAnUntouchedAccount(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 40*gb),
		bulkAccount{email: "unlimited-one", total: 0, enable: true, owned: true, charged: 40 * gb},
	)
	req := &BulkClientUpdateRequest{Op: "subTraffic", AmountBytes: 8 * gb, Targets: f.targets("unlimited-one")}

	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if ticket.Active || ticket.DeltaSpent != 0 {
		t.Fatalf("ticket = %+v; the applier changes nothing here, so nothing may be refunded", ticket)
	}
	if _, _, err := f.svc.BulkUpdateClients(*req); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	if got := f.spent(t); got != 40*gb {
		t.Errorf("SpentBytes = %d; want %d", got, 40*gb)
	}
	if got := f.quotaOf(t, "unlimited-one"); got != 0 {
		t.Errorf("quota = %d; the applier left it unlimited, which is why there was no refund", got)
	}
}

// The skip toggles are the same hole from the other side: an account the applier
// passes over gets no bytes, so charging for it is an overcharge.
func TestPrepareBulkDoesNotChargeSkippedTargets(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 10*gb),
		bulkAccount{email: "live-one", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
		bulkAccount{email: "disabled-one", total: 5 * gb, enable: false, owned: true, charged: 5 * gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: 3 * gb, SkipDisabled: true,
		Targets: f.targets("live-one", "disabled-one"),
	}

	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if ticket.DeltaSpent != 3*gb {
		t.Errorf("DeltaSpent = %d; want %d (only the account that will really be topped up)", ticket.DeltaSpent, 3*gb)
	}
	if _, _, err := f.svc.BulkUpdateClients(*req); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	if got := f.quotaOf(t, "disabled-one"); got != 5*gb {
		t.Errorf("the skipped account's quota moved to %d", got)
	}
	if got := f.charged(t, "disabled-one"); got != 5*gb {
		t.Errorf("the skipped account was charged: %d", got)
	}
}

// --- refused ops ----------------------------------------------------------------

func TestPrepareBulkRefusesSubDaysForAResellerButNotForAnAdmin(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 10*gb),
		bulkAccount{email: "sold-one", total: 5 * gb, enable: true, expiry: testNow + 30*dayMillis, owned: true, charged: 5 * gb},
	)
	req := &BulkClientUpdateRequest{Op: "subDays", Days: 5, Targets: f.targets("sold-one")}

	if _, err := f.rs.PrepareBulk(f.reseller, req); !errors.Is(err, ErrBulkNoSubDays) {
		t.Fatalf("err = %v; want ErrBulkNoSubDays", err)
	}
	if got := len(req.Targets); got != 1 {
		t.Errorf("a refused batch left %d targets; the caller aborts, so the request is not its business", got)
	}

	// The same batch from an admin is not refused, not scoped and not charged.
	ticket, err := f.rs.PrepareBulk(f.admin, req)
	if err != nil {
		t.Fatalf("an admin's subDays: %v", err)
	}
	if ticket.Active {
		t.Errorf("ticket = %+v; an admin has no balance to reserve against", ticket)
	}
	result, _, err := f.svc.BulkUpdateClients(*req)
	if err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	if result.Applied != 1 {
		t.Errorf("applied = %d; an admin's subDays still works", result.Applied)
	}
}

// Under days-per-GB a reseller has no expiry field at all, and the bulk applier
// moves one field at a time, so neither lever can be pulled on its own.
func TestPrepareBulkRefusesDayAndTrafficOpsUnderDerivedDuration(t *testing.T) {
	derived := bulkProfile(100*gb, 10*gb)
	derived.DaysPerGB = 3

	// A DAY op is still refused under the factor: the duration is not the
	// reseller's to set when it is a function of the traffic.
	t.Run("addDays", func(t *testing.T) {
		f := newBulkFixture(t, derived,
			bulkAccount{email: "sold-one", total: 5 * gb, enable: true, expiry: testNow + 30*dayMillis, owned: true, charged: 5 * gb},
		)
		req := &BulkClientUpdateRequest{Op: "addDays", Days: 5, AmountBytes: gb, Targets: f.targets("sold-one")}
		if _, err := f.rs.PrepareBulk(f.reseller, req); !errors.Is(err, ErrBulkDaysAreDerived) {
			t.Fatalf("err = %v; want %v", err, ErrBulkDaysAreDerived)
		}
		if got := f.spent(t); got != 10*gb {
			t.Errorf("SpentBytes = %d; a refused batch must move nothing", got)
		}
	})

	// TRAFFIC ops are NOT refused any more. They used to be, on the grounds that
	// the generic applier moves totalGB alone and would sell bytes while leaving
	// the deadline behind. The cure is to carry the derived deadline, not to
	// withhold the operation: every charge the batch makes must name the new
	// expiry so ApplyBulkExpiry can write it once the applier has run. A charge
	// that arrives with ForceExpiry false here is the old bug returning, silently.
	for _, op := range []string{"addTraffic", "subTraffic"} {
		t.Run(op, func(t *testing.T) {
			f := newBulkFixture(t, derived,
				bulkAccount{email: "sold-one", total: 5 * gb, enable: true, expiry: testNow + 30*dayMillis, owned: true, charged: 5 * gb},
			)
			req := &BulkClientUpdateRequest{Op: op, AmountBytes: gb, Targets: f.targets("sold-one")}
			ticket, err := f.rs.PrepareBulk(f.reseller, req)
			if err != nil {
				t.Fatalf("%s under days-per-GB must be allowed: %v", op, err)
			}
			if !ticket.Active || len(ticket.Charges) != 1 {
				t.Fatalf("ticket = %+v; want one active charge", ticket)
			}
			c := ticket.Charges[0]
			if !c.ForceExpiry {
				t.Fatal("charge carries no derived expiry; the deadline would be left behind")
			}
			if c.ExpiryTime <= 0 {
				t.Errorf("ExpiryTime = %d; want an absolute deadline, never the negative delayed-start form", c.ExpiryTime)
			}
		})
	}

	// The direction of the derived deadline: adding traffic must push it out,
	// removing traffic must pull it in, both measured from the same start.
	t.Run("addTraffic extends and subTraffic shortens", func(t *testing.T) {
		exp := func(op string) int64 {
			f := newBulkFixture(t, derived,
				bulkAccount{email: "sold-one", total: 5 * gb, enable: true, expiry: testNow + 30*dayMillis, owned: true, charged: 5 * gb},
			)
			req := &BulkClientUpdateRequest{Op: op, AmountBytes: gb, Targets: f.targets("sold-one")}
			ticket, err := f.rs.PrepareBulk(f.reseller, req)
			if err != nil {
				t.Fatalf("%s: %v", op, err)
			}
			return ticket.Charges[0].ExpiryTime
		}
		// Compared against each other rather than against the fixture's expiry,
		// which sits in 2001: forcedExpiry bases on max(now, currentExpiry), so a
		// long-expired account correctly restarts from the real clock and both ops
		// land near now. The direction between them is the property that holds
		// whatever the clock says.
		add, sub := exp("addTraffic"), exp("subTraffic")
		if add <= sub {
			t.Errorf("addTraffic expiry %d must be later than subTraffic %d", add, sub)
		}
		// And a deduct can never resurrect an account into the past.
		if sub < testNow {
			t.Errorf("subTraffic expiry = %d; must never fall below now", sub)
		}
	})

	// Without the factor, addDays is the reseller's own business and free: they
	// sell duration themselves, and no byte moves.
	f := newBulkFixture(t, bulkProfile(100*gb, 10*gb),
		bulkAccount{email: "sold-one", total: 5 * gb, enable: true, expiry: testNow + 30*dayMillis, owned: true, charged: 5 * gb},
	)
	req := &BulkClientUpdateRequest{Op: "addDays", Days: 5, Targets: f.targets("sold-one")}
	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("addDays with no days-per-GB factor: %v", err)
	}
	if ticket.Active || f.spent(t) != 10*gb {
		t.Errorf("addDays moved the balance: ticket %+v, spent %d", ticket, f.spent(t))
	}
}

// The free ops are free, but they are still scoped: an unpriced batch is not an
// unrestricted one.
func TestPrepareBulkFreeOpsAreScopedAndCostNothing(t *testing.T) {
	for _, op := range []string{"enable", "disable", "freeze", "unfreeze", "delete"} {
		t.Run(op, func(t *testing.T) {
			f := newBulkFixture(t, bulkProfile(100*gb, 10*gb),
				bulkAccount{email: "admins-client", total: 5 * gb, enable: true},
				bulkAccount{email: "sold-one", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
			)
			req := &BulkClientUpdateRequest{Op: op, Targets: f.targets("admins-client", "sold-one")}
			ticket, err := f.rs.PrepareBulk(f.reseller, req)
			if err != nil {
				t.Fatalf("PrepareBulk: %v", err)
			}
			if ticket.Active {
				t.Errorf("ticket = %+v; %s moves no quota, so it moves no bytes", ticket, op)
			}
			if got := bulkTargetEmails(req.Targets); len(got) != 1 || got[0] != "sold-one" {
				t.Fatalf("targets = %v; want only the reseller's own", got)
			}
			if got := f.spent(t); got != 10*gb {
				t.Errorf("SpentBytes = %d; want it untouched", got)
			}
		})
	}
}

// --- the admin path -------------------------------------------------------------

// The regression guard for every panel that has no resellers at all: an admin's
// batch must come out of PrepareBulk exactly as it went in.
func TestPrepareBulkLeavesAnAdminsBatchAlone(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 10*gb),
		bulkAccount{email: "admins-client", total: 5 * gb, enable: true},
		bulkAccount{email: "sold-one", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: 7 * gb,
		Targets: f.targets("admins-client", "sold-one"),
	}

	ticket, err := f.rs.PrepareBulk(f.admin, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if ticket.Active {
		t.Errorf("ticket = %+v; an admin sells out of no balance", ticket)
	}
	if got := bulkTargetEmails(req.Targets); len(got) != 2 {
		t.Fatalf("targets = %v; an admin's list is not scoped", got)
	}
	if _, _, err := f.svc.BulkUpdateClients(*req); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	for _, email := range []string{"admins-client", "sold-one"} {
		if got := f.quotaOf(t, email); got != 12*gb {
			t.Errorf("%s quota = %d; want %d", email, got, 12*gb)
		}
	}
	// Including the reseller's own account: an admin topping it up is the house
	// giving traffic away, which is the house's business. What must NOT happen is
	// the reseller's balance moving for a batch they did not run.
	if got := f.spent(t); got != 10*gb {
		t.Errorf("SpentBytes = %d; want it untouched at %d", got, 10*gb)
	}
	if got := f.charged(t, "sold-one"); got != 5*gb {
		t.Errorf("charged = %d; want it untouched at %d", got, 5*gb)
	}
}

// Nil arguments are the logged-out and the not-a-request cases, not a panic.
func TestPrepareBulkIsInertWithoutACallerOrARequest(t *testing.T) {
	rs := &ResellerService{}
	if ticket, err := rs.PrepareBulk(nil, &BulkClientUpdateRequest{Op: "addTraffic"}); err != nil || ticket.Active {
		t.Errorf("nil user: ticket %+v, err %v", ticket, err)
	}
	if ticket, err := rs.PrepareBulk(&model.User{IsReseller: true}, nil); err != nil || ticket.Active {
		t.Errorf("nil request: ticket %+v, err %v", ticket, err)
	}
	if err := rs.RollbackBulk(BulkTicket{}); err != nil {
		t.Errorf("rolling back an inactive ticket: %v", err)
	}
}

// --- rollback -------------------------------------------------------------------

// Reserve-first only works if the release does: a batch whose write fails has to
// put back the balance AND every account's standing, or the next delete refunds
// bytes that were handed back once already.
func TestRollbackBulkRestoresTheBalanceAndEveryCharge(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 10*gb),
		bulkAccount{email: "sold-one", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
		bulkAccount{email: "sold-two", total: 2 * gb, enable: true, owned: true, charged: 2 * gb},
	)
	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: 4 * gb,
		Targets: f.targets("sold-one", "sold-two"),
	}

	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if got := f.spent(t); got != 18*gb {
		t.Fatalf("SpentBytes = %d; want %d before the rollback", got, 18*gb)
	}
	if err := f.rs.RollbackBulk(ticket); err != nil {
		t.Fatalf("RollbackBulk: %v", err)
	}
	if got := f.spent(t); got != 10*gb {
		t.Errorf("SpentBytes = %d; want the original %d", got, 10*gb)
	}
	if got := f.charged(t, "sold-one"); got != 5*gb {
		t.Errorf("sold-one charged = %d; want the original %d", got, 5*gb)
	}
	if got := f.charged(t, "sold-two"); got != 2*gb {
		t.Errorf("sold-two charged = %d; want the original %d", got, 2*gb)
	}
}

// --- deletes --------------------------------------------------------------------

// A delete drops the client_traffics row as part of itself, so by the time any
// refund runs, the record of what the customer used is gone. Measured from that
// wreckage, every deleted account looks untouched and refunds its whole charge:
// sell 10 GB, let the customer move all ten, delete, collect 10 GB back. The
// snapshot is what stops it, so this is the test that matters most in the file.
func TestRefundDeletedMeasuresConsumptionFromBeforeTheDelete(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 40*gb),
		// Charged 10, and 4 of them moved since the charge (base 2, all-time 6).
		bulkAccount{email: "sold-one", total: 10 * gb, enable: true, allTime: 6 * gb,
			owned: true, charged: 10 * gb, base: 2 * gb},
		// A second account so the delete below can really take the first one out of
		// the settings blob: an inbound may not be emptied, and the refund now turns
		// on the account having no membership left anywhere.
		bulkAccount{email: "admins-client", total: gb, enable: true},
	)
	req := &BulkClientUpdateRequest{Op: "delete", Targets: f.targets("sold-one")}
	usage, err := f.rs.BulkUsageSnapshot(req.Targets)
	if err != nil {
		t.Fatalf("BulkUsageSnapshot: %v", err)
	}
	if got := usage["sold-one"]; got != 6*gb {
		t.Fatalf("snapshot = %d; want the account's all-time %d", got, 6*gb)
	}

	// The real delete path, which takes BOTH halves: the settings entry and the
	// traffic row the refund would otherwise have read. Both matter now. The traffic
	// row is what makes consumption unreadable after the fact, and the settings entry
	// is what a refund is conditional on, because an account still listed on an
	// inbound still has a membership, is still selling, and must not be refunded.
	if _, _, err := f.svc.BulkUpdateClients(*req); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	var left int64
	if err := database.GetDB().Model(&xray.ClientTraffic{}).
		Where("email = ?", "sold-one").Count(&left).Error; err != nil {
		t.Fatalf("count traffic rows: %v", err)
	}
	if left != 0 {
		t.Fatalf("the delete left the traffic row behind; this test is not testing what it says")
	}
	if err := f.rs.RefundDeleted("sold-one", usage["sold-one"], true); err != nil {
		t.Fatalf("RefundDeleted: %v", err)
	}

	// 10 charged less 4 consumed: 6 back, not 10.
	if got := f.spent(t); got != 34*gb {
		t.Errorf("SpentBytes = %d; want %d (only the 6 GB the customer never moved)", got, 34*gb)
	}
	var rows int64
	if err := database.GetDB().Model(&model.ResellerClient{}).
		Where("email = ?", "sold-one").Count(&rows).Error; err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("the ledger row survived the delete; a recycled email would inherit it")
	}
}

// An account that burned everything it was sold refunds nothing, and never a
// negative amount, which would be balance minted out of a delete.
func TestRefundDeletedGivesNothingBackForAConsumedAccount(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 40*gb),
		bulkAccount{email: "burned", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
	)
	if err := f.rs.RefundDeleted("burned", 9*gb, true); err != nil { // used more than it was charged
		t.Fatalf("RefundDeleted: %v", err)
	}
	if got := f.spent(t); got != 40*gb {
		t.Errorf("SpentBytes = %d; want it unmoved at %d", got, 40*gb)
	}
}

// The house's own accounts have no ledger row, so every delete path can call this
// without asking first.
func TestRefundDeletedIsANoOpForAHouseAccount(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 40*gb),
		bulkAccount{email: "admins-client", total: 5 * gb, enable: true},
	)
	if err := f.rs.RefundDeleted("admins-client", gb, true); err != nil {
		t.Fatalf("RefundDeleted: %v", err)
	}
	if got := f.spent(t); got != 40*gb {
		t.Errorf("SpentBytes = %d; an admin's account is not charged to anyone", got)
	}
}

// A reseller who tops up and then deducts the same batch must not come out ahead
// of where they started. This is the loop anyone would try first.
func TestPrepareBulkTopUpThenDeductLeavesTheResellerWhereTheyStarted(t *testing.T) {
	f := newBulkFixture(t, bulkProfile(100*gb, 10*gb),
		bulkAccount{email: "sold-one", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
		bulkAccount{email: "sold-two", total: 5 * gb, enable: true, owned: true, charged: 5 * gb},
	)
	up := &BulkClientUpdateRequest{Op: "addTraffic", AmountBytes: 3 * gb, Targets: f.targets("sold-one", "sold-two")}
	if _, err := f.rs.PrepareBulk(f.reseller, up); err != nil {
		t.Fatalf("top up: %v", err)
	}
	if _, _, err := f.svc.BulkUpdateClients(*up); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}

	down := &BulkClientUpdateRequest{Op: "subTraffic", AmountBytes: 3 * gb, Targets: f.targets("sold-one", "sold-two")}
	if _, err := f.rs.PrepareBulk(f.reseller, down); err != nil {
		t.Fatalf("deduct: %v", err)
	}
	if _, _, err := f.svc.BulkUpdateClients(*down); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}

	if got := f.spent(t); got != 10*gb {
		t.Errorf("SpentBytes = %d; want the original %d (nothing was consumed, so the round trip is a wash)", got, 10*gb)
	}
	for _, email := range []string{"sold-one", "sold-two"} {
		if got := f.charged(t, email); got != 5*gb {
			t.Errorf("%s charged = %d; want the original %d", email, got, 5*gb)
		}
		if got := f.quotaOf(t, email); got != 5*gb {
			t.Errorf("%s quota = %d; want the original %d", email, got, 5*gb)
		}
	}
}
