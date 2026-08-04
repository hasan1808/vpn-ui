package sub

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/op/go-logging"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// The subscription endpoint had no end-to-end coverage at all: not GetSubs, not
// getInboundsBySubId, not the aggregation behind the Subscription-Userinfo header.
// That is how an account served on several inbounds came to be reported as
// "unlimited, never expires" while it really did expire.

var subTestLoggerOnce sync.Once

const (
	// gb keeps the quota numbers readable. totalGB is BYTES throughout this panel,
	// despite the name (web/service/inbound.go: clientTraffic.Total = client.TotalGB).
	gb = int64(1024 * 1024 * 1024)

	// accountsMigratedSetting must stay in step with accountsMigratedKey in
	// web/service/migrationaccounts.go. It is written directly because the constant
	// is unexported and the flag is what every account-backed read is gated on, so a
	// test that could not set it could not tell the two paths apart.
	accountsMigratedSetting = "accountsMigratedAt"
)

func newSubTestDB(t *testing.T) {
	t.Helper()
	subTestLoggerOnce.Do(func() { logger.InitLogger(logging.ERROR) })
	if err := database.InitDB(filepath.Join(t.TempDir(), "sub-test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
}

// subSvc builds the service the router builds, with Show Info off. "-ieo" is the
// shipped default remark model: separator '-', then inbound remark, email, extra.
func subSvc() *SubService {
	return NewSubService(false, "-ieo")
}

func subClient(email, subId string) map[string]any {
	return map[string]any{
		"id":       "11111111-2222-3333-4444-555555555555",
		"email":    email,
		"password": "pw-" + email,
		"enable":   true,
		"subId":    subId,
	}
}

func seedSubInbound(t *testing.T, protocol model.Protocol, port int, remark string, clients ...map[string]any) *model.Inbound {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port, Remark: remark,
		Protocol: protocol, Enable: true, Settings: string(settings),
		StreamSettings: `{"network":"tcp","security":"none"}`,
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return inbound
}

// seedTraffic writes THE client_traffics row an account has. Email is unique
// panel-wide, so there is exactly one however many inbounds serve the account, and
// which inbound it names is an accident of where the account was created.
func seedTraffic(t *testing.T, inboundId int, email string, up, down, total, expiry int64) {
	t.Helper()
	row := xray.ClientTraffic{
		InboundId: inboundId, Email: email, Enable: true,
		Up: up, Down: down, Total: total, ExpiryTime: expiry,
	}
	if err := database.GetDB().Create(&row).Error; err != nil {
		t.Fatalf("create client_traffics row: %v", err)
	}
}

func seedAccount(t *testing.T, email string, totalGB, expiry int64, inboundIds ...int) *model.Account {
	t.Helper()
	account := &model.Account{Email: email, TotalGB: totalGB, ExpiryTime: expiry, Enable: true}
	if err := database.GetDB().Create(account).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	for _, id := range inboundIds {
		if err := database.GetDB().Create(&model.AccountInbound{AccountId: account.Id, InboundId: id}).Error; err != nil {
			t.Fatalf("create membership: %v", err)
		}
	}
	return account
}

func markAccountsMigrated(t *testing.T) {
	t.Helper()
	if err := database.GetDB().Create(&model.Setting{Key: accountsMigratedSetting, Value: "1"}).Error; err != nil {
		t.Fatalf("set migrated flag: %v", err)
	}
}

// header is what the controller puts in Subscription-Userinfo, built exactly as
// subController.subs builds it, so a test asserts on the string the client reads.
func header(traffic xray.ClientTraffic) string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
}

// fragments returns the node NAME of each link, which is what a subscription client
// keys its servers by.
func fragments(t *testing.T, links []string) []string {
	t.Helper()
	var out []string
	for _, link := range links {
		for _, line := range strings.Split(link, "\n") {
			u, err := url.Parse(line)
			if err != nil {
				t.Fatalf("link does not parse: %v (%s)", err, line)
			}
			out = append(out, u.Fragment)
		}
	}
	return out
}

// THE headline test. One account, one quota, one expiry, three inbounds.
//
// client_traffics.Email is unique panel-wide, so only ONE of the three inbounds
// holds the account's row and the other two answer with a zero value. The old
// aggregation folded those zeros in under the rules "any member with total 0 makes
// the subscription unlimited" and "members whose expiry disagrees means no expiry",
// so the customer was shown ∞ traffic and no expiry date while the account really
// did expire and really did stop working.
func TestGetSubsReportsAccountQuotaAcrossThreeInbounds(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const email = "alice@example.com"
	const subId = "sub-alice"
	expiry := time.Now().Add(30 * 24 * time.Hour).UnixMilli()

	vless := seedSubInbound(t, model.VLESS, 40101, "Germany", subClient(email, subId))
	trojan := seedSubInbound(t, model.Trojan, 40102, "France", subClient(email, subId))
	l2tp := seedSubInbound(t, model.L2TP, 40103, "Turkey", subClient(email, subId))

	// The row lives on ONE membership, with real usage on it.
	seedTraffic(t, vless.Id, email, 3*gb, 7*gb, 100*gb, expiry)
	seedAccount(t, email, 100*gb, expiry, vless.Id, trojan.Id, l2tp.Id)

	links, _, traffic, err := subSvc().GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	if len(links) != 3 {
		t.Fatalf("links = %d, want 3 (one per membership): %q", len(links), links)
	}

	if traffic.Total != 100*gb {
		t.Errorf("total = %d, want %d. 0 here is the bug: it renders as ∞ and the account stops working with no warning", traffic.Total, 100*gb)
	}
	if traffic.ExpiryTime != expiry {
		t.Errorf("expire = %d, want %d. 0 here tells the client the account never expires", traffic.ExpiryTime, expiry)
	}
	// Usage is the account's real usage, counted ONCE: the same authoritative row
	// answers all three memberships, so summing it would treble it.
	if traffic.Up != 3*gb || traffic.Down != 7*gb {
		t.Errorf("up/down = %d/%d, want %d/%d", traffic.Up, traffic.Down, 3*gb, 7*gb)
	}

	want := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", 3*gb, 7*gb, 100*gb, expiry/1000)
	if got := header(traffic); got != want {
		t.Errorf("Subscription-Userinfo:\n got=%s\nwant=%s", got, want)
	}
}

// The same fix on the JSON sub, which carried its own copy of the aggregation.
func TestGetJsonReportsAccountQuotaAcrossInbounds(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const email = "alice@example.com"
	const subId = "sub-alice"
	expiry := time.Now().Add(10 * 24 * time.Hour).UnixMilli()

	vless := seedSubInbound(t, model.VLESS, 40201, "Germany", subClient(email, subId))
	trojan := seedSubInbound(t, model.Trojan, 40202, "France", subClient(email, subId))
	seedTraffic(t, vless.Id, email, gb, 2*gb, 50*gb, expiry)
	seedAccount(t, email, 50*gb, expiry, vless.Id, trojan.Id)

	svc := subSvc()
	_, hdr, err := NewSubJsonService("", "", "", "", svc).GetJson(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetJson: %v", err)
	}
	want := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", gb, 2*gb, 50*gb, expiry/1000)
	if hdr != want {
		t.Errorf("json sub header:\n got=%s\nwant=%s", hdr, want)
	}
}

// And on the Clash sub, which carried a third copy.
func TestGetClashReportsAccountQuotaAcrossInbounds(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const email = "alice@example.com"
	const subId = "sub-alice"
	expiry := time.Now().Add(10 * 24 * time.Hour).UnixMilli()

	vless := seedSubInbound(t, model.VLESS, 40301, "Germany", subClient(email, subId))
	trojan := seedSubInbound(t, model.Trojan, 40302, "France", subClient(email, subId))
	seedTraffic(t, vless.Id, email, gb, 2*gb, 50*gb, expiry)
	seedAccount(t, email, 50*gb, expiry, vless.Id, trojan.Id)

	_, hdr, err := NewSubClashService(subSvc()).GetClash(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetClash: %v", err)
	}
	want := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", gb, 2*gb, 50*gb, expiry/1000)
	if hdr != want {
		t.Errorf("clash sub header:\n got=%s\nwant=%s", hdr, want)
	}
}

// The account is authoritative for quota and expiry, so a stale client_traffics row
// (the projection writes both, and they can disagree for a window) must not be what
// the customer is billed against.
func TestGetSubsPrefersAccountQuotaOverStaleTrafficRow(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const email = "alice@example.com"
	const subId = "sub-alice"
	accountExpiry := time.Now().Add(60 * 24 * time.Hour).UnixMilli()

	vless := seedSubInbound(t, model.VLESS, 40401, "Germany", subClient(email, subId))
	seedTraffic(t, vless.Id, email, gb, gb, 10*gb, time.Now().UnixMilli())
	seedAccount(t, email, 200*gb, accountExpiry, vless.Id)

	_, _, traffic, err := subSvc().GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	if traffic.Total != 200*gb {
		t.Errorf("total = %d, want the account's %d", traffic.Total, 200*gb)
	}
	if traffic.ExpiryTime != accountExpiry {
		t.Errorf("expire = %d, want the account's %d", traffic.ExpiryTime, accountExpiry)
	}
}

// An account that has never been counted has no client_traffics row at all. Its
// quota and expiry still have to be reported, or a subscription looks unlimited for
// exactly as long as it takes the customer to send their first packet.
func TestGetSubsReportsAccountWithNoTrafficRowYet(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const email = "new@example.com"
	const subId = "sub-new"
	expiry := time.Now().Add(24 * time.Hour).UnixMilli()

	vless := seedSubInbound(t, model.VLESS, 40501, "Germany", subClient(email, subId))
	seedAccount(t, email, 5*gb, expiry, vless.Id)

	_, _, traffic, err := subSvc().GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	if traffic.Total != 5*gb || traffic.ExpiryTime != expiry {
		t.Errorf("total/expire = %d/%d, want %d/%d", traffic.Total, traffic.ExpiryTime, 5*gb, expiry)
	}
	if traffic.Up != 0 || traffic.Down != 0 {
		t.Errorf("usage = %d/%d, want 0/0", traffic.Up, traffic.Down)
	}
}

// THE GATE. The accounts tables can be fully populated while the backfill has not
// been verified, and until it is, settings.clients is the only truth. An account
// row must not be read then, however tempting it looks, so the legacy per-inbound
// aggregation (collapse and all) is what an unmigrated panel keeps getting.
func TestGetSubsIgnoresAccountsBeforeMigrationCompletes(t *testing.T) {
	newSubTestDB(t)
	// Deliberately NOT calling markAccountsMigrated.

	const email = "alice@example.com"
	const subId = "sub-alice"
	expiry := time.Now().Add(30 * 24 * time.Hour).UnixMilli()

	vless := seedSubInbound(t, model.VLESS, 40601, "Germany", subClient(email, subId))
	trojan := seedSubInbound(t, model.Trojan, 40602, "France", subClient(email, subId))
	seedTraffic(t, vless.Id, email, gb, gb, 100*gb, expiry)
	seedAccount(t, email, 100*gb, expiry, vless.Id, trojan.Id)

	_, _, traffic, err := subSvc().GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	if traffic.Total != 0 || traffic.ExpiryTime != 0 {
		t.Errorf("total/expire = %d/%d, want 0/0: an unmigrated panel must keep the legacy answer, not read half-built account rows",
			traffic.Total, traffic.ExpiryTime)
	}
}

// The legacy path itself, unchanged. Two SEPARATE accounts sharing one subId is the
// pre-accounts way of selling several servers as one subscription, and the rules it
// is aggregated under are load-bearing for every panel that has not migrated.
func TestGetSubsLegacyAggregationIsUnchanged(t *testing.T) {
	expiry := time.Now().Add(30 * 24 * time.Hour).UnixMilli()

	cases := []struct {
		name       string
		first      xray.ClientTraffic
		second     xray.ClientTraffic
		wantTotal  int64
		wantExpiry int64
	}{
		{
			name:       "equal quotas and expiry add up",
			first:      xray.ClientTraffic{Up: gb, Down: gb, Total: 10 * gb, ExpiryTime: expiry},
			second:     xray.ClientTraffic{Up: 2 * gb, Down: 3 * gb, Total: 20 * gb, ExpiryTime: expiry},
			wantTotal:  30 * gb,
			wantExpiry: expiry,
		},
		{
			name:       "one unlimited member makes the whole subscription unlimited",
			first:      xray.ClientTraffic{Total: 10 * gb, ExpiryTime: expiry},
			second:     xray.ClientTraffic{Total: 0, ExpiryTime: expiry},
			wantTotal:  0,
			wantExpiry: expiry,
		},
		{
			name:       "disagreeing expiries report none",
			first:      xray.ClientTraffic{Total: 10 * gb, ExpiryTime: expiry},
			second:     xray.ClientTraffic{Total: 10 * gb, ExpiryTime: expiry + 1000},
			wantTotal:  20 * gb,
			wantExpiry: 0,
		},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			newSubTestDB(t)
			const subId = "sub-shared"
			port := 40700 + i*10
			// No account rows and no migrated flag: this is a pre-accounts panel.
			first := seedSubInbound(t, model.VLESS, port+1, "Germany", subClient("first@example.com", subId))
			second := seedSubInbound(t, model.Trojan, port+2, "France", subClient("second@example.com", subId))
			seedTraffic(t, first.Id, "first@example.com", c.first.Up, c.first.Down, c.first.Total, c.first.ExpiryTime)
			seedTraffic(t, second.Id, "second@example.com", c.second.Up, c.second.Down, c.second.Total, c.second.ExpiryTime)

			_, _, traffic, err := subSvc().GetSubs(subId, "vpn.example.com")
			if err != nil {
				t.Fatalf("GetSubs: %v", err)
			}
			if traffic.Up != c.first.Up+c.second.Up || traffic.Down != c.first.Down+c.second.Down {
				t.Errorf("usage = %d/%d, want %d/%d", traffic.Up, traffic.Down,
					c.first.Up+c.second.Up, c.first.Down+c.second.Down)
			}
			if traffic.Total != c.wantTotal {
				t.Errorf("total = %d, want %d", traffic.Total, c.wantTotal)
			}
			if traffic.ExpiryTime != c.wantExpiry {
				t.Errorf("expire = %d, want %d", traffic.ExpiryTime, c.wantExpiry)
			}
		})
	}
}

// Two accounts under one subId where one of them is multi-inbound: the account is
// counted once and the two are still summed against each other, so the two rules
// coexist rather than one replacing the other.
func TestGetSubsMixesAccountAndLegacyEntries(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const subId = "sub-mixed"
	expiry := time.Now().Add(30 * 24 * time.Hour).UnixMilli()

	vless := seedSubInbound(t, model.VLESS, 40801, "Germany", subClient("alice@example.com", subId))
	trojan := seedSubInbound(t, model.Trojan, 40802, "France", subClient("alice@example.com", subId))
	solo := seedSubInbound(t, model.VLESS, 40803, "Spain", subClient("bob@example.com", subId))

	seedTraffic(t, vless.Id, "alice@example.com", gb, gb, 10*gb, expiry)
	seedAccount(t, "alice@example.com", 10*gb, expiry, vless.Id, trojan.Id)
	seedTraffic(t, solo.Id, "bob@example.com", gb, gb, 20*gb, expiry)
	seedAccount(t, "bob@example.com", 20*gb, expiry, solo.Id)

	_, _, traffic, err := subSvc().GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	if traffic.Total != 30*gb {
		t.Errorf("total = %d, want %d (10 counted once + 20)", traffic.Total, 30*gb)
	}
	if traffic.Up != 2*gb || traffic.Down != 2*gb {
		t.Errorf("usage = %d/%d, want %d/%d (alice counted once + bob)", traffic.Up, traffic.Down, 2*gb, 2*gb)
	}
	if traffic.ExpiryTime != expiry {
		t.Errorf("expire = %d, want %d", traffic.ExpiryTime, expiry)
	}
}

// Identity is case- and whitespace-insensitive everywhere else, so a client entry
// whose email differs from the account's only in case must still resolve to it.
// Otherwise the account silently falls back to the legacy zero row.
func TestGetSubsMatchesAccountIdentityCaseInsensitively(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const subId = "sub-case"
	expiry := time.Now().Add(30 * 24 * time.Hour).UnixMilli()

	vless := seedSubInbound(t, model.VLESS, 40901, "Germany", subClient("Alice@Example.com", subId))
	trojan := seedSubInbound(t, model.Trojan, 40902, "France", subClient("Alice@Example.com", subId))
	seedTraffic(t, vless.Id, "alice@example.com", gb, gb, 42*gb, expiry)
	seedAccount(t, "alice@example.com", 42*gb, expiry, vless.Id, trojan.Id)

	_, _, traffic, err := subSvc().GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	if traffic.Total != 42*gb || traffic.ExpiryTime != expiry {
		t.Errorf("total/expire = %d/%d, want %d/%d", traffic.Total, traffic.ExpiryTime, 42*gb, expiry)
	}
	if traffic.Up != gb || traffic.Down != gb {
		t.Errorf("usage = %d/%d, want %d/%d", traffic.Up, traffic.Down, gb, gb)
	}
}

// -----------------------------------------------------------------------------
// Node names
// -----------------------------------------------------------------------------

// A subscription client keys its servers by NAME: a repeat is not a second server,
// it REPLACES the first. genRemark composes the inbound remark, the email and a
// per-protocol extra, so one account on inbounds that share a remark (or have none)
// produced byte-identical names and the customer saw one server where they had
// three, with nothing logged anywhere.
func TestGetSubsGivesEveryMembershipItsOwnName(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const email = "alice@example.com"
	const subId = "sub-alice"

	for _, remark := range []string{"Germany", ""} {
		t.Run("remark="+remark, func(t *testing.T) {
			newSubTestDB(t)
			markAccountsMigrated(t)
			a := seedSubInbound(t, model.VLESS, 41001, remark, subClient(email, subId))
			b := seedSubInbound(t, model.VLESS, 41002, remark, subClient(email, subId))
			c := seedSubInbound(t, model.Trojan, 41003, remark, subClient(email, subId))
			seedTraffic(t, a.Id, email, 0, 0, 10*gb, 0)
			seedAccount(t, email, 10*gb, 0, a.Id, b.Id, c.Id)

			links, _, _, err := subSvc().GetSubs(subId, "vpn.example.com")
			if err != nil {
				t.Fatalf("GetSubs: %v", err)
			}
			names := fragments(t, links)
			if len(names) != 3 {
				t.Fatalf("names = %q, want 3", names)
			}
			seen := map[string]bool{}
			for _, name := range names {
				if seen[name] {
					t.Fatalf("duplicate node name %q in %q: the client keeps ONE of them", name, names)
				}
				seen[name] = true
			}
		})
	}
}

// The constraint that matters on upgrade: a name that is not a duplicate is never
// rewritten, so nobody's existing subscription entries are renamed (a renamed node
// reads as a brand-new server in every client). An account on ONE inbound cannot be
// affected at all, whatever its remark is.
func TestSingleMembershipRemarksAreByteIdentical(t *testing.T) {
	cases := []struct {
		name   string
		remark string
		want   string
	}{
		{name: "with a remark", remark: "Germany", want: "Germany-alice@example.com"},
		{name: "with no remark", remark: "", want: "alice@example.com"},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			newSubTestDB(t)
			markAccountsMigrated(t)
			const email = "alice@example.com"
			const subId = "sub-alice"
			port := 41100 + i
			inbound := seedSubInbound(t, model.VLESS, port, c.remark, subClient(email, subId))
			seedTraffic(t, inbound.Id, email, 0, 0, 10*gb, 0)
			seedAccount(t, email, 10*gb, 0, inbound.Id)

			links, _, _, err := subSvc().GetSubs(subId, "vpn.example.com")
			if err != nil {
				t.Fatalf("GetSubs: %v", err)
			}
			names := fragments(t, links)
			if len(names) != 1 || names[0] != c.want {
				t.Fatalf("name = %q, want exactly [%q]", names, c.want)
			}
		})
	}
}

// Two DIFFERENT accounts on two inbounds that share a remark do not collide (the
// email is part of the name), so nothing is renamed there either. This is the case
// that would have been renamed by a blunter fix keyed on the inbound remark alone.
func TestDistinctAccountsOnEquallyRemarkedInboundsKeepTheirNames(t *testing.T) {
	newSubTestDB(t)
	const subId = "sub-shared"

	seedSubInbound(t, model.VLESS, 41201, "Germany", subClient("alice@example.com", subId))
	seedSubInbound(t, model.VLESS, 41202, "Germany", subClient("bob@example.com", subId))

	links, _, _, err := subSvc().GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	names := fragments(t, links)
	want := []string{"Germany-alice@example.com", "Germany-bob@example.com"}
	if len(names) != 2 || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("names = %q, want %q untouched", names, want)
	}
}

// The disambiguated name names the inbound the node belongs to rather than a bare
// counter, so an operator reading a customer's screenshot can tell which one it is.
func TestDuplicateNameFallsBackToTheInboundTag(t *testing.T) {
	scope := newSubScopeForTest()
	first := &model.Inbound{Id: 1, Tag: "inbound-443", Remark: "Germany"}
	second := &model.Inbound{Id: 2, Tag: "inbound-8443", Remark: "Germany"}
	third := &model.Inbound{Id: 3, Remark: "Germany"} // no tag at all

	if got := scope.uniqueName("Germany-alice", first, "-"); got != "Germany-alice" {
		t.Errorf("first claimant = %q, want it untouched", got)
	}
	if got := scope.uniqueName("Germany-alice", second, "-"); got != "Germany-alice-inbound-8443" {
		t.Errorf("second = %q, want the tag appended", got)
	}
	if got := scope.uniqueName("Germany-alice", third, "-"); got != "Germany-alice-#3" {
		t.Errorf("untagged inbound = %q, want the id appended", got)
	}
	// One inbound emits several nodes when external proxies are configured, and those
	// can share a remark too, so even the disambiguated name has to be able to repeat.
	if got := scope.uniqueName("Germany-alice", second, "-"); got != "Germany-alice-inbound-8443-2" {
		t.Errorf("third collision = %q, want a counter after the tag", got)
	}
}

// The Show Info suffix reads the same row the header does. Without that, the one
// membership owning the client_traffics row showed remaining traffic and days and
// the other two showed nothing, which reads as three unrelated servers.
func TestShowInfoSuffixIsOnEveryMembership(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const email = "alice@example.com"
	const subId = "sub-alice"
	expiry := time.Now().Add(30 * 24 * time.Hour).UnixMilli()

	a := seedSubInbound(t, model.VLESS, 41301, "Germany", subClient(email, subId))
	b := seedSubInbound(t, model.Trojan, 41302, "France", subClient(email, subId))
	seedTraffic(t, a.Id, email, gb, gb, 100*gb, expiry)
	seedAccount(t, email, 100*gb, expiry, a.Id, b.Id)

	links, _, _, err := NewSubService(true, "-ieo").GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	names := fragments(t, links)
	if len(names) != 2 {
		t.Fatalf("names = %q, want 2", names)
	}
	for _, name := range names {
		if !strings.Contains(name, "📊") || !strings.Contains(name, "⏳") {
			t.Errorf("name %q carries no remaining traffic/days; every membership reports the same account", name)
		}
	}
}

// A disabled account is marked on EVERY node, not just the one whose inbound owns
// the traffic row: a customer looking at two working-looking servers and one
// ⛔️N/A has no way to read that.
func TestDisabledAccountIsMarkedOnEveryMembership(t *testing.T) {
	newSubTestDB(t)
	markAccountsMigrated(t)

	const email = "alice@example.com"
	const subId = "sub-alice"

	a := seedSubInbound(t, model.VLESS, 41401, "Germany", subClient(email, subId))
	b := seedSubInbound(t, model.Trojan, 41402, "France", subClient(email, subId))
	seedTraffic(t, a.Id, email, gb, gb, 10*gb, 0)
	account := seedAccount(t, email, 10*gb, 0, a.Id, b.Id)
	account.Enable = false
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("disable account: %v", err)
	}

	links, _, _, err := NewSubService(true, "-ieo").GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	names := fragments(t, links)
	if len(names) != 2 {
		t.Fatalf("names = %q, want 2", names)
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "⛔️N/A") {
			t.Errorf("name %q is not marked, but the account is disabled", name)
		}
	}
}

// -----------------------------------------------------------------------------
// getInboundsBySubId
// -----------------------------------------------------------------------------

func TestGetInboundsBySubIdSelectsOnlyMatchingEnabledInbounds(t *testing.T) {
	newSubTestDB(t)
	const subId = "sub-alice"

	wanted := seedSubInbound(t, model.VLESS, 41501, "Germany", subClient("alice@example.com", subId))
	also := seedSubInbound(t, model.Trojan, 41502, "France", subClient("alice@example.com", subId))
	seedSubInbound(t, model.VLESS, 41503, "Spain", subClient("bob@example.com", "other-sub"))

	disabled := seedSubInbound(t, model.VLESS, 41504, "Italy", subClient("alice@example.com", subId))
	disabled.Enable = false
	if err := database.GetDB().Save(disabled).Error; err != nil {
		t.Fatalf("disable inbound: %v", err)
	}

	got, err := subSvc().getInboundsBySubId(subId)
	if err != nil {
		t.Fatalf("getInboundsBySubId: %v", err)
	}
	if len(got) != 2 || got[0].Id != wanted.Id || got[1].Id != also.Id {
		var ids []int
		for _, in := range got {
			ids = append(ids, in.Id)
		}
		t.Fatalf("inbounds = %v, want [%d %d] in id order", ids, wanted.Id, also.Id)
	}
}

// One inbound whose settings blob is not valid JSON used to fail the whole query:
// SQLite's JSON functions RAISE on malformed input, and the scan evaluates them per
// row, so every subscription on the panel answered "Error!" because of a single
// hand-edited or imported inbound.
func TestGetInboundsBySubIdSurvivesAMalformedSettingsBlob(t *testing.T) {
	newSubTestDB(t)
	const subId = "sub-alice"

	broken := &model.Inbound{
		UserId: 1, Tag: "broken-inbound", Port: 41601,
		Protocol: model.L2TP, Enable: true, Settings: `{"clients": [ THIS IS NOT JSON`,
	}
	if err := database.GetDB().Create(broken).Error; err != nil {
		t.Fatalf("create broken inbound: %v", err)
	}
	healthy := seedSubInbound(t, model.VLESS, 41602, "Germany", subClient("alice@example.com", subId))

	got, err := subSvc().getInboundsBySubId(subId)
	if err != nil {
		t.Fatalf("one broken inbound must not break every subscription: %v", err)
	}
	if len(got) != 1 || got[0].Id != healthy.Id {
		t.Fatalf("inbounds = %+v, want only the healthy one (%d)", got, healthy.Id)
	}
}

// An empty settings blob and one with no clients array are the other two shapes a
// row can take (a protocol whose inbound carries no accounts yet, a partial write).
func TestGetInboundsBySubIdSurvivesEmptyAndClientlessSettings(t *testing.T) {
	newSubTestDB(t)
	const subId = "sub-alice"

	for i, settings := range []string{``, `{}`, `{"clients":null}`, `{"clients":[]}`} {
		inbound := &model.Inbound{
			UserId: 1, Tag: fmt.Sprintf("empty-%d", i), Port: 41700 + i,
			Protocol: model.VLESS, Enable: true, Settings: settings,
		}
		if err := database.GetDB().Create(inbound).Error; err != nil {
			t.Fatalf("create inbound: %v", err)
		}
	}
	healthy := seedSubInbound(t, model.VLESS, 41710, "Germany", subClient("alice@example.com", subId))

	got, err := subSvc().getInboundsBySubId(subId)
	if err != nil {
		t.Fatalf("getInboundsBySubId: %v", err)
	}
	if len(got) != 1 || got[0].Id != healthy.Id {
		t.Fatalf("inbounds = %+v, want only %d", got, healthy.Id)
	}
}

// A subId matching nothing is an error rather than an empty page, which is what
// stops a typo'd link rendering as a working but empty subscription.
func TestGetSubsErrorsOnUnknownSubId(t *testing.T) {
	newSubTestDB(t)
	seedSubInbound(t, model.VLESS, 41801, "Germany", subClient("alice@example.com", "sub-alice"))

	if _, _, _, err := subSvc().GetSubs("nobody", "vpn.example.com"); err == nil {
		t.Fatal("an unknown subId must be an error")
	}
}

// The subscriber page is rendered by TWO calls on two different service instances:
// GetSubs works on its own per-response copy, then the controller calls
// BuildPageData on the shared one. Anything the first stashes on itself is
// therefore not there for the second to read, and the calendar was exactly that:
// a panel configured on the Jalali calendar would silently have rendered Gregorian
// dates, which is a wrong answer rather than a missing one.
func TestBuildPageDataUsesTheConfiguredDatepicker(t *testing.T) {
	newSubTestDB(t)
	if err := database.GetDB().Create(&model.Setting{Key: "datepicker", Value: "jalali"}).Error; err != nil {
		t.Fatalf("set datepicker: %v", err)
	}
	const subId = "sub-alice"
	seedSubInbound(t, model.VLESS, 41901, "Germany", subClient("alice@example.com", subId))

	svc := subSvc()
	subs, lastOnline, traffic, err := svc.GetSubs(subId, "vpn.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	page := svc.BuildPageData(subId, "vpn.example.com", traffic, lastOnline, subs, "", "", "", "/")
	if page.Datepicker != "jalali" {
		t.Errorf("Datepicker = %q, want %q", page.Datepicker, "jalali")
	}
}

// -----------------------------------------------------------------------------
// The fold, as a unit
// -----------------------------------------------------------------------------

// newSubScopeForTest builds a scope without touching the database: uniqueName and
// the fold do not need one, and the name dedup is worth testing on its own.
func newSubScopeForTest() *subScope {
	return &subScope{
		accounts: map[string]*model.Account{},
		traffics: map[string]identityTraffic{},
		names:    map[string]bool{},
	}
}

// The per-identity fold has to leave the cross-identity answer exactly as it was,
// which holds because the legacy rules are order independent: total collapses to 0
// the moment any entry is 0 and never recovers, and expiry collapses the moment any
// entry disagrees. This pins that, so a future refactor of quotaFold cannot quietly
// change what an unmigrated panel reports.
func TestSubUsageMatchesTheLegacyFoldForDistinctIdentities(t *testing.T) {
	rows := []xray.ClientTraffic{
		{Email: "a@x", Up: 1, Down: 2, Total: 10, ExpiryTime: 500},
		{Email: "b@x", Up: 3, Down: 4, Total: 20, ExpiryTime: 500},
		{Email: "c@x", Up: 5, Down: 6, Total: 30, ExpiryTime: 500},
	}

	// The loop GetSubs used to run, verbatim.
	var legacy xray.ClientTraffic
	for index, row := range rows {
		if index == 0 {
			legacy.Up = row.Up
			legacy.Down = row.Down
			legacy.Total = row.Total
			if row.ExpiryTime > 0 {
				legacy.ExpiryTime = row.ExpiryTime
			}
			continue
		}
		legacy.Up += row.Up
		legacy.Down += row.Down
		if legacy.Total == 0 || row.Total == 0 {
			legacy.Total = 0
		} else {
			legacy.Total += row.Total
		}
		if row.ExpiryTime != legacy.ExpiryTime {
			legacy.ExpiryTime = 0
		}
	}

	usage := newSubUsage()
	for _, row := range rows {
		usage.add(row.Email, row, false)
	}
	got := usage.result()
	if got.Up != legacy.Up || got.Down != legacy.Down || got.Total != legacy.Total || got.ExpiryTime != legacy.ExpiryTime {
		t.Errorf("fold diverged from the legacy loop:\n got=%+v\nwant=%+v", got, legacy)
	}
}

// A negative expiry is a not-yet-started account, and this endpoint has always
// reported it as "no expiry" rather than as a date in 1970.
func TestSubUsageReportsNotYetStartedAccountsAsNoExpiry(t *testing.T) {
	usage := newSubUsage()
	usage.add("a@x", xray.ClientTraffic{Total: 10, ExpiryTime: -86400000}, true)
	if got := usage.result().ExpiryTime; got != 0 {
		t.Errorf("expire = %d, want 0", got)
	}
}

// The account-backed entry is taken once however many memberships report it.
func TestSubUsageCountsAnAccountOnce(t *testing.T) {
	row := xray.ClientTraffic{Up: 5, Down: 7, Total: 100, ExpiryTime: 9000}
	usage := newSubUsage()
	for range 3 {
		usage.add("a@x", row, true)
	}
	got := usage.result()
	if got.Up != 5 || got.Down != 7 || got.Total != 100 || got.ExpiryTime != 9000 {
		t.Errorf("three memberships of one account = %+v, want the row itself", got)
	}
}

// lastOnline is the most recent across the whole subscription, wherever it was seen.
func TestSubUsageKeepsTheMostRecentLastOnline(t *testing.T) {
	usage := newSubUsage()
	usage.add("a@x", xray.ClientTraffic{LastOnline: 100}, false)
	usage.add("b@x", xray.ClientTraffic{LastOnline: 900}, false)
	usage.add("c@x", xray.ClientTraffic{LastOnline: 400}, false)
	if usage.lastOnline != 900 {
		t.Errorf("lastOnline = %d, want 900", usage.lastOnline)
	}
}
