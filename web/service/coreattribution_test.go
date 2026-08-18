package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// Attributing the bytes Xray reports without an inbound on them.
//
// The reported bug, twice over: an account on ten inbounds using ONE of them showed
// its whole usage against every Xray inbound it held (or a zero against the one it
// was actually on), and its lamp lit on all ten. Both come from the same place - the
// core's counter is "user>>><email>>>>traffic" with no inbound in it - and both are
// fixed by finishing the attribution from what else the tick knows.
//
// These pin the three rules in web/service/coreattribution.go, and the two things
// that must NOT happen: a pool VPN inbound being chosen (it cannot produce a user
// stat, so those bytes are never its), and a record the panel metered itself being
// second-guessed.

// seedAccountOn puts one account on the given inbounds and gives it the counter row
// a real panel would have created with it.
func seedAccountOn(t *testing.T, svc *AccountService, email string, inbounds ...*model.Inbound) {
	t.Helper()
	svc.MigrationAccounts()
	account, err := svc.GetAccountByEmail(email)
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail(%s): account %v, err %v", email, account, err)
	}
	account.VpnUsername = "login-" + email
	account.Password = "pw-" + email
	account.UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save account: %v", err)
	}
	ids := make([]int, 0, len(inbounds))
	for _, in := range inbounds {
		ids = append(ids, in.Id)
	}
	if _, err := svc.ApplyMemberships(email, ids, nil, true); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}
}

// coreRecord is what the traffic job hands over for bytes Xray counted: an account,
// an amount, and no idea which inbound they came through.
func coreRecord(email string, up, down int64) *xray.ClientTraffic {
	return &xray.ClientTraffic{Email: email, Up: up, Down: down, CoreCounted: true}
}

// inboundTotal is the same tick's per-inbound counter, the evidence rule 3 uses.
func inboundTotal(tag string, up, down int64) *xray.Traffic {
	return &xray.Traffic{IsInbound: true, Tag: tag, Up: up, Down: down}
}

// renderedStats is what the Clients page and the Inbounds page are handed for one
// account on one inbound.
func renderedStats(t *testing.T, inboundId int, email string) *xray.ClientTraffic {
	t.Helper()
	loaded, err := (&InboundService{}).GetAllInbounds()
	if err != nil {
		t.Fatalf("GetAllInbounds: %v", err)
	}
	for _, in := range loaded {
		if in.Id != inboundId {
			continue
		}
		for i := range in.ClientStats {
			if accountKey(in.ClientStats[i].Email) == accountKey(email) {
				return &in.ClientStats[i]
			}
		}
	}
	return nil
}

// Rule 2: one candidate, so no evidence is needed. The account is on an openvpn and a
// vless inbound, and only the vless one can have produced a per-user stat at all.
//
// This is the shape most panels are actually in, and the one that used to leave the
// vless inbound reading 0 used forever.
func TestCoreTrafficLandsOnTheOnlyInboundThatCouldHaveCountedIt(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "onecandidate@example.com"
	openvpn := seedTaggedInbound(t, model.OPENVPN, 48101, []map[string]any{
		{"id": "login-" + email, "email": email, "enable": true, "totalGB": float64(0)},
	})
	vless := seedTaggedInbound(t, model.VLESS, 48102, nil)
	seedAccountOn(t, svc, email, openvpn, vless)
	seedAccountTraffic(t, email, openvpn.Id)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(
		[]*xray.Traffic{inboundTotal("vless-48102", 1*mb, 5*mb)},
		[]*xray.ClientTraffic{coreRecord(email, 1*mb, 5*mb)},
	)
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	share := membershipUsageOf(t, email, vless.Id)
	if share.Up != 1*mb || share.Down != 5*mb {
		t.Fatalf("vless membership = (up %d, down %d); want (%d, %d). A zero here is the "+
			"reported bug: the inbound the customer is actually using shows nothing.",
			share.Up, share.Down, 1*mb, 5*mb)
	}

	row := renderedStats(t, vless.Id, email)
	if row == nil {
		t.Fatal("the vless inbound does not list the account")
	}
	if row.InboundUp != 1*mb || row.InboundDown != 5*mb {
		t.Errorf("vless row = (up %d, down %d); want (%d, %d)", row.InboundUp, row.InboundDown, 1*mb, 5*mb)
	}
	if row.Shared {
		t.Error("the vless row is marked shared, but this tick was attributed to it outright")
	}

	// And the account's other inbound is not credited with bytes it never carried.
	if other := renderedStats(t, openvpn.Id, email); other == nil || other.InboundUp+other.InboundDown != 0 {
		t.Errorf("openvpn row = %+v; want no usage at all", other)
	}
}

// The lamp half of the same fix: liveness is now per membership, so the inbound the
// customer is on lights up and the other nine do not.
func TestCoreTrafficMarksOnlyTheAttributedMembershipOnline(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "lamp@example.com"
	vless := seedTaggedInbound(t, model.VLESS, 48111, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true, "totalGB": float64(0)},
	})
	l2tp := seedTaggedInbound(t, model.L2TP, 48112, nil)
	seedAccountOn(t, svc, email, vless, l2tp)
	seedAccountTraffic(t, email, vless.Id)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(
		[]*xray.Traffic{inboundTotal("vless-48111", 0, 2*mb)},
		[]*xray.ClientTraffic{coreRecord(email, 0, 2*mb)},
	)
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	pairs := inbounds.GetOnlineMemberships()
	want := onlineMembershipKey(vless.Id, email)
	found := false
	for _, pair := range pairs {
		if pair == want {
			found = true
		}
		if pair == onlineMembershipKey(l2tp.Id, email) {
			t.Errorf("the l2tp membership is reported online; the customer connected over vless")
		}
	}
	if !found {
		t.Errorf("online memberships = %v; want %q. Without it the page cannot say which "+
			"inbound the customer is on, and marks every one of them live.", pairs, want)
	}
}

// Rule 1: a pool VPN inbound is never the answer, however busy it is. Its clients
// reach the core through a dokodemo-door with no identity on it, so a per-user stat
// cannot have come from there - and picking it would put another protocol's bytes on
// its bill.
func TestCoreTrafficIsNeverAttributedToAPoolVpnInbound(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "vpnbusy@example.com"
	l2tp := seedTaggedInbound(t, model.L2TP, 48121, []map[string]any{
		{"id": "login-" + email, "email": email, "enable": true, "totalGB": float64(0)},
	})
	vless := seedTaggedInbound(t, model.VLESS, 48122, nil)
	trojan := seedTaggedInbound(t, model.Trojan, 48123, nil)
	seedAccountOn(t, svc, email, l2tp, vless, trojan)
	seedAccountTraffic(t, email, l2tp.Id)

	inbounds := &InboundService{}
	// The l2tp inbound is the only one with traffic on it this tick, and it is still
	// not a candidate: two Xray inbounds remain, neither of them active, so the
	// record stays unattributed.
	err, _, _, _, _ := inbounds.AddTraffic(
		[]*xray.Traffic{inboundTotal("l2tp-48121", 3*mb, 3*mb)},
		[]*xray.ClientTraffic{coreRecord(email, 1*mb, 1*mb)},
	)
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	if share := membershipUsageOf(t, email, l2tp.Id); share.Up != 0 || share.Down != 0 {
		t.Errorf("the l2tp membership was credited with (up %d, down %d) of Xray's bytes; "+
			"a dokodemo-door cannot produce a per-user stat, so those are not its",
			share.Up, share.Down)
	}
	row := renderedStats(t, vless.Id, email)
	if row == nil || !row.Shared || row.InboundUp+row.InboundDown != 2*mb {
		t.Errorf("vless row = %+v; want the pooled remainder %d marked shared", row, 2*mb)
	}
}

// Rule 3: several candidates, and the tick's own per-inbound totals settle it. Only
// one of the account's Xray inbounds moved any bytes at all, so the account's bytes
// are that inbound's.
func TestCoreTrafficFollowsTheOneActiveInbound(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "active@example.com"
	vless := seedTaggedInbound(t, model.VLESS, 48131, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true, "totalGB": float64(0)},
	})
	trojan := seedTaggedInbound(t, model.Trojan, 48132, nil)
	seedAccountOn(t, svc, email, vless, trojan)
	seedAccountTraffic(t, email, vless.Id)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(
		[]*xray.Traffic{
			inboundTotal("trojan-48132", 0, 0),
			inboundTotal("vless-48131", 2*mb, 8*mb),
		},
		[]*xray.ClientTraffic{coreRecord(email, 2*mb, 8*mb)},
	)
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	if share := membershipUsageOf(t, email, vless.Id); share.Up != 2*mb || share.Down != 8*mb {
		t.Errorf("vless membership = (up %d, down %d); want (%d, %d): it was the only one of "+
			"this account's inbounds that carried anything this tick",
			share.Up, share.Down, 2*mb, 8*mb)
	}
	if share := membershipUsageOf(t, email, trojan.Id); share.Up != 0 || share.Down != 0 {
		t.Errorf("trojan membership = (up %d, down %d); want nothing: it moved no bytes at all",
			share.Up, share.Down)
	}
}

// And where the evidence does not settle it, nothing is invented: two of the
// account's inbounds were live, so the bytes stay pooled and both memberships say so.
func TestCoreTrafficStaysPooledWhenTwoInboundsWereLive(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "ambiguous@example.com"
	vless := seedTaggedInbound(t, model.VLESS, 48141, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true, "totalGB": float64(0)},
	})
	trojan := seedTaggedInbound(t, model.Trojan, 48142, nil)
	seedAccountOn(t, svc, email, vless, trojan)
	seedAccountTraffic(t, email, vless.Id)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(
		[]*xray.Traffic{
			inboundTotal("vless-48141", 1*mb, 1*mb),
			inboundTotal("trojan-48142", 1*mb, 1*mb),
		},
		[]*xray.ClientTraffic{coreRecord(email, 1*mb, 3*mb)},
	)
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	for _, in := range []*model.Inbound{vless, trojan} {
		if share := membershipUsageOf(t, email, in.Id); share.Up != 0 || share.Down != 0 {
			t.Errorf("inbound %d was credited with (up %d, down %d); with two of the account's "+
				"inbounds live, which of them moved these bytes is genuinely unknown",
				in.Id, share.Up, share.Down)
		}
		row := renderedStats(t, in.Id, email)
		if row == nil || !row.Shared || row.InboundUp+row.InboundDown != 4*mb {
			t.Errorf("inbound %d row = %+v; want the pooled %d marked shared", in.Id, row, 4*mb)
		}
	}
}

// A relay account. ssh and mtproto terminate outside Xray but egress through a paired
// socks inbound carrying the account's email, so the core bills them as a user stat
// with no inbound on it, exactly like a vless client - and the relay's own stamped
// tally is dropped by the tick's de-duplication before it can say otherwise. That
// left an ssh inbound reading 0 used while the customer was on it all day.
func TestRelayTrafficLandsOnItsInbound(t *testing.T) {
	for _, tc := range []struct {
		protocol model.Protocol
		port     int
	}{
		{model.SSH, 48151},
		{model.MTPROTO, 48152},
	} {
		t.Run(string(tc.protocol), func(t *testing.T) {
			svc := newAccountsDB(t)
			email := string(tc.protocol) + "@example.com"
			relay := seedTaggedInbound(t, tc.protocol, tc.port, []map[string]any{
				{"id": "login-" + email, "email": email, "enable": true, "totalGB": float64(0)},
			})
			seedAccountOn(t, svc, email, relay)
			seedAccountTraffic(t, email, relay.Id)

			inbounds := &InboundService{}
			err, _, _, _, _ := inbounds.AddTraffic(
				[]*xray.Traffic{inboundTotal(relay.Tag, 4*mb, 6*mb)},
				[]*xray.ClientTraffic{coreRecord(email, 4*mb, 6*mb)},
			)
			if err != nil {
				t.Fatalf("AddTraffic: %v", err)
			}

			// Attributed outright, not merely pooled: the relay is the only inbound
			// this account holds, so nothing else could have carried these bytes.
			if share := membershipUsageOf(t, email, relay.Id); share.Up != 4*mb || share.Down != 6*mb {
				t.Errorf("%s membership = (up %d, down %d); want (%d, %d)",
					tc.protocol, share.Up, share.Down, 4*mb, 6*mb)
			}
			row := renderedStats(t, relay.Id, email)
			if row == nil {
				t.Fatal("the relay inbound does not list the account")
			}
			if row.InboundUp+row.InboundDown != 10*mb {
				t.Errorf("%s row = (up %d, down %d); want %d used. Zero is the reported bug.",
					tc.protocol, row.InboundUp, row.InboundDown, 10*mb)
			}
			if row.Shared {
				t.Errorf("%s row is marked shared; every byte of it was attributed", tc.protocol)
			}
		})
	}
}

// A record the panel metered itself is never touched, whether or not it managed to
// name its inbound. Those bytes came off an nft counter on a tunnel address, so
// handing them to the account's vless inbound because it is the only Xray one would
// be filing one protocol's traffic under another.
func TestPanelMeteredRecordsAreNotAttributedToXray(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "metered@example.com"
	l2tp := seedTaggedInbound(t, model.L2TP, 48161, []map[string]any{
		{"id": "login-" + email, "email": email, "enable": true, "totalGB": float64(0)},
	})
	vless := seedTaggedInbound(t, model.VLESS, 48162, nil)
	seedAccountOn(t, svc, email, l2tp, vless)
	seedAccountTraffic(t, email, l2tp.Id)

	inbounds := &InboundService{}
	// The nft collector could not place this session (a panel restarted mid-session),
	// so it reports the bytes with no inbound - and no CoreCounted flag, because they
	// are not Xray's.
	err, _, _, _, _ := inbounds.AddTraffic(nil, []*xray.ClientTraffic{
		{Email: email, Up: 5 * mb, Down: 5 * mb},
	})
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	if share := membershipUsageOf(t, email, vless.Id); share.Up != 0 || share.Down != 0 {
		t.Errorf("the vless membership was credited with (up %d, down %d) of l2tp's bytes",
			share.Up, share.Down)
	}
	if total := accountTrafficOf(t, email); total.Up+total.Down != 10*mb {
		t.Errorf("account total = %d; want %d: unattributed bytes still count against the quota",
			total.Up+total.Down, 10*mb)
	}
}

// Whatever the attribution decides, the breakdown never claims more or less than the
// account row. This is the invariant the whole file rests on: the panel bills from
// client_traffics and displays from the shares, and the two must not disagree.
func TestAttributedSharesStillSumToTheAccountTotal(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "sums@example.com"
	vless := seedTaggedInbound(t, model.VLESS, 48171, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true, "totalGB": float64(0)},
	})
	openvpn := seedTaggedInbound(t, model.OPENVPN, 48172, nil)
	seedAccountOn(t, svc, email, vless, openvpn)
	seedAccountTraffic(t, email, vless.Id)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(
		[]*xray.Traffic{inboundTotal("vless-48171", 0, 7*mb)},
		[]*xray.ClientTraffic{
			coreRecord(email, 0, 7*mb),
			{InboundId: openvpn.Id, Email: email, Up: 0, Down: 3 * mb},
		},
	)
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	total := accountTrafficOf(t, email)
	shares := membershipUsageOf(t, email, vless.Id).Down + membershipUsageOf(t, email, openvpn.Id).Down
	if total.Down != 10*mb {
		t.Errorf("account total down = %d; want %d", total.Down, 10*mb)
	}
	if shares != total.Down {
		t.Errorf("the shares sum to %d but the account row says %d", shares, total.Down)
	}
	// Nothing is left over, so nothing is rendered as shared.
	if row := renderedStats(t, vless.Id, email); row == nil || row.Shared {
		t.Errorf("vless row = %+v; want it not marked shared once every byte is attributed", row)
	}
}

// Every protocol the panel can hold an account on, checked for the one symptom that
// was reported: the inbound a customer is actually using reading 0 while the account
// row above it is right.
//
// The protocols do not get there the same way, which is the point of running all of
// them rather than a representative two. The nine pool VPNs are metered by the panel
// itself (an nft counter per tunnel address, so the record arrives already naming its
// inbound); the two relays and everything Xray terminates are counted per ACCOUNT by
// the core with no inbound on the record at all, and are attributed here.
func TestPerInboundUsageRendersForEveryProtocol(t *testing.T) {
	// Hysteria is deliberately absent: the panel stores v1 and v2 under one
	// protocol string and model.IsHysteria discriminates on settings.version, so
	// seeding "hysteria2" as a protocol would test a row shape the panel never
	// writes.
	protocols := []model.Protocol{
		model.VMESS, model.VLESS, model.Trojan, model.Shadowsocks, model.HTTP,
		model.Mixed, model.WireGuard, model.ANYTLS, model.TUIC, model.NAIVE,
		model.Hysteria,
		model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP,
		model.IKEV2, model.WGC, model.AWG, model.GRE,
		model.MTPROTO, model.SSH,
	}

	for i, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			svc := newAccountsDB(t)
			email := "matrix@example.com"
			used := seedTaggedInbound(t, protocol, 49000+i*2, []map[string]any{
				{"id": "login-" + email, "email": email, "enable": true, "totalGB": float64(0)},
			})
			// A second membership, so this is the multi-inbound account the bug was
			// reported on. Its protocol is chosen to be the opposite family, which
			// leaves exactly one inbound that could have produced a core-counted
			// record and keeps the case unambiguous either way.
			other := model.OPENVPN
			if isVpnProtocol(protocol) {
				other = model.VLESS
			}
			spare := seedTaggedInbound(t, other, 49001+i*2, nil)
			seedAccountOn(t, svc, email, used, spare)
			seedAccountTraffic(t, email, used.Id)

			// What that protocol's collector actually hands in.
			var record *xray.ClientTraffic
			if isVpnProtocol(protocol) {
				record = &xray.ClientTraffic{InboundId: used.Id, Email: email, Up: 4 * mb, Down: 6 * mb}
			} else {
				record = coreRecord(email, 4*mb, 6*mb)
			}

			inbounds := &InboundService{}
			err, _, _, _, _ := inbounds.AddTraffic(
				[]*xray.Traffic{inboundTotal(used.Tag, 4*mb, 6*mb)},
				[]*xray.ClientTraffic{record},
			)
			if err != nil {
				t.Fatalf("AddTraffic: %v", err)
			}

			if total := accountTrafficOf(t, email); total.Up+total.Down != 10*mb {
				t.Fatalf("account total = %d; want %d", total.Up+total.Down, 10*mb)
			}
			row := renderedStats(t, used.Id, email)
			if row == nil {
				t.Fatalf("the %s inbound does not list the account at all", protocol)
			}
			if row.InboundUp+row.InboundDown != 10*mb {
				t.Errorf("%s shows %d used on the inbound the customer is on; want %d",
					protocol, row.InboundUp+row.InboundDown, 10*mb)
			}
			if row.Shared {
				t.Errorf("%s row is marked shared, but these bytes were attributed to it", protocol)
			}
			// And the membership that carried nothing says nothing.
			if idle := renderedStats(t, spare.Id, email); idle == nil || idle.InboundUp+idle.InboundDown != 0 {
				t.Errorf("the account's other inbound (%s) shows %v; want no usage",
					other, idle)
			}
		})
	}
}
