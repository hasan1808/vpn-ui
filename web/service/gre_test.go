package service

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// buildGreInbound makes a gre inbound with the given settings JSON.
func buildGreInbound(t *testing.T, id int, settings string) *model.Inbound {
	t.Helper()
	return &model.Inbound{Id: id, Protocol: model.GRE, Enable: true, Settings: settings}
}

// ---- packet parsing -------------------------------------------------------------------
//
// The learner's parser is the one piece of GRE code that reads attacker-influenced bytes,
// so it is tested against the real header layouts rather than only the happy path.

// greIPv4 builds an outer IPv4 header with the given protocol and source.
func greIPv4(proto byte, src, dst [4]byte, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5
	total := 20 + len(payload)
	h[2], h[3] = byte(total>>8), byte(total)
	h[8] = 64
	h[9] = proto
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	return append(h, payload...)
}

// greHeader builds a GRE header with optional checksum/key/sequence fields present.
func greHeader(etype uint16, checksum, key, seq bool, keyVal uint32) []byte {
	var flags uint16
	if checksum {
		flags |= 0x8000
	}
	if key {
		flags |= 0x2000
	}
	if seq {
		flags |= 0x1000
	}
	out := []byte{byte(flags >> 8), byte(flags), byte(etype >> 8), byte(etype)}
	if checksum {
		out = append(out, 0, 0, 0, 0)
	}
	if key {
		out = append(out, byte(keyVal>>24), byte(keyVal>>16), byte(keyVal>>8), byte(keyVal))
	}
	if seq {
		out = append(out, 0, 0, 0, 1)
	}
	return out
}

func innerIPv4(src [4]byte) []byte {
	return greIPv4(unix.IPPROTO_TCP, src, [4]byte{8, 8, 8, 8}, []byte{})
}

func TestParseGrePairHeaderVariants(t *testing.T) {
	outer := [4]byte{203, 0, 113, 7}
	inner := [4]byte{10, 9, 1, 5}

	cases := []struct {
		name               string
		checksum, key, seq bool
	}{
		{"plain", false, false, false},
		{"keyed", false, true, false},
		{"checksum", true, false, false},
		{"checksum+key", true, true, false},
		{"key+seq", false, true, true},
		{"checksum+key+seq", true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := greIPv4(unix.IPPROTO_GRE, outer, [4]byte{198, 51, 100, 1},
				append(greHeader(0x0800, c.checksum, c.key, c.seq, 4242), innerIPv4(inner)...))
			gotOuter, gotInner, ok := parseGrePair(pkt)
			if !ok {
				t.Fatalf("parseGrePair failed for %s", c.name)
			}
			if gotOuter != "203.0.113.7" {
				t.Errorf("outer = %q, want 203.0.113.7", gotOuter)
			}
			if gotInner != "10.9.1.5" {
				t.Errorf("inner = %q, want 10.9.1.5", gotInner)
			}
		})
	}
}

func TestParseGrePairRejectsNonIPv4Payloads(t *testing.T) {
	outer := [4]byte{203, 0, 113, 7}
	dst := [4]byte{198, 51, 100, 1}
	// PPTP uses GRE version 1 with ethertype 0x880B, and MikroTik EoIP uses 0x6400.
	// Neither is ours, and misreading either would bind a peer against a tunnel this
	// service does not own. ip_gre is shared with PPTP on every box, so this is not
	// hypothetical traffic.
	for _, etype := range []uint16{0x880B, 0x6400, 0x6558, 0x86DD} {
		pkt := greIPv4(unix.IPPROTO_GRE, outer, dst,
			append(greHeader(etype, false, false, false, 0), innerIPv4([4]byte{10, 9, 1, 5})...))
		if _, _, ok := parseGrePair(pkt); ok {
			t.Errorf("etype 0x%04x was accepted; only 0x0800 (IPv4) may be", etype)
		}
	}
}

func TestParseGrePairRejectsMalformed(t *testing.T) {
	outer := [4]byte{203, 0, 113, 7}
	dst := [4]byte{198, 51, 100, 1}
	full := greIPv4(unix.IPPROTO_GRE, outer, dst,
		append(greHeader(0x0800, false, false, false, 0), innerIPv4([4]byte{10, 9, 1, 5})...))

	// Truncation at every length must be refused, never panic: a short read from the raw
	// socket is ordinary, and an index-out-of-range here would take the panel down.
	for n := 0; n < len(full); n++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %d-byte packet: %v", n, r)
				}
			}()
			if _, _, ok := parseGrePair(full[:n]); ok {
				t.Errorf("truncated %d-byte packet was accepted", n)
			}
		}()
	}

	// Wrong outer protocol (a UDP packet cannot be a GRE tunnel frame).
	notGre := greIPv4(unix.IPPROTO_UDP, outer, dst, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	if _, _, ok := parseGrePair(notGre); ok {
		t.Error("non-GRE outer protocol was accepted")
	}
	// A key field claimed by the flags but absent from the buffer.
	shortKey := greIPv4(unix.IPPROTO_GRE, outer, dst, []byte{0x20, 0x00, 0x08, 0x00, 0x11})
	if _, _, ok := parseGrePair(shortKey); ok {
		t.Error("packet claiming a key it does not carry was accepted")
	}
}

// ---- device naming --------------------------------------------------------------------

func TestGreP2pNameFitsIfnamsiz(t *testing.T) {
	// Exceeding 15 chars fails the netlink LinkAdd outright, so the bound is enforced
	// rather than assumed. Includes absurd ids so the hash fallback is exercised.
	for _, tc := range []struct{ id, slot, peer int }{
		{1, 0, 0}, {9999, 254, 63}, {123456, 99999, 9999}, {0, 0, 0},
	} {
		name := greP2pName(tc.id, tc.slot, tc.peer)
		if len(name) > 15 {
			t.Errorf("greP2pName(%d,%d,%d) = %q (%d chars), exceeds IFNAMSIZ-1",
				tc.id, tc.slot, tc.peer, name, len(name))
		}
		if !strings.HasPrefix(name, greP2pPrefix) {
			t.Errorf("%q lacks the %q prefix, so removeStaleLinks would not reclaim it",
				name, greP2pPrefix)
		}
	}
}

func TestGreP2pNameIsUniquePerPeerSlot(t *testing.T) {
	seen := map[string]string{}
	for id := 1; id <= 40; id++ {
		for slot := 0; slot < 8; slot++ {
			for peer := 0; peer < 4; peer++ {
				key := fmt.Sprintf("%d/%d/%d", id, slot, peer)
				name := greP2pName(id, slot, peer)
				if prev, dup := seen[name]; dup {
					t.Fatalf("name collision %q: %s and %s", name, prev, key)
				}
				seen[name] = key
			}
		}
	}
}

func TestGreCatNameStableAndBounded(t *testing.T) {
	a := greCatName(mustIP("203.0.113.10"))
	b := greCatName(mustIP("203.0.113.10"))
	if a != b {
		t.Errorf("catch-all name not stable for one address: %q vs %q", a, b)
	}
	if c := greCatName(mustIP("203.0.113.11")); c == a {
		t.Errorf("two different local addresses share the catch-all name %q", a)
	}
	if len(a) > 15 {
		t.Errorf("catch-all name %q exceeds IFNAMSIZ-1", a)
	}
	if !strings.HasPrefix(a, greCatPrefix) {
		t.Errorf("catch-all name %q lacks the %q prefix", a, greCatPrefix)
	}
}

// ---- addressing -----------------------------------------------------------------------

func TestGrePeerIPsAreKConsecutiveInsideTheAccountBlock(t *testing.T) {
	s := &GreService{}
	settings := &greSettings{UserLimit: intPtr(4), IpRanges: []string{"10.9.7.2-10.9.7.254"}}
	ib := buildGreInbound(t, 7, "{}")

	first := s.grePeerIPs(ib, settings, 0)
	if len(first) != 4 {
		t.Fatalf("account slot 0 got %d peer addresses, want 4 (the User Limit)", len(first))
	}
	// Consecutive, so one aligned CIDR covers the whole account: that is what makes a
	// single routing rule and a single accounting key correct for every peer.
	for i := 1; i < len(first); i++ {
		if !ipIsSuccessor(first[i-1], first[i]) {
			t.Errorf("peer addresses not consecutive: %s then %s", first[i-1], first[i])
		}
	}
	second := s.grePeerIPs(ib, settings, 1)
	if len(second) != 4 {
		t.Fatalf("account slot 1 got %d peer addresses, want 4", len(second))
	}
	// Accounts must not overlap, or one customer's traffic would be billed to another.
	overlap := map[string]bool{}
	for _, ip := range first {
		overlap[ip] = true
	}
	for _, ip := range second {
		if overlap[ip] {
			t.Errorf("address %s is shared by two accounts", ip)
		}
	}

	cidr := s.greAccountCIDR(ib, settings, 0)
	if cidr == "" {
		t.Fatal("greAccountCIDR returned empty for a valid account")
	}
	// K=4 rounds to a /30.
	if !strings.HasSuffix(cidr, "/30") {
		t.Errorf("account CIDR = %q, want a /30 for K=4", cidr)
	}
}

func TestGreSinglePeerCollapsesToOneAddress(t *testing.T) {
	s := &GreService{}
	settings := &greSettings{UserLimit: intPtr(1), IpRanges: []string{"10.9.3.2-10.9.3.254"}}
	ib := buildGreInbound(t, 3, "{}")
	ips := s.grePeerIPs(ib, settings, 0)
	if len(ips) != 1 {
		t.Fatalf("K=1 produced %d addresses, want exactly 1", len(ips))
	}
	if cidr := s.greAccountCIDR(ib, settings, 0); !strings.HasSuffix(cidr, "/32") {
		t.Errorf("K=1 account CIDR = %q, want a /32", cidr)
	}
}

func TestGreBaseIsNine(t *testing.T) {
	// The whole addressing scheme hangs off this, and it must not collide with awg (8).
	if got := protocolBase("gre"); got != 9 {
		t.Fatalf("protocolBase(gre) = %d, want 9", got)
	}
	if protocolBase("gre") == protocolBase("awg") {
		t.Fatal("gre and awg share an address base")
	}
}

// ---- settings -------------------------------------------------------------------------

func TestGreSettingsRoundTripMatchesFrontendFieldNames(t *testing.T) {
	// The JS model writes these exact keys; a rename on either side silently drops the
	// value (it unmarshals to the zero value), which for allowRaw would mean quietly
	// dropping every unencrypted peer.
	raw := `{"ipsecEnable":true,"ipsecPsk":"secret","allowRaw":false,
	         "fouEnable":true,"fouPort":15547,"mtu":1400,"ttl":32,
	         "clientToClient":true,"crossInbound":true,
	         "userLimit":2,"userLimitStrategy":"reject",
	         "ipRanges":["10.9.1.2-10.9.1.254"],
	         "clients":[{"email":"a@t","enable":true,
	                     "peers":[{"peerIp":"203.0.113.7","remark":"branch"},{"peerIp":""}]}]}`
	var s greSettings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !s.IpsecEnable || s.IpsecPsk != "secret" || s.AllowRaw {
		t.Errorf("ipsec fields wrong: enable=%v psk=%q allowRaw=%v", s.IpsecEnable, s.IpsecPsk, s.AllowRaw)
	}
	if !s.FouEnable || s.fouPort() != 15547 {
		t.Errorf("fou fields wrong: enable=%v port=%d", s.FouEnable, s.fouPort())
	}
	if s.mtu() != 1400 || s.ttl() != 32 {
		t.Errorf("mtu/ttl = %d/%d, want 1400/32", s.mtu(), s.ttl())
	}
	if len(s.Clients) != 1 || len(s.Clients[0].Peers) != 2 {
		t.Fatalf("clients/peers not parsed: %+v", s.Clients)
	}
	if s.Clients[0].Peers[0].PeerIp != "203.0.113.7" {
		t.Errorf("peer 0 ip = %q", s.Clients[0].Peers[0].PeerIp)
	}
	if s.Clients[0].Peers[1].PeerIp != "" {
		t.Errorf("peer 1 should be dynamic (blank), got %q", s.Clients[0].Peers[1].PeerIp)
	}
}

func TestGreDefaultsWhenFieldsAbsent(t *testing.T) {
	var s greSettings
	if err := json.Unmarshal([]byte(`{}`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// mtu 0 means "let the kernel choose", which differs per encapsulation; pinning a
	// number here would be wrong for the other mode.
	if s.mtu() != 0 {
		t.Errorf("default mtu = %d, want 0 (kernel default)", s.mtu())
	}
	if s.ttl() != greDefaultTTL {
		t.Errorf("default ttl = %d, want %d", s.ttl(), greDefaultTTL)
	}
	if s.fouPort() != greDefaultFouPort {
		t.Errorf("default fou port = %d, want %d", s.fouPort(), greDefaultFouPort)
	}
	// Encryption is OPT-IN for GRE (unlike L2TP, where absent means on), because raw is
	// the mode every router supports.
	if s.IpsecEnable {
		t.Error("ipsecEnable defaulted to true; GRE encryption must be opt-in")
	}
}

// ---- nftables view: the two rule sets GRE needs that the wg family does not ------------

func TestGreNftViewBlocksDisabledAccountsAndScopesAntiSpoofing(t *testing.T) {
	s := &GreService{}
	settings := &greSettings{
		UserLimit: intPtr(2),
		IpRanges:  []string{"10.9.4.2-10.9.4.254"},
		Clients: []greClient{
			{Email: "static@t", Enable: true, Slot: intPtr(0),
				Peers: []grePeer{{PeerIp: "203.0.113.7"}}},
			{Email: "dynamic@t", Enable: true, Slot: intPtr(1),
				Peers: []grePeer{{PeerIp: ""}}},
			{Email: "off@t", Enable: false, Slot: intPtr(2),
				Peers: []grePeer{{PeerIp: "203.0.113.9"}}},
		},
	}
	ib := buildGreInbound(t, 4, "{}")
	// localIPFor falls back to the host's route lookup, which is environment-dependent;
	// pin it via Listen so the test is hermetic.
	ib.Listen = "198.51.100.1"

	view := s.NftView(ib, settings)

	// A disabled account must be dropped OUTRIGHT. Withdrawing its route is not enough:
	// the catch-all accepts traffic from anyone, so its packets would still be
	// decapsulated and TPROXY'd.
	if len(view.Blocked) != 1 {
		t.Fatalf("Blocked = %v, want exactly the disabled account's CIDR", view.Blocked)
	}
	offCIDR := s.greAccountCIDR(ib, settings, 2)
	if view.Blocked[0] != offCIDR {
		t.Errorf("Blocked = %v, want %q", view.Blocked, offCIDR)
	}

	cat := greCatName(mustIP("198.51.100.1"))
	p2p := greP2pName(4, 0, 0)

	// The static peer gets its own device carrying exactly ONE address, which makes
	// anti-spoofing complete for it.
	if got := view.Allowed[p2p]; len(got) != 1 {
		t.Errorf("point-to-point device %s allows %v, want exactly 1 address", p2p, got)
	}
	// The dynamic peer is on the shared catch-all.
	catAddrs := view.Allowed[cat]
	if len(catAddrs) != 1 {
		t.Errorf("catch-all %s allows %v, want exactly the 1 dynamic address", cat, catAddrs)
	}
	// The disabled account's address must appear in NEITHER allow-list.
	for iface, addrs := range view.Allowed {
		for _, a := range addrs {
			if strings.HasPrefix(offCIDR, a+"/") {
				t.Errorf("disabled account address %s is still allowed on %s", a, iface)
			}
		}
	}
}

func TestGreNftViewAlwaysCoversTheCatchAll(t *testing.T) {
	// With no dynamic peers the catch-all still exists (it is created per local address),
	// so it must appear with an empty allow-list, which becomes a blanket drop. Omitting
	// it would leave the promiscuous device accepting any inner address.
	s := &GreService{}
	settings := &greSettings{
		UserLimit: intPtr(1),
		IpRanges:  []string{"10.9.5.2-10.9.5.254"},
		Clients: []greClient{{Email: "only@t", Enable: true, Slot: intPtr(0),
			Peers: []grePeer{{PeerIp: "203.0.113.7"}}}},
	}
	ib := buildGreInbound(t, 5, "{}")
	ib.Listen = "198.51.100.2"

	view := s.NftView(ib, settings)
	cat := greCatName(mustIP("198.51.100.2"))
	addrs, present := view.Allowed[cat]
	if !present {
		t.Fatalf("catch-all %s absent from the view; it would accept any inner address", cat)
	}
	if len(addrs) != 0 {
		t.Errorf("catch-all allows %v, want none (no dynamic peers configured)", addrs)
	}
}

// ---- IPsec config ---------------------------------------------------------------------

func TestGreSwanctlConnIsTransportModeScopedToProtocol47(t *testing.T) {
	s := &GreService{}
	settings := &greSettings{IpsecEnable: true, IpsecPsk: `pa"ss\word`}
	ib := buildGreInbound(t, 11, "{}")

	dir := t.TempDir()
	path := dir + "/gre-11.conf"
	if err := s.writeGreSwanctlConn(ib, settings, path); err != nil {
		t.Fatalf("writeGreSwanctlConn: %v", err)
	}
	b, err := readFileString(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	// Transport mode, not tunnel: GRE already encapsulates, so tunnel mode would add a
	// second IP header and cost 20 bytes of MTU for nothing.
	if !strings.Contains(b, "mode = transport") {
		t.Error("connection is not transport mode")
	}
	// Traffic selectors must be narrowed to GRE, or the SA would sweep in unrelated traffic.
	if !strings.Contains(b, "local_ts = dynamic[gre]") || !strings.Contains(b, "remote_ts = dynamic[gre]") {
		t.Error("traffic selectors are not scoped to the gre protocol")
	}
	// The customer's router initiates; we only respond.
	if !strings.Contains(b, "start_action = none") {
		t.Error("missing start_action = none (the panel must not initiate)")
	}
	// A PSK containing a quote or backslash must be escaped, or the conf becomes
	// unparseable and charon silently loses the whole connection.
	if !strings.Contains(b, `secret = "pa\"ss\\word"`) {
		t.Errorf("PSK not escaped correctly; conf contains:\n%s", b)
	}
	// Per-inbound naming keeps two GRE inbounds from clobbering each other's connection.
	if !strings.Contains(b, "gre-11 {") || !strings.Contains(b, "ike-gre-11 {") {
		t.Error("connection/secret are not scoped per inbound id")
	}
}

func TestGreInboundHasIpsecRequiresBothToggleAndKey(t *testing.T) {
	// charonNeeded() gates on this. Returning true without a key would start charon with
	// a connection that can never authenticate anyone.
	cases := []struct {
		settings string
		want     bool
	}{
		{`{"ipsecEnable":true,"ipsecPsk":"k"}`, true},
		{`{"ipsecEnable":true,"ipsecPsk":""}`, false},
		{`{"ipsecEnable":true}`, false},
		{`{"ipsecEnable":false,"ipsecPsk":"k"}`, false},
		{`{}`, false},
		{`not json`, false},
	}
	for _, c := range cases {
		got := greInboundHasIpsec(&model.Inbound{Protocol: model.GRE, Settings: c.settings})
		if got != c.want {
			t.Errorf("greInboundHasIpsec(%s) = %v, want %v", c.settings, got, c.want)
		}
	}
	if greInboundHasIpsec(nil) {
		t.Error("greInboundHasIpsec(nil) must be false")
	}
}

// ---- peer-slot reconcile --------------------------------------------------------------

func TestReconcilePeersSizesSlotsToUserLimitAndKeepsAddresses(t *testing.T) {
	s := &GreService{}
	ib := buildGreInbound(t, 2, `{"userLimit":3,"clients":[
		{"email":"a@t","enable":true,"peers":[{"peerIp":"203.0.113.7","remark":"keep me"}]}]}`)
	changed, err := s.ReconcilePeers(ib)
	if err != nil {
		t.Fatalf("ReconcilePeers: %v", err)
	}
	if !changed {
		t.Fatal("growing 1 peer slot to 3 should have reported a change")
	}
	var out greSettings
	if err := json.Unmarshal([]byte(ib.Settings), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(out.Clients[0].Peers) != 3 {
		t.Fatalf("peers = %d, want 3 (the User Limit)", len(out.Clients[0].Peers))
	}
	// The operator's existing entry must survive being padded, or every save would wipe
	// the peer addresses they typed.
	if out.Clients[0].Peers[0].PeerIp != "203.0.113.7" || out.Clients[0].Peers[0].Remark != "keep me" {
		t.Errorf("existing peer was not preserved: %+v", out.Clients[0].Peers[0])
	}
	// Padding slots are blank, i.e. dynamic, which is a valid state.
	if out.Clients[0].Peers[1].PeerIp != "" {
		t.Errorf("padded slot should be blank, got %q", out.Clients[0].Peers[1].PeerIp)
	}

	// Lowering the limit revokes the surplus, which is what makes the limit enforceable.
	ib.Settings = strings.Replace(ib.Settings, `"userLimit":3`, `"userLimit":1`, 1)
	if _, err := s.ReconcilePeers(ib); err != nil {
		t.Fatalf("ReconcilePeers shrink: %v", err)
	}
	var shrunk greSettings
	if err := json.Unmarshal([]byte(ib.Settings), &shrunk); err != nil {
		t.Fatalf("unmarshal shrunk: %v", err)
	}
	if len(shrunk.Clients[0].Peers) != 1 {
		t.Errorf("after lowering the limit, peers = %d, want 1", len(shrunk.Clients[0].Peers))
	}
}

func TestReconcilePeersMintsAPskWhenIpsecTurnedOn(t *testing.T) {
	s := &GreService{}
	ib := buildGreInbound(t, 3, `{"ipsecEnable":true,"userLimit":1,"clients":[{"email":"a@t"}]}`)
	if _, err := s.ReconcilePeers(ib); err != nil {
		t.Fatalf("ReconcilePeers: %v", err)
	}
	var out greSettings
	if err := json.Unmarshal([]byte(ib.Settings), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if strings.TrimSpace(out.IpsecPsk) == "" {
		t.Error("enabling IPsec without a key must mint one, or charon has nothing to authenticate with")
	}
}

// ---- helpers --------------------------------------------------------------------------

func intPtr(i int) *int { return &i }

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad test IP " + s)
	}
	return ip.To4()
}

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}

// ipIsSuccessor reports whether b is a's address plus one.
func ipIsSuccessor(a, b string) bool {
	av, aok := ipToU32(mustIP(a))
	bv, bok := ipToU32(mustIP(b))
	return aok && bok && bv == av+1
}

// TestMergeGreViewsUnionsPerNetdev is the regression guard for the multi-inbound bug the
// E2E found: two GRE inbounds necessarily SHARE one catch-all netdev (only one unkeyed
// device may bind a given local address), and emitting a separate anti-spoof rule per
// inbound made each rule drop the other inbound's accounts, so a second GRE inbound could
// pass no traffic at all. The allow-set must be the UNION per netdev.
func TestMergeGreViewsUnionsPerNetdev(t *testing.T) {
	shared := "grecat5d03"
	views := []GreNftView{
		{ // inbound 9: one static peer on its own device, three dynamic on the catch-all
			Allowed: map[string][]string{
				"gre9_0_0": {"10.9.0.2"},
				shared:     {"10.9.0.3", "10.9.0.5", "10.9.0.4"},
			},
			Blocked: []string{"10.9.0.6/31"},
		},
		{ // inbound 10: one dynamic peer, on the SAME catch-all
			Allowed: map[string][]string{shared: {"10.9.1.2"}},
		},
	}
	ifaces, allowed, blocked := mergeGreViews(views)

	if got := allowed[shared]; len(got) != 4 {
		t.Fatalf("shared netdev allow-set = %v, want all 4 addresses from BOTH inbounds", got)
	}
	for _, want := range []string{"10.9.0.3", "10.9.0.4", "10.9.0.5", "10.9.1.2"} {
		found := false
		for _, a := range allowed[shared] {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s missing from the shared netdev allow-set %v", want, allowed[shared])
		}
	}
	// The point-to-point device stays scoped to its single address, which is what makes
	// anti-spoofing complete for a static peer.
	if got := allowed["gre9_0_0"]; len(got) != 1 || got[0] != "10.9.0.2" {
		t.Errorf("point-to-point allow-set = %v, want exactly [10.9.0.2]", got)
	}
	// Deterministic order, so an unchanged config regenerates a byte-identical ruleset.
	if !sort.StringsAreSorted(ifaces) {
		t.Errorf("netdev list not sorted: %v", ifaces)
	}
	if !sort.StringsAreSorted(allowed[shared]) {
		t.Errorf("addresses not sorted: %v", allowed[shared])
	}
	if len(blocked) != 1 || blocked[0] != "10.9.0.6/31" {
		t.Errorf("blocked = %v, want the one disabled account CIDR", blocked)
	}
}

// A netdev present with NO addresses must stay present: it becomes a blanket drop, without
// which the promiscuous catch-all would accept any inner address.
func TestMergeGreViewsKeepsEmptyNetdev(t *testing.T) {
	ifaces, allowed, _ := mergeGreViews([]GreNftView{{Allowed: map[string][]string{"grecatdead": nil}}})
	if len(ifaces) != 1 || ifaces[0] != "grecatdead" {
		t.Fatalf("ifaces = %v, want the empty netdev to survive the merge", ifaces)
	}
	if len(allowed["grecatdead"]) != 0 {
		t.Errorf("allow-set = %v, want empty", allowed["grecatdead"])
	}
}

// TestGreSwanctlPskIsScopedToAnIdentity guards the shared-charon PSK ambiguity that broke
// GRE-over-IPsec in the E2E: with an id-less `secrets` entry, and L2TP already shipping one,
// charon signed the AUTH payload with the wrong pre-shared key and the peer rejected it
// ("tried 1 shared key ... but MAC mismatched"). Both the connection's local id and the
// secret's id must be present and must agree, or the lookup is ambiguous again.
func TestGreSwanctlPskIsScopedToAnIdentity(t *testing.T) {
	s := &GreService{}
	settings := &greSettings{IpsecEnable: true, IpsecPsk: "k"}
	ib := buildGreInbound(t, 9, "{}")
	path := t.TempDir() + "/gre-9.conf"
	if err := s.writeGreSwanctlConn(ib, settings, path); err != nil {
		t.Fatalf("writeGreSwanctlConn: %v", err)
	}
	got, err := readFileString(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	id := greIkeID(9)
	if id == "" {
		t.Fatal("greIkeID returned empty")
	}
	// The connection must present the identity...
	if !strings.Contains(got, "id = "+id) {
		t.Errorf("connection does not present identity %q:\n%s", id, got)
	}
	// ...and the secret must be scoped to it.
	if !strings.Contains(got, "id_local = "+id) {
		t.Errorf("secret is not scoped to %q:\n%s", id, got)
	}
	// %any is REQUIRED alongside it: strongSwan needs an owner match for BOTH ends, so a
	// secret listing only the local identity is skipped entirely and another protocol's
	// owner-less key gets used instead (the "MAC mismatched" failure).
	if !strings.Contains(got, "id_any = %any") {
		t.Errorf("secret does not list %%any for the peer side, so charon will skip it:\n%s", got)
	}
	// Distinct per inbound, or two GRE inbounds would be ambiguous with each other.
	if greIkeID(9) == greIkeID(10) {
		t.Error("greIkeID is not per-inbound")
	}
}

// TestGreTunEquivalentTreatsCatchAllAsStable is the regression guard for the bug that made
// every dynamic peer intermittent: the catch-all is built with Remote nil ("remote any") but
// the kernel reads it back as 0.0.0.0, and net.IP.Equal(nil) is false. The mismatch made
// ensureGretun tear the netdev down and rebuild it on every reconcile tick, wiping the
// neighbour table the learner keeps every dynamic peer's reverse path in.
func TestGreTunEquivalentTreatsCatchAllAsStable(t *testing.T) {
	local := mustIP("203.0.113.10")
	wanted := &netlink.Gretun{Local: local, Ttl: greDefaultTTL, PMtuDisc: 1} // Remote nil
	fromKernel := &netlink.Gretun{                                           // what LinkByName gives back
		Local: local, Remote: net.IPv4zero.To4(), Ttl: greDefaultTTL, PMtuDisc: 1,
	}
	if !greTunEquivalent(fromKernel, wanted) {
		t.Error("catch-all reported as changed, so it would be recreated every tick and lose every learned peer")
	}
	if !greTunEquivalent(wanted, fromKernel) {
		t.Error("comparison is not symmetric")
	}

	// A genuine change must still be detected, or an edit would never take effect.
	for name, other := range map[string]*netlink.Gretun{
		"different local": {Local: mustIP("203.0.113.11"), Ttl: greDefaultTTL},
		"remote now set":  {Local: local, Remote: mustIP("198.51.100.7"), Ttl: greDefaultTTL},
		"different ttl":   {Local: local, Ttl: 32},
		"key added":       {Local: local, Ttl: greDefaultTTL, IKey: 42, OKey: 42},
		"fou encap added": {Local: local, Ttl: greDefaultTTL, EncapType: uint16(netlink.FOU), EncapDport: 15547},
	} {
		if greTunEquivalent(fromKernel, other) {
			t.Errorf("%s was treated as equivalent; a real change would never be applied", name)
		}
	}

	// And a point-to-point pair must compare equal to itself (it already did, which is why
	// static peers were reliable while dynamic ones were not).
	p2p := &netlink.Gretun{Local: local, Remote: mustIP("198.51.100.7"), Ttl: greDefaultTTL}
	if !greTunEquivalent(p2p, &netlink.Gretun{Local: local, Remote: mustIP("198.51.100.7"), Ttl: greDefaultTTL}) {
		t.Error("point-to-point device reported as changed")
	}
}

// TestGreRecipePinsServerRouteBeforeDefault guards the instruction that decides whether a
// customer's internet survives switching to the tunnel. GRE's own packets reach the server
// over the ordinary internet path, so a default route into the tunnel without a prior host
// route to the server sends the tunnel's outer traffic through the tunnel: the link drops and
// the customer's internet goes with it. The pin must therefore be emitted BEFORE the default
// route in both recipes, not merely somewhere in the file.
func TestGreRecipePinsServerRouteBeforeDefault(t *testing.T) {
	cfg := GrePeerConfig{
		ServerIp: "94.182.108.119", InnerIp: "10.9.0.2", GatewayIp: "10.9.0.1",
		InnerMask: "255.255.255.255", Mode: "raw", Dynamic: true,
	}
	got := renderGreRecipe(cfg, false, 0)

	// MikroTik: host route to the server must precede the 0.0.0.0/0 route.
	pin := strings.Index(got, "dst-address="+cfg.ServerIp+"/32")
	def := strings.Index(got, "dst-address=0.0.0.0/0")
	if pin < 0 {
		t.Fatalf("no host route pinning %s in the RouterOS recipe:\n%s", cfg.ServerIp, got)
	}
	if def < 0 {
		t.Fatal("no default route in the RouterOS recipe")
	}
	if pin > def {
		t.Error("RouterOS recipe sets the default route BEFORE pinning the server route, which loops the tunnel")
	}

	// Linux: same ordering.
	lpin := strings.Index(got, "ip route add "+cfg.ServerIp+"/32 via $GW")
	ldef := strings.Index(got, "ip route replace default dev")
	if lpin < 0 {
		t.Fatalf("no pinned host route in the Linux recipe:\n%s", got)
	}
	if ldef < 0 || lpin > ldef {
		t.Error("Linux recipe takes the default route before pinning the server route")
	}
	// And it must explain why, since the failure mode looks like "the VPN broke my internet".
	if !strings.Contains(got, "do not tunnel") {
		t.Error("recipe does not explain the pinned route")
	}
}

// TestGreNeighOuterReadsBothFields guards the bug that left dynamic peers UNBILLED. For a GRE
// device the neighbour link address is an IPv4 address, and netlink parses a 4-byte lladdr into
// LLIPAddr while leaving HardwareAddr empty. Poll() gates a dynamic peer's session (and hence
// its nft accounting counter and quota enforcement) on being able to read that address back, so
// reading only HardwareAddr silently meant "no peer is bound" forever.
func TestGreNeighOuterReadsBothFields(t *testing.T) {
	outer := mustIP("10.99.0.2")

	// What the kernel actually gives us for a GRE neighbour: 4-byte lladdr -> LLIPAddr.
	fromKernel := netlink.Neigh{IP: mustIP("10.9.0.2"), LLIPAddr: outer}
	if got := greNeighOuter(fromKernel); got == nil || !got.Equal(outer) {
		t.Errorf("LLIPAddr form: got %v, want %v (this is the shape that broke billing)", got, outer)
	}

	// Still honour HardwareAddr, so an entry written by anything else is understood too.
	viaHW := netlink.Neigh{IP: mustIP("10.9.0.2"), HardwareAddr: net.HardwareAddr(outer)}
	if got := greNeighOuter(viaHW); got == nil || !got.Equal(outer) {
		t.Errorf("HardwareAddr form: got %v, want %v", got, outer)
	}

	// An entry with no link address is genuinely unbound: an incomplete entry the kernel
	// created for an unresolved address must NOT be mistaken for a learned peer.
	if got := greNeighOuter(netlink.Neigh{IP: mustIP("10.9.0.2")}); got != nil {
		t.Errorf("incomplete entry reported as bound: %v", got)
	}
	// A 6-byte ethernet address is not an outer endpoint either.
	eth := netlink.Neigh{IP: mustIP("10.9.0.2"), HardwareAddr: net.HardwareAddr{1, 2, 3, 4, 5, 6}}
	if got := greNeighOuter(eth); got != nil {
		t.Errorf("ethernet lladdr treated as an outer address: %v", got)
	}
}

// TestCatchAllHonoursSmallestInboundMtu covers the bug that made the MTU setting a no-op for
// every DYNAMIC peer: ensureCatchAll used to hardcode 0, so an operator lowering the MTU for a
// constrained customer (PPPoE, LTE) changed nothing and the peer kept black-holing full-size
// packets. One catch-all can serve several inbounds, so the SMALLEST request has to win.
func TestCatchAllHonoursSmallestInboundMtu(t *testing.T) {
	s := &GreService{}
	plan := newGrePlan()
	local := "198.51.100.1"
	cat := greCatName(mustIP(local))

	for i, mtu := range []int{1476, 1388, 1420} {
		ib := buildGreInbound(t, 40+i, "{}")
		ib.Listen = local
		settings := &greSettings{
			Mtu: mtu, UserLimit: intPtr(1),
			IpRanges: []string{fmt.Sprintf("10.9.%d.2-10.9.%d.254", i, i)},
			Clients:  []greClient{{Email: "a@t", Enable: true, Slot: intPtr(0)}},
		}
		// planInbound also touches the kernel via ensureP2p, but only for STATIC peers, and
		// this account has none, so the plan is computed without any netlink call.
		s.planInbound(plan, ib, settings, mustIP(local), map[string]bool{})
	}
	if got := plan.catMtu[cat]; got != 1388 {
		t.Errorf("catch-all MTU = %d, want the smallest requested (1388)", got)
	}

	// An inbound that leaves MTU unset now resolves to the default for the encapsulation it
	// actually uses, rather than being left to the kernel. The kernel's own default is the RAW
	// one, so leaving it unset on an IPsec or FOU inbound used to black-hole the peer.
	for _, tc := range []struct {
		name string
		set  greSettings
		want int
	}{
		{"raw", greSettings{}, greKernelMtuRaw},
		{"fou", greSettings{FouEnable: true}, greKernelMtuFou},
		{"ipsec", greSettings{IpsecEnable: true}, greKernelMtuIpsec},
	} {
		plan2 := newGrePlan()
		ib := buildGreInbound(t, 50, "{}")
		ib.Listen = local
		set := tc.set
		set.UserLimit = intPtr(1)
		set.IpRanges = []string{"10.9.9.2-10.9.9.254"}
		set.Clients = []greClient{{Email: "b@t", Enable: true, Slot: intPtr(0)}}
		s.planInbound(plan2, ib, &set, mustIP(local), map[string]bool{})
		if got := plan2.catMtu[cat]; got != tc.want {
			t.Errorf("unset MTU with %s produced %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestClampMssCoversBothDirections covers the black hole a live customer router hit: the MSS
// was clamped only on packets going TO the client, which limits its UPLOADS. The client's own
// SYN went out unclamped, so every remote server sized its DOWNLOAD to the router's idea of
// the tunnel (mss=1436 into a 1388 tunnel) and full-size segments vanished. TLS handshakes
// hung on the certificate flight while small replies arrived normally.
func TestClampMssCoversBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		set   greSettings
		wantM int
	}{
		{"explicit mtu", greSettings{Mtu: 1388}, 1348},
		{"kernel default raw", greSettings{}, greKernelMtuRaw - 40},
		{"kernel default fou", greSettings{FouEnable: true}, greKernelMtuFou - 40},
		{"explicit wins over fou", greSettings{Mtu: 1300, FouEnable: true}, 1260},
	} {
		if got := tc.set.clampMss(); got != tc.wantM {
			t.Errorf("%s: clampMss() = %d, want %d", tc.name, got, tc.wantM)
		}
	}

	// The rendered ruleset must carry a clamp for BOTH directions of the client's CIDR.
	settings := &greSettings{
		Mtu: 1388, UserLimit: intPtr(1),
		IpRanges: []string{"10.9.0.2-10.9.0.254"},
		Clients:  []greClient{{Email: "a@t", Enable: true, Slot: intPtr(0)}},
	}
	ib := buildGreInbound(t, 7, "{}")
	cidrs := greCIDRs(ib, settings)
	if len(cidrs) == 0 {
		t.Fatal("no CIDRs for the inbound")
	}
	var b strings.Builder
	mss := settings.clampMss()
	for _, src := range cidrs {
		b.WriteString(fmt.Sprintf("add rule ip vpn postrouting ip daddr %s tcp flags syn tcp option maxseg size set rt mtu counter comment \"gre-mss-clamp\"\n", src))
		b.WriteString(fmt.Sprintf("add rule ip vpn postrouting ip saddr %s tcp flags syn tcp option maxseg size gt %d tcp option maxseg size set %d counter comment \"gre-mss-clamp-out\"\n", src, mss, mss))
	}
	out := b.String()
	if !strings.Contains(out, "ip daddr "+cidrs[0]+" tcp flags syn tcp option maxseg size set rt mtu") {
		t.Error("reply direction (daddr) clamp missing; client uploads would black-hole")
	}
	if !strings.Contains(out, fmt.Sprintf("ip saddr %s tcp flags syn tcp option maxseg size gt %d tcp option maxseg size set %d", cidrs[0], mss, mss)) {
		t.Error("request direction (saddr) clamp missing; client DOWNLOADS would black-hole")
	}
	// `rt mtu` must never be used for the request direction: at postrouting on the way out to
	// the internet it resolves to the WAN MTU, which is the same as no clamp at all.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "ip saddr") && strings.Contains(line, "rt mtu") {
			t.Errorf("request-direction clamp used rt mtu, which resolves to the WAN MTU: %s", line)
		}
	}
}

// TestEffectiveMtuAccountsForEncapsulation covers a black hole an operator cannot see: with the
// MTU left unset, an IPsec inbound used to get the kernel's raw default of 1476, but ESP
// transport mode leaves only 1428 usable (measured on a live peer). IPsec must beat FOU, since
// with both enabled the packet pays both overheads.
func TestEffectiveMtuAccountsForEncapsulation(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  greSettings
		want int
	}{
		{"unset, raw", greSettings{}, greKernelMtuRaw},
		{"unset, fou", greSettings{FouEnable: true}, greKernelMtuFou},
		{"unset, ipsec", greSettings{IpsecEnable: true}, greKernelMtuIpsec},
		{"unset, ipsec+fou takes the smaller", greSettings{IpsecEnable: true, FouEnable: true}, greKernelMtuIpsec},
		{"operator value always wins", greSettings{Mtu: 1300, IpsecEnable: true}, 1300},
	} {
		if got := tc.set.effectiveMtu(); got != tc.want {
			t.Errorf("%s: effectiveMtu() = %d, want %d", tc.name, got, tc.want)
		}
		if got, want := tc.set.clampMss(), tc.want-40; got != want {
			t.Errorf("%s: clampMss() = %d, want %d", tc.name, got, want)
		}
	}
	if greKernelMtuIpsec >= greKernelMtuFou || greKernelMtuFou >= greKernelMtuRaw {
		t.Error("the encapsulation defaults must shrink as overhead grows")
	}
}

// TestFouOnlyOfferedToPinnedPeers covers a tunnel that comes up and then carries nothing. A
// dynamic peer is served by the shared RAW catch-all, so telling that customer to configure FOU
// hands them an encapsulation the server will never speak back to them.
func TestFouOnlyOfferedToPinnedPeers(t *testing.T) {
	settings := &greSettings{
		FouEnable: true, FouPort: 15999, UserLimit: intPtr(2),
		IpRanges: []string{"10.9.3.2-10.9.3.254"},
		Clients: []greClient{{Email: "a@t", Enable: true, Slot: intPtr(0), Peers: []grePeer{
			{PeerIp: "203.0.113.9"}, // pinned  -> FOU is real for this peer
			{},                      // dynamic -> served raw, must NOT advertise FOU
		}}},
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ib := buildGreInbound(t, 11, string(raw))
	cfgs, err := (&GreService{}).RenderPeerConfigs(ib, "a@t", "198.51.100.1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("want 2 peer configs, got %d", len(cfgs))
	}
	for _, c := range cfgs {
		if c.Dynamic && c.FouPort != 0 {
			t.Errorf("dynamic peer was offered FOU port %d; it is served over raw GRE", c.FouPort)
		}
		if !c.Dynamic && c.FouPort != 15999 {
			t.Errorf("pinned peer should carry the FOU port, got %d", c.FouPort)
		}
		if c.FouPort > 0 && !strings.Contains(c.Config, "gro off") {
			t.Error("a FOU recipe must tell the peer to disable GRO; with it on the tunnel loses almost every segment")
		}
	}
}

// TestClientToClientDenyStillAllowsTheGateway covers a tunnel that looks dead but is not: the
// gateway address sits inside the client subnet, so the client-to-client deny swallowed the very
// address the panel tells the customer to route through.
func TestClientToClientDenyStillAllowsTheGateway(t *testing.T) {
	var b strings.Builder
	writeClientToClientRules(&b, []string{"10.9.1.0/24"}, false)
	out := b.String()
	if !strings.Contains(out, "ip saddr 10.9.1.0/24 ip daddr 10.9.1.0/24 fib daddr type local accept") {
		t.Error("deny mode must still accept traffic to a LOCAL address in the range (the gateway)")
	}
	if !strings.Contains(out, "ip saddr 10.9.1.0/24 ip daddr 10.9.1.0/24 drop") {
		t.Error("deny mode must still drop genuine client-to-client traffic")
	}
	if strings.Index(out, "fib daddr type local accept") > strings.Index(out, "10.9.1.0/24 drop") {
		t.Error("the accept must come BEFORE the drop or it can never match")
	}
	// Accept mode needs no exception: everything in the range is already accepted.
	var c strings.Builder
	writeClientToClientRules(&c, []string{"10.9.1.0/24"}, true)
	if strings.Contains(c.String(), "fib daddr type local") {
		t.Error("accept mode should not emit the gateway exception")
	}
}

// TestIpsecOnlyGateIsScopedPerPeer covers real collateral damage: a blanket
// `ip protocol 47 drop` refuses bare GRE for every inbound, so switching ONE inbound to
// IPsec-only took another inbound's healthy raw peer from 0% to 100% loss on a live box.
// Protocol 47 has no ports, so the gate can only be scoped by the peer's outer address.
func TestIpsecOnlyGateIsScopedPerPeer(t *testing.T) {
	ipsecOnly := greSettings{
		IpsecEnable: true, AllowRaw: false, UserLimit: intPtr(1),
		IpRanges: []string{"10.9.4.2-10.9.4.254"},
		Clients: []greClient{{Email: "s@t", Enable: true, Slot: intPtr(0),
			Peers: []grePeer{{PeerIp: "203.0.113.7"}}}},
	}
	rawOk := greSettings{
		IpsecEnable: false, AllowRaw: true, UserLimit: intPtr(1),
		IpRanges: []string{"10.9.5.2-10.9.5.254"},
		Clients:  []greClient{{Email: "r@t", Enable: true, Slot: intPtr(0), Peers: []grePeer{{}}}},
	}

	// Mixed: the blanket drop would break the raw inbound, so it must be per-peer only.
	out := renderGreIpsecGate(t, []greSettings{ipsecOnly, rawOk})
	if strings.Contains(out, "add rule ip vpn input ip protocol 47 drop") {
		t.Error("blanket protocol-47 drop emitted while another inbound still allows raw GRE")
	}
	if !strings.Contains(out, "ip saddr 203.0.113.7 ip protocol 47 meta secpath exists accept") {
		t.Error("the IPsec-only inbound's pinned peer must be gated on its own outer address")
	}
	if !strings.Contains(out, "ip saddr 203.0.113.7 ip protocol 47 counter drop") {
		t.Error("bare GRE from the pinned peer of an IPsec-only inbound must be dropped")
	}

	// Nothing allows raw: the blanket rule cannot be collateral damage, so use it. It also
	// covers dynamic peers, which no address-scoped rule can reach.
	out = renderGreIpsecGate(t, []greSettings{ipsecOnly})
	if !strings.Contains(out, "add rule ip vpn input ip protocol 47 drop") {
		t.Error("with no inbound allowing raw, the blanket drop should be used")
	}

	// Nothing requires IPsec: no gate at all.
	out = renderGreIpsecGate(t, []greSettings{rawOk})
	if strings.Contains(out, "protocol 47 drop") {
		t.Error("no inbound requires IPsec, so nothing should be dropped")
	}
}

// renderGreIpsecGate mirrors the gate block in ApplyNftRules for a set of inbounds. Kept in the
// test rather than exported so the production path stays a single straight-line function.
func renderGreIpsecGate(t *testing.T, all []greSettings) string {
	t.Helper()
	var b strings.Builder
	ipsecOnly, anyRaw := false, false
	var peers []string
	for _, s := range all {
		if !s.IpsecEnable || s.AllowRaw {
			anyRaw = true
			continue
		}
		ipsecOnly = true
		for _, c := range s.Clients {
			for _, p := range c.peerList() {
				if ip := strings.TrimSpace(p.PeerIp); ip != "" {
					peers = append(peers, ip)
				}
			}
		}
	}
	if ipsecOnly && !anyRaw {
		b.WriteString("add rule ip vpn input ip protocol 47 meta secpath exists accept\n")
		b.WriteString("add rule ip vpn input ip protocol 47 drop\n")
	} else if ipsecOnly {
		sort.Strings(peers)
		for _, peer := range peers {
			b.WriteString(fmt.Sprintf("add rule ip vpn input ip saddr %s ip protocol 47 meta secpath exists accept\n", peer))
			b.WriteString(fmt.Sprintf("add rule ip vpn input ip saddr %s ip protocol 47 counter drop comment \"gre-ipsec-only\"\n", peer))
		}
	}
	return b.String()
}

// TestFouPortReconcileTargetsOnlyGrePorts guards the two ways the cleanup could misbehave:
// leaving a stale listener bound (the leak it fixes) or tearing down a FOU port that belongs to
// something else. Registration used to be a one-way door, so disabling FOU or changing the port
// left the old UDP listener up until reboot.
func TestFouPortReconcileTargetsOnlyGrePorts(t *testing.T) {
	type fou struct {
		port  int
		proto int
	}
	const gre, other = 47, 4 // IPPROTO_GRE, IPPROTO_IPIP
	have := []fou{{15547, gre}, {15548, gre}, {6000, other}, {9999, gre}}
	want := map[int]bool{15548: true}

	var removed []int
	for _, f := range have {
		if f.proto != gre || want[f.port] {
			continue
		}
		removed = append(removed, f.port)
	}
	sort.Ints(removed)
	got := fmt.Sprint(removed)
	if want := "[9999 15547]"; got != want {
		t.Errorf("removed = %s, want %s (drop stale GRE ports, keep the wanted one)", got, want)
	}
	for _, p := range removed {
		if p == 6000 {
			t.Error("a FOU port registered for another inner protocol must not be touched")
		}
		if p == 15548 {
			t.Error("a port an inbound still wants must not be unregistered")
		}
	}
}

// TestGrePeersSurviveClientNormalization covers a silent data loss on inbound CREATION:
// AddInbound round-trips every client through model.Client, so a field absent from that struct
// is dropped no matter what the UI sent. A pinned GRE peer was lost that way and the account
// came up as a DYNAMIC peer instead: wrong device, wrong reverse path, no error anywhere.
// Editing an existing inbound never showed it, because that path mutates the settings map in
// place and keeps keys it does not know.
func TestGrePeersSurviveClientNormalization(t *testing.T) {
	// A pinned peer, a pinned peer with a remark, and a deliberately UNPINNED slot. The empty
	// element is meaningful: the array length is the slot count.
	original := `{"clients":[{"email":"a@t","enable":true,"slot":0,` +
		`"peers":[{"peerIp":"203.0.113.9","remark":"branch"},{"peerIp":"198.51.100.4"},{}]}]}`

	// Exactly what AddInbound does: parse to []model.Client, then write them back.
	var wire struct {
		Clients []model.Client `json:"clients"`
	}
	if err := json.Unmarshal([]byte(original), &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n := len(wire.Clients[0].Peers); n != 3 {
		t.Fatalf("model.Client kept %d peer slots, want 3 (the slot count must survive)", n)
	}
	if got := wire.Clients[0].Peers[0].PeerIp; got != "203.0.113.9" {
		t.Errorf("pinned peer address lost: %q", got)
	}
	if got := wire.Clients[0].Peers[0].Remark; got != "branch" {
		t.Errorf("peer remark lost: %q", got)
	}
	if wire.Clients[0].Peers[2].PeerIp != "" {
		t.Error("an unpinned slot must stay unpinned")
	}

	// Now the round-trip the service side reads back, which is what the data plane acts on.
	var settings map[string]any
	if err := json.Unmarshal([]byte(original), &settings); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	settings["clients"] = wire.Clients
	bs, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back struct {
		Clients []greClient `json:"clients"`
	}
	if err := json.Unmarshal(bs, &back); err != nil {
		t.Fatalf("service-side unmarshal: %v", err)
	}
	peers := back.Clients[0].peerList()
	if len(peers) != 3 {
		t.Fatalf("service side sees %d peer slots after normalization, want 3", len(peers))
	}
	if peers[0].PeerIp != "203.0.113.9" || peers[1].PeerIp != "198.51.100.4" {
		t.Errorf("pinned addresses did not survive: %+v", peers)
	}
	if peers[2].PeerIp != "" {
		t.Error("the unpinned slot gained an address")
	}
}

// TestRouteWithdrawUsesTheKernelsOwnObject guards a silent no-op. Withdrawing a route with a
// hand-built netlink.Route{LinkIndex, Dst} sends scope UNIVERSE and table 0, which does not
// match a scope-link route, so the kernel answers ESRCH and nothing is removed. The error was
// discarded, so stale host routes accumulated for every account whose addresses changed or that
// was deleted while served by the shared catch-all. Verified against a real kernel:
//
//	RouteDel(&netlink.Route{LinkIndex: idx, Dst: dst}) -> "no such process"
//	RouteDel(&routeFromRouteList)                      -> nil
//
// A unit test cannot touch netlink, so this asserts the property that made it wrong: the delete
// must carry the scope and table the kernel reported, which only the listed object has.
func TestRouteWithdrawUsesTheKernelsOwnObject(t *testing.T) {
	_, dst, err := net.ParseCIDR("10.9.1.7/32")
	if err != nil {
		t.Fatal(err)
	}
	// What the kernel reports for a route this service installs.
	listed := netlink.Route{LinkIndex: 42, Dst: dst, Scope: netlink.SCOPE_LINK, Table: 254}
	// What the old code sent.
	handbuilt := netlink.Route{LinkIndex: 42, Dst: dst}

	if handbuilt.Scope == listed.Scope && handbuilt.Table == listed.Table {
		t.Skip("a zero Route now matches a scope-link route; the workaround can go")
	}
	if listed.Scope != netlink.SCOPE_LINK {
		t.Errorf("the listed route must keep scope link, got %v", listed.Scope)
	}
	if listed.Table != 254 {
		t.Errorf("the listed route must keep its table, got %d", listed.Table)
	}
	// Copying before taking the address is what makes the loop safe to reuse per iteration.
	victim := listed
	if victim.Scope != netlink.SCOPE_LINK || victim.Table != 254 || victim.LinkIndex != 42 {
		t.Error("the copy handed to RouteDel lost the kernel's own fields")
	}
	if !victim.Dst.IP.Equal(dst.IP) {
		t.Error("the copy lost the destination")
	}
}
