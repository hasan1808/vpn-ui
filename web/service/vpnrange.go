package service

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// VPN client IP addressing lives in per-protocol /16s so cross-protocol
// collisions are impossible by construction:
//
//	L2TP        -> 10.0.0.0/16
//	PPTP        -> 10.1.0.0/16
//	OpenVPN UDP -> 10.2.0.0/16  (TCP mirrors into 10.3.0.0/16)
//	OpenConnect -> 10.4.0.0/16  (single network, no mirror)
//
// Within a protocol, each inbound owns whole /24s; no two inbounds may share a
// /24. L2TP/PPTP inbounds may own an arbitrary list of /24 ranges (grown on
// demand); OpenVPN and OpenConnect own one contiguous, aligned power-of-two block
// (their single `server`/`ipv4-network` directive needs a contiguous CIDR).
//
// This file holds the protocol-agnostic range math + the allocator/validator
// (normalizeRanges) shared by the services, RADIUS, nftables, and the controller.

// ipToU32 converts a 4-byte IP to its uint32 value. Returns 0,false for non-IPv4.
func ipToU32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

// u32ToIP converts a uint32 back to a 4-byte net.IP.
func u32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).To4()
}

// log2i returns the base-2 log of a power of two (0 for values <= 1).
func log2i(n int) int {
	l := 0
	for n > 1 {
		n >>= 1
		l++
	}
	return l
}

// prefixToMask returns the dotted-decimal netmask for an IPv4 prefix length.
func prefixToMask(prefix int) string {
	m := net.CIDRMask(prefix, 32)
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

// parseRange parses one "A.B.C.s-A.B.C.e" range (also accepts the "A.B.C.s-e"
// last-octet shorthand). Both ends must lie within the same /24 and start <= end.
func parseRange(s string) (start, end net.IP, ok bool) {
	s = strings.TrimSpace(s)
	i := strings.IndexByte(s, '-')
	if i < 0 {
		return nil, nil, false
	}
	start = net.ParseIP(strings.TrimSpace(s[:i])).To4()
	if start == nil {
		return nil, nil, false
	}
	endStr := strings.TrimSpace(s[i+1:])
	if strings.Contains(endStr, ".") {
		end = net.ParseIP(endStr).To4()
	} else {
		last, err := strconv.Atoi(endStr)
		if err != nil || last < 0 || last > 255 {
			return nil, nil, false
		}
		end = net.IPv4(start[0], start[1], start[2], byte(last)).To4()
	}
	if end == nil {
		return nil, nil, false
	}
	// Must be the same /24 and non-decreasing.
	if start[0] != end[0] || start[1] != end[1] || start[2] != end[2] || start[3] > end[3] {
		return nil, nil, false
	}
	return start, end, true
}

// canonRange returns the canonical "A.B.C.s-A.B.C.e" form of a valid range.
func canonRange(s string) (string, bool) {
	start, end, ok := parseRange(s)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s-%s", start.String(), end.String()), true
}

// rangeSubnet returns the "A.B.C" /24 prefix of a range (empty if malformed).
func rangeSubnet(s string) string {
	start, _, ok := parseRange(s)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", start[0], start[1], start[2])
}

// rangeCapacity returns the total number of usable host addresses across ranges.
func rangeCapacity(ranges []string) int {
	total := 0
	for _, r := range ranges {
		if start, end, ok := parseRange(r); ok {
			total += int(end[3]) - int(start[3]) + 1
		}
	}
	return total
}

// subnetsOf returns the distinct /24 prefixes ("A.B.C") covered by ranges.
func subnetsOf(ranges []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range ranges {
		if p := rangeSubnet(r); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// protocolBase returns the second octet of a protocol's /16 (OpenVPN => UDP base).
func protocolBase(proto string) int {
	switch proto {
	case "pptp":
		return 1
	case "openvpn":
		return 2
	// 3 is OpenVPN's TCP mirror (mirrorOvpnSubnet), not a protocol of its own.
	case "openconnect":
		return 4
	case "sstp":
		return 5
	case "ikev2":
		return 6
	case "wg-c":
		return 7
	case "awg":
		return 8
	case "gre":
		return 9
	default: // l2tp
		return 0
	}
}

// v6UlaPrefix maps a VPN client subnet "10.{b}.{n}.0/24" to a deterministic
// ULA /64 "fd00:0:BBnn::/64" (BBnn = b<<8|n as one hextet). The (b,n) pair is
// unique per protocol+transport block, so every block owns a distinct pool with
// no allocation bookkeeping: the third hextet carries the whole identity, and
// OpenVPN's server-ipv6 hands each client an address out of the /64 (it rejects
// anything wider than /64). ULA (fc00::/7) is chosen on purpose: it is not
// routable on the internet, so anything confined to it can never reach a real
// v6 site through a misconfigured forward path.
func v6UlaPrefix(subnet string) string {
	parts := strings.Split(subnet, ".")
	if len(parts) < 3 {
		return ""
	}
	b, err := strconv.Atoi(parts[1])
	if err != nil {
		return ""
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil {
		return ""
	}
	if b < 0 || b > 0xfe || n < 0 || n > 0xff {
		return ""
	}
	return fmt.Sprintf("fd00:0:%04x::/64", b<<8|n)
}

// nextFreeSubnet returns the lowest free "10.{base}.{n}" /24 (n in 2..254) for a
// protocol that is absent from every provided occupancy set. "" when exhausted.
func nextFreeSubnet(proto string, usedSets ...map[string]bool) string {
	base := protocolBase(proto)
	for n := 2; n <= 254; n++ {
		p := fmt.Sprintf("10.%d.%d", base, n)
		taken := false
		for _, u := range usedSets {
			if u[p] {
				taken = true
				break
			}
		}
		if !taken {
			return p
		}
	}
	return ""
}

// defaultRange is the default host window for a freshly assigned /24: the full
// usable range .2-.254 (253 addresses). The gateway takes .1, so clients start
// at .2. Matches OpenVPN's per-/24 window (ovpnRangeForSubnet).
func defaultRange(subnet string) string {
	return fmt.Sprintf("%s.2-%s.254", subnet, subnet)
}

// vpnRangeView is a partial view of an inbound's Settings JSON for range math.
type vpnRangeView struct {
	IpRanges []string          `json:"ipRanges"`
	IpRange  string            `json:"ipRange"` // legacy single-range field
	Clients  []json.RawMessage `json:"clients"`
}

// decodeRanges returns the explicit ranges from a settings map (ipRanges, or the
// legacy ipRange seeded as a single-element list). Empty means "unassigned".
func decodeRanges(raw map[string]json.RawMessage) []string {
	var ranges []string
	if rb, ok := raw["ipRanges"]; ok {
		_ = json.Unmarshal(rb, &ranges)
	}
	var cleaned []string
	for _, r := range ranges {
		if strings.TrimSpace(r) != "" {
			cleaned = append(cleaned, strings.TrimSpace(r))
		}
	}
	if len(cleaned) > 0 {
		return cleaned
	}
	if lb, ok := raw["ipRange"]; ok {
		var legacy string
		if json.Unmarshal(lb, &legacy) == nil && strings.TrimSpace(legacy) != "" {
			return []string{strings.TrimSpace(legacy)}
		}
	}
	return nil
}

// decodeClientCount returns the number of client slots (index-based IP allocation
// assigns by array position, so disabled clients still consume a slot).
func decodeClientCount(raw map[string]json.RawMessage) int {
	if cb, ok := raw["clients"]; ok {
		var clients []json.RawMessage
		if json.Unmarshal(cb, &clients) == nil {
			return len(clients)
		}
	}
	return 0
}

// decodeHighestSlot returns the largest stored account slot in a settings map, or -1 when
// no client carries one. An unstamped client counts as its position, which is the address it
// is using (slotOr).
func decodeHighestSlot(raw map[string]json.RawMessage) int {
	cb, ok := raw["clients"]
	if !ok {
		return -1
	}
	var clients []struct {
		Slot *int `json:"slot"`
	}
	if json.Unmarshal(cb, &clients) != nil {
		return -1
	}
	highest := -1
	for i := range clients {
		if s := slotOr(clients[i].Slot, i); s > highest {
			highest = s
		}
	}
	return highest
}

// decodeUserLimit returns the per-inbound User Limit as a device-block size. An
// explicit 0 means "no limit" (=> noLimitDevices); a present value >=1 clamps to
// [1,64]. An ABSENT field is legacy and stays 1 (byte-identical single-IP), which
// is why this checks presence before normalizing (see normUserLimit's note).
func decodeUserLimit(raw map[string]json.RawMessage) int {
	if b, ok := raw["userLimit"]; ok {
		var k int
		if json.Unmarshal(b, &k) == nil {
			return normUserLimit(k)
		}
	}
	return 1
}

// normUserLimitStrategy normalizes the per-inbound "User Limit Strategy" — what
// happens when a (K+1)-th device connects to an account already at its User Limit.
// "reject" refuses the new device; anything else (default/unset) is "accept" —
// disconnect the account's oldest device and admit the new one. Only meaningful
// when User Limit K>1.
func normUserLimitStrategy(s string) string {
	if s == "reject" {
		return "reject"
	}
	return "accept"
}

// inboundRanges returns the effective /24 ranges an inbound currently owns, used
// to build the cross-inbound occupancy set. Falls back to a protocol default
// derived from the inbound id when nothing is stored (legacy inbounds).
func inboundRanges(ib *model.Inbound) []string {
	var raw map[string]json.RawMessage
	if len(ib.Settings) > 0 {
		_ = json.Unmarshal([]byte(ib.Settings), &raw)
	}
	if ranges := decodeRanges(raw); len(ranges) > 0 {
		return ranges
	}
	// Legacy fallback: the deterministic id-derived /24 each protocol used before
	// ranges were stored.
	base := protocolBase(string(ib.Protocol))
	sub := fmt.Sprintf("10.%d.%d", base, ib.Id)
	if ib.Protocol == model.OPENVPN {
		return []string{ovpnRangeForSubnet(sub)}
	}
	return []string{defaultRange(sub)}
}

// usedVpnSubnets returns the set of /24 prefixes owned by every VPN inbound
// except excludeId. OpenVPN inbounds own both their UDP (10.2.x) and mirrored
// TCP (10.3.x) subnets.
func usedVpnSubnets(excludeId int) map[string]bool {
	used := map[string]bool{}
	db := database.GetDB()
	if db == nil {
		return used
	}
	var inbounds []*model.Inbound
	db.Where("protocol IN ?", []string{"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wg-c", "awg", "gre"}).Find(&inbounds)
	for _, ib := range inbounds {
		if ib.Id == excludeId {
			continue
		}
		for _, sub := range subnetsOf(inboundRanges(ib)) {
			used[sub] = true
			if ib.Protocol == model.OPENVPN {
				used[mirrorOvpnSubnet(sub)] = true
			}
		}
	}
	return used
}

// mirrorOvpnSubnet swaps a UDP OpenVPN /24 (10.2.x) for its TCP mirror (10.3.x)
// and vice-versa. Non-OpenVPN subnets pass through unchanged.
func mirrorOvpnSubnet(sub string) string {
	switch {
	case strings.HasPrefix(sub, "10.2."):
		return "10.3." + sub[len("10.2."):]
	case strings.HasPrefix(sub, "10.3."):
		return "10.2." + sub[len("10.3."):]
	}
	return sub
}

// ovpnRangeForSubnet returns the full usable host window (.2-.254) for an
// OpenVPN /24 — its server takes .1 and clients start at .2.
func ovpnRangeForSubnet(subnet string) string {
	return fmt.Sprintf("%s.2-%s.254", subnet, subnet)
}

// NormalizeVpnRanges validates and normalizes an inbound's IP ranges in place
// (see normalizeRanges). Exported for the controller's pre-write validation:
// an overlap returns an error so the save can be rejected. No-op for non-VPN
// protocols.
func NormalizeVpnRanges(inbound *model.Inbound, excludeId int) error {
	return normalizeRanges(inbound, excludeId)
}

// AutoExpandVpnRanges re-normalizes every inbound of a protocol and persists any
// that grew — the auto-expand path for endpoints that change the client count
// without editing ranges (add/remove client). Append-only, so overlap errors
// are logged and skipped rather than surfaced.
// Returns true if any inbound's ranges were expanded/changed and persisted — the
// caller must then reload the daemon so the new range takes effect.
func AutoExpandVpnRanges(protocol string) bool {
	db := database.GetDB()
	if db == nil {
		return false
	}
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ?", protocol).Find(&inbounds).Error; err != nil {
		return false
	}
	expanded := false
	for _, ib := range inbounds {
		before := ib.Settings
		if err := normalizeRanges(ib, ib.Id); err != nil {
			logger.Warningf("range auto-expand skipped for inbound %d: %v", ib.Id, err)
			continue
		}
		if ib.Settings != before {
			if err := db.Model(&model.Inbound{}).Where("id = ?", ib.Id).Update("settings", ib.Settings).Error; err != nil {
				logger.Warningf("range auto-expand persist failed for inbound %d: %v", ib.Id, err)
			} else {
				expanded = true
				logger.Infof("VPN ranges auto-expanded for inbound %d", ib.Id)
			}
		}
	}
	return expanded
}

// normalizeRanges validates, assigns, and auto-expands an inbound's IP ranges,
// writing the normalized ranges back into inbound.Settings. excludeId is the
// inbound's own id on update (0 on add) so it is not treated as an overlap.
//
// For L2TP/PPTP a user-supplied range that overlaps another inbound is rejected
// with an error. OpenVPN ranges are panel-managed (no UI editing), so they are
// re-allocated rather than rejected on conflict.
func normalizeRanges(inbound *model.Inbound, excludeId int) error {
	proto := string(inbound.Protocol)
	if proto != "l2tp" && proto != "pptp" && proto != "openvpn" && proto != "openconnect" && proto != "sstp" && proto != "ikev2" && proto != "wg-c" && proto != "awg" && proto != "gre" {
		return nil
	}

	var raw map[string]json.RawMessage
	if len(inbound.Settings) > 0 {
		if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil {
			return fmt.Errorf("failed to parse settings: %w", err)
		}
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}

	ranges := decodeRanges(raw)
	clientCount := decodeClientCount(raw)
	// Size for the highest SLOT in use, not merely the number of accounts. Slots are
	// stored and survive a delete, so an account can sit ABOVE the count (delete the
	// middle of three: two accounts, highest slot 2). Today the pool would still cover it
	// because keepOwnedBlock never shrinks a block and slots are allocated lowest-free,
	// but that is an invariant two files apart; this makes the sizing say what it means.
	if hs := decodeHighestSlot(raw); hs+1 > clientCount {
		clientCount = hs + 1
	}
	userLimit := decodeUserLimit(raw)
	used := usedVpnSubnets(excludeId)

	var normalized []string
	var err error
	switch proto {
	case "openvpn":
		normalized, err = normalizeOvpnRanges(inbound.Id, clientCount, userLimit, used, ranges)
	case "openconnect":
		// Same aligned-block model as OpenVPN (single contiguous CIDR) but in the
		// 10.4 /16 with no TCP mirror.
		normalized, err = normalizeBlockRanges(inbound.Id, clientCount, userLimit, protocolBase("openconnect"), -1, used, ranges)
	case "ikev2":
		// Aligned-block model like OpenConnect (single contiguous CIDR, no mirror) in
		// the 10.6 /16. One shared charon assigns each account its block IP via the
		// RADIUS Framed-IP-Address, exactly like ocserv.
		normalized, err = normalizeBlockRanges(inbound.Id, clientCount, userLimit, protocolBase("ikev2"), -1, used, ranges)
	case "wg-c":
		// Gateway model: each account owns ONE aligned power-of-two block (nextPow2 of the
		// User Limit, e.g. 6 -> a /29) in the 10.7 /16. User Limit 0 = the maximum 64-device
		// block (/26), via wgc semantics (not the shared decodeUserLimit's no-limit size).
		// Size the /24 allocation by that same block so the range never under-provisions
		// relative to wgcAccountBlock; the kernel interface takes the /24 .1, one Xray
		// source-route per account.
		normalized, err = normalizeBlockRanges(inbound.Id, clientCount, nextPow2(wgcDecodeUserLimit(raw)), protocolBase("wg-c"), -1, used, ranges)
	case "awg":
		// AmneziaWG: identical gateway model to wg-c, in the 10.8 /16 (base 8).
		normalized, err = normalizeBlockRanges(inbound.Id, clientCount, nextPow2(wgcDecodeUserLimit(raw)), protocolBase("awg"), -1, used, ranges)
	case "gre":
		// GRE: same gateway model again, in the 10.9 /16 (base 9). An account owns one
		// aligned block and each of its K peer routers takes one address out of it.
		normalized, err = normalizeBlockRanges(inbound.Id, clientCount, nextPow2(wgcDecodeUserLimit(raw)), protocolBase("gre"), -1, used, ranges)
	default:
		normalized, err = normalizePppRanges(proto, ranges, clientCount, userLimit, used)
	}
	if err != nil {
		return err
	}

	rb, _ := json.Marshal(normalized)
	raw["ipRanges"] = rb
	delete(raw, "ipRange") // superseded by ipRanges

	// L2TP/PPTP: keep localIp in sync with the first range's .1 (the PPP gateway).
	if proto != "openvpn" && proto != "openconnect" && proto != "ikev2" && proto != "wg-c" && proto != "awg" && proto != "gre" && len(normalized) > 0 {
		if s, _, ok := parseRange(normalized[0]); ok {
			lb, _ := json.Marshal(fmt.Sprintf("%d.%d.%d.1", s[0], s[1], s[2]))
			raw["localIp"] = lb
		}
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	inbound.Settings = string(out)
	return nil
}

// normalizePppRanges validates L2TP/PPTP ranges (rejecting overlaps), assigns a
// free /24 when none are given, and appends free /24s until capacity covers the
// client count.
func normalizePppRanges(proto string, ranges []string, clientCount, userLimit int, used map[string]bool) ([]string, error) {
	own := map[string]bool{}
	var valid []string
	for _, r := range ranges {
		canon, ok := canonRange(r)
		if !ok {
			return nil, fmt.Errorf("invalid IP range %q (expected e.g. 10.0.5.2-10.0.5.254 within one /24)", r)
		}
		sub := rangeSubnet(canon)
		if used[sub] {
			return nil, fmt.Errorf("IP range %q overlaps another inbound (subnet %s.0/24 is already in use)", r, sub)
		}
		own[sub] = true
		valid = append(valid, canon)
	}

	if len(valid) == 0 {
		sub := nextFreeSubnet(proto, used)
		if sub == "" {
			return nil, fmt.Errorf("no free /24 subnet available for %s", proto)
		}
		valid = append(valid, defaultRange(sub))
		own[sub] = true
	}

	// Capacity target: for K==1 it's the legacy host count (rangeCapacity, which
	// respects a narrow user range); for K>=2 each account consumes a whole
	// K-block, so capacity is counted in account blocks per /24.
	haveCapacity := func() bool {
		if userLimit <= 1 {
			return rangeCapacity(valid) >= clientCount
		}
		return vpnAccountsCapacity(subnetsOf(valid), userLimit) >= clientCount
	}
	for !haveCapacity() {
		sub := nextFreeSubnet(proto, used, own)
		if sub == "" {
			break // address space exhausted — best effort, stop expanding
		}
		valid = append(valid, defaultRange(sub))
		own[sub] = true
	}
	return valid, nil
}

// normalizeOvpnRanges (re)allocates a contiguous, aligned power-of-two block of
// /24s for an OpenVPN inbound large enough for clientCount. For <=253 clients it
// yields the single legacy /24 (10.2.{id}) whenever that /24 is free, keeping
// existing deployments byte-identical. Thin wrapper over normalizeBlockRanges in
// the OpenVPN /16 (base 10.2) with its TCP mirror (10.3).
func normalizeOvpnRanges(inboundId, clientCount, userLimit int, used map[string]bool, current []string) ([]string, error) {
	return normalizeBlockRanges(inboundId, clientCount, userLimit, 2, 3, used, current)
}

// normalizeBlockRanges (re)allocates a contiguous, aligned power-of-two block of
// /24s in the 10.{base} /16 for a single-CIDR VPN protocol (OpenVPN, OpenConnect)
// large enough for clientCount. mirrorBase is a paired /16 whose matching /24s
// must also stay free (OpenVPN's TCP mirror, 3), or -1 for none. For <=253 clients
// it yields the single legacy /24 (10.{base}.{id}) whenever free, so existing
// inbounds stay byte-identical.
func normalizeBlockRanges(inboundId, clientCount, userLimit, base, mirrorBase int, used map[string]bool, current []string) ([]string, error) {
	needed := clientCount
	if needed < 1 {
		needed = 1
	}
	// Each /24 holds accountsPerSubnet(K) account blocks (253 for K==1, so this
	// stays byte-identical to the legacy sizing for existing inbounds).
	per := accountsPerSubnet(userLimit)
	num24 := 1
	for num24*per < needed {
		num24 *= 2
	}
	if num24 > 64 {
		num24 = 64 // cap the block at a /18 (16k+ hosts)
	}

	// An inbound that already owns a usable block KEEPS it.
	//
	// This is the whole reason `current` is threaded in. Allocation runs again on
	// every reconcile (wgcChanged -> AutoExpandVpnRanges -> normalizeRanges), and
	// allocateAlignedBlock prefers the slot matching the inbound id. On the create
	// path the id is still 0, so inbounds are packed from slot 0 upward and then
	// DRAGGED toward their id on the next reconcile: with two wg-c inbounds, #2
	// moved 10.7.1 -> 10.7.2 on the first reconcile and #1 moved 10.7.0 -> 10.7.1
	// on the second. Deleting any inbound shuffled the survivors again.
	//
	// For the daemon-assigned protocols that only wasted a renumber. For wg-c and
	// awg it is fatal and silent: a WireGuard config hardcodes `Address = <block
	// IP>/32` and the server cryptokey-routes exactly that address, so every config
	// already handed out keeps sourcing an address the peer no longer allows. The
	// handshake still succeeds and not one packet gets through.
	if kept, ok := keepOwnedBlock(current, num24, base, mirrorBase, used); ok {
		return kept, nil
	}

	thirds, ok := allocateAlignedBlock(inboundId, num24, base, mirrorBase, used)
	if !ok {
		return nil, fmt.Errorf("no free aligned block of %d /24s available in 10.%d.0.0/16", num24, base)
	}
	out := make([]string, 0, len(thirds))
	for _, t := range thirds {
		out = append(out, ovpnRangeForSubnet(fmt.Sprintf("10.%d.%d", base, t)))
	}
	return out, nil
}

// keepOwnedBlock reports whether the inbound's CURRENT ranges are still a usable
// block, and returns them re-rendered if so. Usable means: contiguous, a power-of-two
// count, aligned to its own size, at least as big as the inbound now needs, and not
// overlapping another inbound. `used` already excludes the inbound itself (see
// usedVpnSubnets), so an inbound never collides with its own block here.
//
// An oversized block is deliberately kept rather than shrunk. Reclaiming the spare
// /24s would be another reason for a live block to move, and address stability is
// worth far more than a few unused /24s inside a /16.
func keepOwnedBlock(current []string, num24, base, mirrorBase int, used map[string]bool) ([]string, bool) {
	thirds := ovpnThirds(current)
	have := len(thirds)
	if have < num24 || have&(have-1) != 0 { // absent, too small, or not a power of two
		return nil, false
	}
	if thirds[0]%have != 0 { // not aligned to its own size
		return nil, false
	}
	for i, t := range thirds {
		if t != thirds[0]+i { // not contiguous
			return nil, false
		}
		if t > 254 {
			return nil, false
		}
		if used[fmt.Sprintf("10.%d.%d", base, t)] {
			return nil, false // another inbound moved in; this one has to move out
		}
		if mirrorBase >= 0 && used[fmt.Sprintf("10.%d.%d", mirrorBase, t)] {
			return nil, false
		}
	}
	out := make([]string, 0, have)
	for _, t := range thirds {
		out = append(out, ovpnRangeForSubnet(fmt.Sprintf("10.%d.%d", base, t)))
	}
	return out, true
}

// allocateAlignedBlock finds num24 consecutive, aligned free /24 third-octets in
// the 10.{base} /16, preferring the aligned block that contains the inbound id.
// The base slot (10.{base}.x) and, when mirrorBase >= 0, the mirror slot
// (10.{mirrorBase}.x) must both be free.
func allocateAlignedBlock(id, num24, base, mirrorBase int, used map[string]bool) ([]int, bool) {
	free := func(n int) bool {
		if n < 0 || n+num24-1 > 254 {
			return false
		}
		for t := n; t < n+num24; t++ {
			if used[fmt.Sprintf("10.%d.%d", base, t)] {
				return false
			}
			if mirrorBase >= 0 && used[fmt.Sprintf("10.%d.%d", mirrorBase, t)] {
				return false
			}
		}
		return true
	}
	build := func(n int) []int {
		thirds := make([]int, 0, num24)
		for t := n; t < n+num24; t++ {
			thirds = append(thirds, t)
		}
		return thirds
	}
	// Prefer the aligned block that would contain the legacy id-derived /24.
	if n0 := (id / num24) * num24; free(n0) {
		return build(n0), true
	}
	for n := 0; n+num24-1 <= 254; n += num24 {
		if free(n) {
			return build(n), true
		}
	}
	return nil, false
}

// ovpnThirds returns the sorted, distinct third octets covered by OpenVPN's
// (UDP-side, 10.2.x) ranges.
func ovpnThirds(udpRanges []string) []int {
	var thirds []int
	seen := map[int]bool{}
	for _, sub := range subnetsOf(udpRanges) {
		parts := strings.Split(sub, ".")
		if len(parts) != 3 {
			continue
		}
		t, err := strconv.Atoi(parts[2])
		if err != nil || seen[t] {
			continue
		}
		seen[t] = true
		thirds = append(thirds, t)
	}
	sort.Ints(thirds)
	return thirds
}

// vpnBlock returns the network address and prefix length of the aligned block
// covering ranges in the 10.{base} /16. Falls back to the legacy
// 10.{base}.{fallbackId}.0/24 when no ranges are stored. Shared by OpenVPN (base
// 2/3) and OpenConnect (base 4).
func vpnBlock(ranges []string, base, fallbackId int) (net.IP, int) {
	thirds := ovpnThirds(ranges)
	if len(thirds) == 0 {
		return net.IPv4(10, byte(base), byte(fallbackId), 0).To4(), 24
	}
	count := len(thirds)
	// Round up to a power of two so the covering prefix is exact/aligned.
	blk := 1
	for blk < count {
		blk <<= 1
	}
	prefix := 24 - log2i(blk)
	// Align the network address down to the block boundary.
	minThird := thirds[0] &^ (blk - 1)
	return net.IPv4(10, byte(base), byte(minThird), 0).To4(), prefix
}

// ovpnBlock returns the network address and prefix length of the OpenVPN block
// covering udpRanges, for the given transport (udp => 10.2.x, tcp => 10.3.x).
// Falls back to the legacy 10.{2|3}.{fallbackId}.0/24 when no ranges are stored.
func ovpnBlock(udpRanges []string, proto string, fallbackId int) (net.IP, int) {
	base := 2
	if proto == "tcp" {
		base = 3
	}
	return vpnBlock(udpRanges, base, fallbackId)
}

// ovpnBlockClientIP returns the tunnel IP for client index i inside an OpenVPN
// block (network/prefix). The server takes .1 of the block, clients start at .2.
// Returns "" when i overflows the block.
func ovpnBlockClientIP(netAddr net.IP, prefix, i int) string {
	base, ok := ipToU32(netAddr)
	if !ok {
		return ""
	}
	host := uint32(2 + i)
	size := uint32(1) << uint(32-prefix)
	if host >= size-1 { // reserve the block broadcast address
		return ""
	}
	return u32ToIP(base + host).String()
}

// ============================ User Limit (per-account device blocks) =========
//
// A per-inbound "User Limit" K lets ONE account drive K simultaneous devices,
// each with a distinct source IP inside an aligned CIDR block, all matched by a
// single routing rule (the block CIDR). K is a power of two in [1,64].
//
// K==1 is the legacy one-IP-per-account behavior and is deliberately left
// byte-identical: every K>=2 code path is gated, so existing inbounds (which
// have no userLimit, decoding to 1) are completely unaffected.
//
// Layout for K>=2: each /24 an inbound owns is carved into K-aligned sub-blocks.
// The first sub-block (holds .0 network + .1 gateway) and the last (holds .255
// broadcast) are skipped, leaving 256/K - 2 clean blocks. Account `subIdx` in a
// /24 takes block (subIdx+1), i.e. host octets [(subIdx+1)*K, (subIdx+1)*K+K-1].

const maxUserLimit = 64

// noLimitDevices is the effective device-block size for a "no limit" (User Limit
// 0) account. Per-account routing and per-IP quota still work — the account owns a
// real block of that many consecutive IPs — but the block is generous enough that
// normal use never reaches the cap. Tunable: larger = more simultaneous devices per
// account, fewer accounts per /24.
const noLimitDevices = 16

// normUserLimit maps a PRESENT user-limit value to a concrete device-block size.
// An explicit 0 means "no limit" and expands to a generous bounded block
// (noLimitDevices); values >=1 clamp to [1,64]. Any integer is allowed (not just
// powers of two): an account owns K consecutive tunnel IPs, matched in routing by
// an explicit IP list, so no CIDR alignment is required.
//
// IMPORTANT: only call this with a value known to be PRESENT. An ABSENT field
// (legacy inbound) must resolve to 1 via decodeUserLimit / effectiveUserLimit — the
// Go zero value of an absent int is also 0, which here means "no limit", so mixing
// the two up would silently flip every legacy inbound to no-limit.
func normUserLimit(k int) int {
	if k == 0 {
		return noLimitDevices
	}
	if k < 1 {
		return 1
	}
	if k > maxUserLimit {
		return maxUserLimit
	}
	return k
}

// effectiveUserLimit resolves a User Limit unmarshalled into a struct field into a
// device-block size, distinguishing an ABSENT field (nil → 1, legacy single-IP)
// from an explicit 0 (→ no-limit block). Use this at every JSON-struct read site,
// where absent and 0 would otherwise collide on the int zero value.
func effectiveUserLimit(p *int) int {
	if p == nil {
		return 1
	}
	return normUserLimit(*p)
}

// --- Account slots -----------------------------------------------------------------
//
// An account's addresses come from its SLOT in the inbound's pool, which is stored on the
// account (model.Client.Slot). It used to be the account's position in clients[], so
// deleting an account renumbered every account after it and moved live sessions onto other
// accounts' addresses. The slot is allocated once, at creation, and never derived again.

// slotOr returns the account's stored slot, falling back to its position in clients[].
//
// The fallback is for rows the startup migration has not stamped yet (including one
// written by an older binary while a newer one runs): they keep exactly today's behaviour
// instead of collapsing onto slot 0. Every allocator reads its index through this.
func slotOr(slot *int, listIndex int) int {
	if slot != nil && *slot >= 0 {
		return *slot
	}
	return listIndex
}

// slotsForNewAccounts returns, in order, the slots the next n accounts added to an inbound
// would take: the lowest free ones.
//
// Lowest-free rather than monotonic, so a panel that churns accounts does not walk off the
// end of its /24 while most of it sits idle. The consequence is that a new account can
// inherit a deleted one's addresses, which is safe only because every client change rebuilds
// the routing rules and the accounting chains from scratch.
func slotsForNewAccounts(existing []model.Client, n int) []int {
	used := make(map[int]bool, len(existing))
	for i := range existing {
		// An unstamped account effectively holds its list index (slotOr), so it counts
		// too, or a new account would be handed an address already in use.
		used[slotOr(existing[i].Slot, i)] = true
	}
	out := make([]int, 0, n)
	for slot := 0; len(out) < n; slot++ {
		if !used[slot] {
			used[slot] = true
			out = append(out, slot)
		}
	}
	return out
}

var slotPoolProtocols = []string{"l2tp", "pptp", "openvpn", "openconnect", "sstp",
	"ikev2", "wg-c", "awg", "gre"}

// slotPoolProtocol reports whether a protocol's accounts draw a tunnel address from a pool,
// which is the only case a slot means anything. mtproto and ssh relay (identity is the
// secret / username) and the Xray protocols have no pool, so their client JSON is left
// alone.
func slotPoolProtocol(p model.Protocol) bool {
	for _, sp := range slotPoolProtocols {
		if string(p) == sp {
			return true
		}
	}
	return false
}

// assignSlotsToClientMaps stamps a pool slot onto each raw client map that has none.
//
// It works on the raw JSON maps rather than []model.Client because the add/update paths
// splice what the caller posted verbatim; normalizing through model.Client would drop any
// field that struct does not know about.
//
// A client that already carries a slot keeps it. One whose email matches an existing
// account inherits that account's slot, which is what makes a whole-inbound save (the form
// posts every client) preserve addresses instead of re-deriving them from order. Anything
// else takes the lowest slot no existing account and no earlier client in the batch holds.
func assignSlotsToClientMaps(protocol model.Protocol, existing []model.Client, clients []any) {
	if !slotPoolProtocol(protocol) {
		return
	}
	used := make(map[int]bool, len(existing))
	byEmail := make(map[string]int, len(existing))
	for i := range existing {
		slot := slotOr(existing[i].Slot, i)
		used[slot] = true
		if e := accountKey(existing[i].Email); e != "" {
			byEmail[e] = slot
		}
	}
	nextFree := func() int {
		for slot := 0; ; slot++ {
			if !used[slot] {
				used[slot] = true
				return slot
			}
		}
	}

	for i := range clients {
		c, ok := clients[i].(map[string]any)
		if !ok {
			continue
		}
		if v, has := c["slot"]; has {
			if f, ok := v.(float64); ok && f >= 0 {
				used[int(f)] = true
				continue
			}
		}
		slot := -1
		if e, _ := c["email"].(string); accountKey(e) != "" {
			if s, found := byEmail[accountKey(e)]; found {
				slot, used[s] = s, true
			}
		}
		if slot < 0 {
			slot = nextFree()
		}
		c["slot"] = slot
	}
}

// accountKey normalizes an email for slot lookups the same way account identity is compared
// elsewhere (case- and whitespace-insensitive).
func accountKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// highestSlot returns the largest slot held, or -1 for none. Used by the pool-capacity
// guard, which has to ask "does this slot fit" rather than "how many accounts are there"
// once slots can be sparse.
func highestSlot(clients []model.Client) int {
	highest := -1
	for i := range clients {
		if s := slotOr(clients[i].Slot, i); s > highest {
			highest = s
		}
	}
	return highest
}

// wgcEffectiveK resolves a WireGuard (C) User Limit into an account block size. Unlike the
// shared effectiveUserLimit/normUserLimit (where an explicit 0 means the small no-limit
// block, noLimitDevices), WireGuard (C) treats 0 as "maximum" — a full 64-device block (a
// /26) — because its User Limit only SIZES the account's gateway block, it does not gate
// simultaneous devices. Absent (nil) or 1 stays a single /32; other values clamp to [1,64].
func wgcEffectiveK(p *int) int {
	if p == nil {
		return 1
	}
	k := *p
	if k == 0 {
		return maxUserLimit
	}
	if k < 1 {
		return 1
	}
	if k > maxUserLimit {
		return maxUserLimit
	}
	return k
}

// wgcDecodeUserLimit is wgcEffectiveK for the raw-JSON path (normalizeRanges), where an
// absent field is legacy (=> 1) and an explicit 0 means the maximum 64-device block.
func wgcDecodeUserLimit(raw map[string]json.RawMessage) int {
	if b, ok := raw["userLimit"]; ok {
		var k int
		if json.Unmarshal(b, &k) == nil {
			return wgcEffectiveK(&k)
		}
	}
	return 1
}

// accountsPerSubnet is how many K-sized account blocks fit in one /24. K==1 keeps
// the legacy .2-.254 window (253 accounts). For K>=2, account s occupies hosts
// [(s+1)*K, (s+2)*K-1]; the last host must stay <=254 (leaving .0 network, .1
// gateway, .255 broadcast free), giving floor(255/K)-1 blocks. This equals the
// old 256/K-2 for every power-of-two K, so pow2 sizing is byte-identical.
func accountsPerSubnet(k int) int {
	k = normUserLimit(k)
	if k == 1 {
		return 253
	}
	n := 255/k - 1
	if n < 0 {
		n = 0
	}
	return n
}

// vpnAccountsCapacity returns how many K-account blocks the given ordered /24
// prefixes ("A.B.C") can hold in total.
func vpnAccountsCapacity(subnets []string, k int) int {
	return len(subnets) * accountsPerSubnet(k)
}

// maxVpnAccounts returns an UPPER BOUND on the number of per-account tunnel IPs an
// inbound can ever hold after maximum auto-expansion (ok=false for protocols with no
// per-account IP: the relays mtproto/ssh and the xray protocols). It mirrors the sizing
// in normalizeRanges: PPP protocols (l2tp/pptp/sstp) can grow to own every free /24 in
// their /16; the block protocols (openvpn/openconnect/ikev2/wg-c) are hard-capped at a
// /18 (64 /24s). Because it counts the largest pool the inbound could obtain, it never
// under-reports, so the add-client guard built on it never falsely rejects a placeable
// client; it exists to catch the hard walls (the /18 block cap, and /16 exhaustion)
// where the index-based allocator would otherwise hand the account a nil IP silently.
func maxVpnAccounts(inbound *model.Inbound) (int, bool) {
	proto := string(inbound.Protocol)
	switch proto {
	case "l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wg-c", "awg", "gre":
	default:
		return 0, false
	}

	var raw map[string]json.RawMessage
	if len(inbound.Settings) > 0 {
		if json.Unmarshal([]byte(inbound.Settings), &raw) != nil {
			return 0, false
		}
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}

	// Free /24s available to this inbound: its own (excludeId) plus any that no other
	// inbound of the family owns.
	used := usedVpnSubnets(inbound.Id)
	base := protocolBase(proto)
	free := 0
	for n := 2; n <= 254; n++ {
		if !used[fmt.Sprintf("10.%d.%d", base, n)] {
			free++
		}
	}

	switch proto {
	case "l2tp", "pptp", "sstp":
		// PPP: no per-inbound cap, grows across the whole /16.
		return free * accountsPerSubnet(decodeUserLimit(raw)), true
	case "wg-c", "awg", "gre":
		// Gateway model: block sizing rounds the wg-c/awg/gre User Limit up to a power of
		// two; the single contiguous block is capped at 64 /24s (a /18).
		n24 := free
		if n24 > 64 {
			n24 = 64
		}
		return n24 * accountsPerSubnet(nextPow2(wgcDecodeUserLimit(raw))), true
	default:
		// openvpn/openconnect/ikev2: single aligned block capped at 64 /24s (a /18).
		n24 := free
		if n24 > 64 {
			n24 = 64
		}
		return n24 * accountsPerSubnet(decodeUserLimit(raw)), true
	}
}

// vpnAccountBlock maps account index i to its (/24 prefix, first-host octet) under
// user limit k>=2, walking the ordered /24 prefixes. ok=false past capacity.
func vpnAccountBlock(subnets []string, i, k int) (subnet string, hostBase int, ok bool) {
	k = normUserLimit(k)
	per := accountsPerSubnet(k)
	if per <= 0 {
		return "", 0, false
	}
	sIdx := i / per
	sub := i % per
	if sIdx >= len(subnets) {
		return "", 0, false
	}
	return subnets[sIdx], (sub + 1) * k, true
}

// vpnAccountDeviceIPs returns the K tunnel IPs of account i's block under user
// limit k>=2, device 0..K-1 in order (e.g. K=6 -> ".6",".7",...,".11"). nil past
// capacity. Blocks are consecutive [base, base+K) ranges with no CIDR alignment,
// so K need not be a power of two; routing matches the whole account with this
// explicit IP list and the OpenVPN block file leases a free IP from it.
func vpnAccountDeviceIPs(subnets []string, i, k int) []string {
	kk := normUserLimit(k)
	subnet, hostBase, ok := vpnAccountBlock(subnets, i, kk)
	if !ok {
		return nil
	}
	out := make([]string, 0, kk)
	for d := 0; d < kk; d++ {
		out = append(out, fmt.Sprintf("%s.%d", subnet, hostBase+d))
	}
	return out
}

// vpnAccountDeviceIP returns the tunnel IP of device d in [0,k) for account i
// under user limit k>=2. "" past capacity or for an out-of-range device index.
func vpnAccountDeviceIP(subnets []string, i, k, d int) string {
	kk := normUserLimit(k)
	if d < 0 || d >= kk {
		return ""
	}
	subnet, hostBase, ok := vpnAccountBlock(subnets, i, kk)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s.%d", subnet, hostBase+d)
}
