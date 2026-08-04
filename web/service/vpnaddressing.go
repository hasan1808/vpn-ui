package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// Read-only introspection of the VPN address plane.
//
// Everything here is already decided by the panel and stored, but until now none of it
// was READABLE over the API. An operator could set `ipRanges` and `userLimit` and never
// find out what they actually got: the pool is auto-assigned by NormalizeVpnRanges, the
// slot is allocated by AddInbound, and the tunnel address an account ends up on is
// computed from the two of them by code the caller cannot run. The answers existed only
// inside a generated daemon config or a rendered client config, and for the PPP family
// (l2tp, pptp, openconnect, sstp, ikev2) not even there.
//
// That gap is not cosmetic. The address is what an operator writes firewall rules
// against, what they hand to a customer for a site-to-site route, and the first thing
// they need when an account is reachable but not routing. Guessing it means
// reimplementing slotOr + effectiveUserLimit + vpnAccountDeviceIPs outside the panel and
// silently drifting from it the first time either changes.
//
// THE ADDRESSES ARE NOT RECOMPUTED HERE. They come from BuildVpnEmailToIPMap, the same
// mapper the Xray config generator uses to turn email-based routing rules into
// source-IP rules, so what this reports is by construction what the data plane routes.
// Every per-protocol special case (the ikev2 psk/eap-tls whole-block lease, the
// wg-c/awg/gre gateway CIDR, OpenVPN's two transports) is inherited rather than
// restated, which is the point: a second implementation would be a second thing to keep
// in step, and this file exists precisely because that kind of drift is invisible.

// VpnAccountAddressing is one account's place in an inbound's address pool.
type VpnAccountAddressing struct {
	Email string `json:"email"`
	// Slot is the account's index into the pool, which is what its address is derived
	// from. Stored on the account; falls back to its position in clients[] for rows
	// written before slots existed (see slotOr).
	Slot int `json:"slot"`
	// Addresses is what the data plane will route for this account ON THIS INBOUND.
	// One entry for a single-device account, K for a device block, one CIDR for the
	// gateway protocols, and two sets for an OpenVPN inbound serving both transports.
	Addresses []string `json:"addresses"`
}

// VpnAddressingReport is everything readable about one inbound's address plane.
type VpnAddressingReport struct {
	InboundId int            `json:"inboundId"`
	Protocol  model.Protocol `json:"protocol"`

	// Ranges is the pool as stored, in the allocator's own "A.B.C.s-A.B.C.e" spelling
	// (NOT CIDR). Subnets is the same thing as the /24 prefixes the allocator works in.
	Ranges  []string `json:"ranges"`
	Subnets []string `json:"subnets"`

	// UserLimit reports the posted value, what it actually resolves to, and why. This
	// is the field most worth reading back: the resolution is not the identity, and
	// three separate rules apply depending on presence and protocol.
	UserLimit VpnUserLimitReport `json:"userLimit"`

	// Accounts is how many accounts the CURRENT pool holds, MaxAccounts an upper bound
	// after the pool has auto-expanded as far as it is allowed to. Both are counts of
	// accounts, not addresses: an account occupies EffectiveK of them.
	Capacity    int `json:"capacity"`
	MaxAccounts int `json:"maxAccounts"`
	Used        int `json:"used"`

	Accounts []VpnAccountAddressing `json:"accounts"`
}

// VpnUserLimitReport spells out the User Limit resolution, which is the single most
// misread number in the settings JSON.
//
// Three rules, and which one applies depends on both presence and protocol:
//
//   - ABSENT is not 0. A missing key means a legacy single-device inbound and resolves
//     to 1; an explicit 0 means "no limit".
//   - "No limit" is NOT 64. For every pool protocol except the gateway ones it resolves
//     to noLimitDevices, a generous bounded block, because the account has to own a real
//     run of consecutive addresses for per-account routing to work at all.
//   - wg-c and awg read an explicit 0 as the MAXIMUM (a full 64-device block), because
//     there the number only sizes the account's gateway block and gates nothing.
//
// A caller who sets 0 expecting 64 and gets a different block is not doing anything
// wrong, they are reading the browser model's comment rather than the server's rule.
// Reporting Posted and Effective side by side is the cheapest way to end that.
type VpnUserLimitReport struct {
	// Posted is the stored value, or nil when the key is absent.
	Posted *int `json:"posted"`
	// Effective is the device-block size actually used for this protocol.
	Effective int `json:"effective"`
	// Rule names which of the three resolutions applied, for a caller that wants to
	// branch rather than parse prose: "absent-legacy", "no-limit", "explicit".
	Rule string `json:"rule"`
}

// VpnPoolBlock is one /24 of the VPN address space and who holds it.
type VpnPoolBlock struct {
	Subnet    string         `json:"subnet"` // "A.B.C", the /24 prefix
	Protocol  model.Protocol `json:"protocol"`
	InboundId int            `json:"inboundId"`
	Remark    string         `json:"remark"`
}

// InboundAddressing builds the address-plane report for one inbound. ok is false for a
// protocol with no address pool at all: the relays (mtproto, ssh) and every Xray-native
// protocol hand out no client address, so there is nothing to report rather than an
// empty pool to misread as one.
func InboundAddressing(inbound *model.Inbound) (*VpnAddressingReport, bool) {
	if inbound == nil || !isVpnProtocol(inbound.Protocol) {
		return nil, false
	}

	ranges := inboundRanges(inbound)
	report := &VpnAddressingReport{
		InboundId: inbound.Id,
		Protocol:  inbound.Protocol,
		Ranges:    ranges,
		Subnets:   subnetsOf(ranges),
		UserLimit: inboundUserLimitReport(inbound),
		Accounts:  []VpnAccountAddressing{},
	}
	report.Capacity = vpnAccountsCapacity(report.Subnets, report.UserLimit.Effective)
	if max, ok := maxVpnAccounts(inbound); ok {
		report.MaxAccounts = max
	}

	clients, err := (&InboundService{}).GetClients(inbound)
	if err != nil {
		// A pool with unreadable accounts is still a pool worth reporting. Returning
		// nothing here would make a single malformed client entry look like "this
		// inbound has no addressing", which is the opposite of the truth.
		return report, true
	}
	report.Used = len(clients)

	// The authoritative map, panel-wide and keyed by email. Filtering it to this
	// inbound's own subnets is what makes it per-inbound, and it is exact rather than
	// approximate: the allocator's central invariant is that no two inbounds share a
	// /24 (see usedVpnSubnets, which is what stops the assignment in the first place),
	// so an address inside this inbound's subnets can only have come from it.
	//
	// An account on SEVERAL inbounds is precisely why this filter has to exist: its
	// entry in the map carries every inbound's addresses merged together, and reporting
	// those here would tell an operator their l2tp account answers on a wg-c address.
	all := BuildVpnEmailToIPMap()
	mine := subnetSet(report.Subnets)
	// OpenVPN owns a second /24 per range: the TCP side mirrors the UDP block into
	// 10.3.x, and those addresses are as much this inbound's as the UDP ones.
	if inbound.Protocol == model.OPENVPN {
		for _, s := range report.Subnets {
			mine[mirrorOvpnSubnet(s)] = true
		}
	}

	for i, client := range clients {
		if client.Email == "" {
			continue
		}
		report.Accounts = append(report.Accounts, VpnAccountAddressing{
			Email:     client.Email,
			Slot:      slotOr(client.Slot, i),
			Addresses: addressesInSubnets(all[client.Email], mine),
		})
	}
	return report, true
}

// inboundUserLimitReport resolves the User Limit the way the inbound's own protocol
// does, and says which rule it used. See VpnUserLimitReport for why the three differ.
func inboundUserLimitReport(inbound *model.Inbound) VpnUserLimitReport {
	var raw struct {
		UserLimit *int `json:"userLimit"`
	}
	_ = json.Unmarshal([]byte(inbound.Settings), &raw)

	out := VpnUserLimitReport{Posted: raw.UserLimit}
	gateway := inbound.Protocol == model.WGC || inbound.Protocol == model.AWG
	switch {
	case raw.UserLimit == nil:
		out.Rule = "absent-legacy"
	case *raw.UserLimit == 0:
		out.Rule = "no-limit"
	default:
		out.Rule = "explicit"
	}
	if gateway {
		out.Effective = wgcEffectiveK(raw.UserLimit)
	} else {
		out.Effective = effectiveUserLimit(raw.UserLimit)
	}
	return out
}

// subnetSet indexes /24 prefixes for membership tests.
func subnetSet(subnets []string) map[string]bool {
	out := make(map[string]bool, len(subnets))
	for _, s := range subnets {
		out[s] = true
	}
	return out
}

// addressesInSubnets keeps the addresses that fall inside the given /24 prefixes.
//
// Entries may be a bare address or a CIDR (the gateway protocols and the ikev2
// whole-block modes report a block, not a host), so the prefix is taken off the address
// half before the /24 is read. Anything unparseable is dropped rather than guessed at:
// reporting an address the data plane does not actually route would be worse than
// reporting one fewer.
func addressesInSubnets(addresses []string, subnets map[string]bool) []string {
	out := []string{}
	for _, addr := range addresses {
		host := addr
		if slash := strings.IndexByte(host, '/'); slash >= 0 {
			host = host[:slash]
		}
		dot := strings.LastIndexByte(host, '.')
		if dot < 0 {
			continue
		}
		if subnets[host[:dot]] {
			out = append(out, addr)
		}
	}
	return out
}

// VpnPoolOccupancy lists every /24 of the VPN address space that an inbound currently
// holds, ordered by subnet.
//
// The pool is assigned by the panel and never surfaced, so an operator planning a range
// by hand has no way to see what is already taken. Posting one that overlaps is refused
// (for the protocols where ranges are editable) with an error that names the conflict
// but not the map, so the only way to find a free block was trial and error.
func VpnPoolOccupancy() []VpnPoolBlock {
	db := database.GetDB()
	if db == nil {
		return []VpnPoolBlock{}
	}
	var inbounds []*model.Inbound
	if err := db.Model(model.Inbound{}).Find(&inbounds).Error; err != nil {
		return []VpnPoolBlock{}
	}

	out := []VpnPoolBlock{}
	for _, inbound := range inbounds {
		if !isVpnProtocol(inbound.Protocol) {
			continue
		}
		subnets := subnetsOf(inboundRanges(inbound))
		if inbound.Protocol == model.OPENVPN {
			// The TCP mirror is held by this inbound too, and an operator who cannot
			// see it will eventually try to allocate over it.
			for _, s := range append([]string{}, subnets...) {
				subnets = append(subnets, mirrorOvpnSubnet(s))
			}
		}
		for _, subnet := range subnets {
			if subnet == "" {
				continue
			}
			out = append(out, VpnPoolBlock{
				Subnet:    subnet,
				Protocol:  inbound.Protocol,
				InboundId: inbound.Id,
				Remark:    inbound.Remark,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subnet != out[j].Subnet {
			return subnetLess(out[i].Subnet, out[j].Subnet)
		}
		return out[i].InboundId < out[j].InboundId
	})
	return out
}

// subnetLess orders "A.B.C" prefixes numerically. Sorting them as strings puts
// "10.10.x" before "10.2.x", which reads as corruption in a list an operator is
// scanning for a free block.
func subnetLess(a, b string) bool {
	var a1, a2, a3, b1, b2, b3 int
	if _, err := fmt.Sscanf(a, "%d.%d.%d", &a1, &a2, &a3); err != nil {
		return a < b
	}
	if _, err := fmt.Sscanf(b, "%d.%d.%d", &b1, &b2, &b3); err != nil {
		return a < b
	}
	if a1 != b1 {
		return a1 < b1
	}
	if a2 != b2 {
		return a2 < b2
	}
	return a3 < b3
}
