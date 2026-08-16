package service

import (
	"encoding/json"
	"fmt"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
)

// Shared-daemon config conflicts.
//
// L2TP, PPTP and IKEv2 each run ONE daemon for the whole panel, so some settings
// are physically per-protocol rather than per-inbound:
//
//   - L2TP/PPTP link options (DNS, MTU) are one options file for the shared LNS.
//   - The L2TP/IPsec pre-shared key is one global PSK. This one is a protocol
//     constraint, not an implementation shortcut: IKEv1 Main Mode selects the PSK
//     by source IP before the peer's identity is known, so a dynamic road warrior
//     cannot be matched to a per-inbound secret.
//   - IKEv2 pushes one DNS pair from the shared charon.
//
// The generators resolve these by taking the first enabled inbound's value and
// ignoring the rest. That silently lied: a second inbound's PSK would be accepted,
// displayed as saved, and never used, so its clients shipped a profile that could
// not authenticate. Rejecting the save instead surfaces the constraint at the point
// of the mistake, which is the only place it can be acted on.
//
// This is enforced on save rather than at generation time because by then the value
// is already stored and the operator has already been told it worked.

// l2tpSharedSettings is the subset of an l2tp inbound's settings that the shared
// daemon can only honour one of.
type l2tpSharedSettings struct {
	IpsecEnable bool   `json:"ipsecEnable"`
	IpsecPsk    string `json:"ipsecPsk"`
	Dns1        string `json:"dns1"`
	Dns2        string `json:"dns2"`
	Mtu         int    `json:"mtu"`
}

// ikev2SharedSettings is the IKEv2 equivalent.
type ikev2SharedSettings struct {
	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
}

// sharedConflict names a setting whose value is dictated panel-wide.
type sharedConflict struct {
	Field string
	Mine  string
	Other string
	// OtherRemark identifies the inbound that already owns the value, so the
	// operator can find it. Deliberately included even across admins: the value is
	// shared whether or not they can see the inbound, and an unexplained rejection
	// would be worse than naming it.
	OtherRemark string
	OtherId     int
}

func (c sharedConflict) Error() string {
	return fmt.Sprintf(
		"%s is shared by every %s inbound on this server (one daemon serves them all), "+
			"and inbound #%d (%q) already set it to %q. Use that value, or change it there.",
		c.Field, "L2TP", c.OtherId, c.OtherRemark, c.Other)
}

// checkL2tpSharedConflicts reports a setting that the incoming l2tp inbound would
// lose to another enabled l2tp inbound. excludeId skips the row being edited.
func checkL2tpSharedConflicts(inbound *model.Inbound, excludeId int) error {
	if inbound == nil || inbound.Protocol != model.L2TP || !inbound.Enable {
		return nil
	}
	var mine l2tpSharedSettings
	if err := json.Unmarshal([]byte(inbound.Settings), &mine); err != nil {
		return nil // malformed settings fail elsewhere with a better message
	}

	others, err := enabledInboundsOfProtocol(model.L2TP, excludeId)
	if err != nil {
		return nil // never block a save because the conflict check itself failed
	}
	for _, other := range others {
		var theirs l2tpSharedSettings
		if json.Unmarshal([]byte(other.Settings), &theirs) != nil {
			continue
		}
		// The PSK is the damaging one: a mismatch means clients get a profile that
		// cannot authenticate, with nothing in the UI to explain why.
		if mine.IpsecEnable && theirs.IpsecEnable &&
			mine.IpsecPsk != "" && theirs.IpsecPsk != "" && mine.IpsecPsk != theirs.IpsecPsk {
			return sharedConflict{
				Field: "The IPsec pre-shared key", Mine: mine.IpsecPsk, Other: theirs.IpsecPsk,
				OtherRemark: other.Remark, OtherId: other.Id,
			}
		}
		if mine.Dns1 != "" && theirs.Dns1 != "" && mine.Dns1 != theirs.Dns1 {
			return sharedConflict{
				Field: "The primary DNS server", Mine: mine.Dns1, Other: theirs.Dns1,
				OtherRemark: other.Remark, OtherId: other.Id,
			}
		}
		if mine.Mtu != 0 && theirs.Mtu != 0 && mine.Mtu != theirs.Mtu {
			return sharedConflict{
				Field: "The MTU", Mine: fmt.Sprint(mine.Mtu), Other: fmt.Sprint(theirs.Mtu),
				OtherRemark: other.Remark, OtherId: other.Id,
			}
		}
	}
	return nil
}

// checkIkev2SharedConflicts is the IKEv2 twin: the shared charon pushes one DNS pair.
func checkIkev2SharedConflicts(inbound *model.Inbound, excludeId int) error {
	if inbound == nil || inbound.Protocol != model.IKEV2 || !inbound.Enable {
		return nil
	}
	var mine ikev2SharedSettings
	if err := json.Unmarshal([]byte(inbound.Settings), &mine); err != nil {
		return nil
	}
	if mine.Dns1 == "" {
		return nil
	}
	others, err := enabledInboundsOfProtocol(model.IKEV2, excludeId)
	if err != nil {
		return nil
	}
	for _, other := range others {
		var theirs ikev2SharedSettings
		if json.Unmarshal([]byte(other.Settings), &theirs) != nil {
			continue
		}
		if theirs.Dns1 != "" && theirs.Dns1 != mine.Dns1 {
			return fmt.Errorf(
				"the DNS server is shared by every IKEv2 inbound on this server (one charon serves them all), "+
					"and inbound #%d (%q) already set it to %q. Use that value, or change it there",
				other.Id, other.Remark, theirs.Dns1)
		}
	}
	return nil
}

// CheckSharedDaemonConflicts is the entry point called before an inbound is saved.
func CheckSharedDaemonConflicts(inbound *model.Inbound, excludeId int) error {
	if err := checkL2tpSharedConflicts(inbound, excludeId); err != nil {
		return err
	}
	return checkIkev2SharedConflicts(inbound, excludeId)
}

func enabledInboundsOfProtocol(protocol model.Protocol, excludeId int) ([]*model.Inbound, error) {
	db := database.GetDB()
	if db == nil {
		return nil, fmt.Errorf("no database")
	}
	var out []*model.Inbound
	q := db.Model(model.Inbound{}).Where("protocol = ? AND enable = ?", protocol, true)
	if excludeId > 0 {
		q = q.Where("id != ?", excludeId)
	}
	err := q.Find(&out).Error
	return out, err
}

// logSharedWinner records which inbound's value the shared daemon actually adopted.
// The save-time check stops NEW conflicts, but a panel upgraded with conflicting
// rows already on disk still needs the winner named somewhere.
func logSharedWinner(protocol string, field string, winner *model.Inbound, total int) {
	if total > 1 && winner != nil {
		logger.Infof("%s: %s comes from inbound #%d (%q) and applies to all %d %s inbounds",
			protocol, field, winner.Id, winner.Remark, total, protocol)
	}
}
