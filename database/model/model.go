// Package model defines the database models and data structures used by the vpn-ui panel.
package model

import (
	"fmt"

	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Protocol represents the protocol type for Xray inbounds.
type Protocol string

// Protocol constants for different Xray inbound protocols
const (
	VMESS       Protocol = "vmess"
	VLESS       Protocol = "vless"
	Tunnel      Protocol = "tunnel"
	HTTP        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Socks       Protocol = "socks"
	Mixed       Protocol = "mixed"
	WireGuard   Protocol = "wireguard"
	L2TP        Protocol = "l2tp"
	PPTP        Protocol = "pptp"
	OPENVPN     Protocol = "openvpn"
	OPENCONNECT Protocol = "openconnect"
	SSTP        Protocol = "sstp"
	IKEV2       Protocol = "ikev2"
	WGC         Protocol = "wg-c"
	AWG         Protocol = "awg"
	GRE         Protocol = "gre"
	MTPROTO     Protocol = "mtproto"
	SSH         Protocol = "ssh"
	// Native Xray protocols like vmess/vless/trojan: the core terminates them
	// itself, so they take no dokodemo/socks derivation, no core install and no
	// address pool. See isVpnProtocol / hasDerivedXrayInbound in
	// web/service/inbound.go for the three lists they must stay OUT of.
	ANYTLS Protocol = "anytls"
	TUIC   Protocol = "tuic"
	NAIVE  Protocol = "naive"
	// UI stores Hysteria v1 and v2 both as "hysteria" and uses
	// settings.version to discriminate. Imports from outside the panel
	// can carry the literal "hysteria2" string, so IsHysteria below
	// accepts both.
	Hysteria  Protocol = "hysteria"
	Hysteria2 Protocol = "hysteria2"
)

// IsHysteria returns true for both "hysteria" and "hysteria2".
// Use instead of a bare ==model.Hysteria check: a v2 inbound stored
// with the literal v2 string would otherwise fall through (#4081).
func IsHysteria(p Protocol) bool {
	return p == Hysteria || p == Hysteria2
}

// IsInboundProtocol reports whether p is a protocol the Inbounds page can be
// scoped to via /panel/inbounds/:proto. It accepts every value the frontend's
// Protocols list in web/assets/js/model/inbound.js offers — including the
// legacy "tun" slug and the literal "hysteria2" string, which the UI normalizes
// to the hysteria tab — so a direct link to any tab resolves rather than
// bouncing back to the unfiltered page.
func IsInboundProtocol(p string) bool {
	if p == "tun" {
		return true
	}
	for _, c := range []Protocol{
		VMESS, VLESS, Tunnel, HTTP, Trojan, Shadowsocks, Socks, Mixed, WireGuard,
		L2TP, PPTP, OPENVPN, OPENCONNECT, SSTP, IKEV2, WGC, AWG, GRE, MTPROTO,
		SSH, ANYTLS, TUIC, NAIVE, Hysteria, Hysteria2,
	} {
		if string(c) == p {
			return true
		}
	}
	return false
}

// ClientExternalProxy is one alternate endpoint rendered into an account's links
// instead of this server's own address (a relay/CDN in front of the proxy). It
// affects generated links only: no daemon ever reads it.
type ClientExternalProxy struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

// User represents an admin account in the vpn-ui panel.
//
// Password and TwoFactorToken are secrets and carry json:"-" so they can never be
// serialized out to the browser: the panel's session cookie is signed but NOT
// encrypted, so anything that reaches it is readable client-side. The session
// stores only Id for the same reason (see web/session).
type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username" gorm:"uniqueIndex"`
	Password string `json:"-"`

	// Nickname is a human label for the Admins list; it carries no privilege.
	Nickname string `json:"nickname" form:"nickname"`

	// IsSuperAdmin bypasses Permissions entirely and is the only role that may
	// manage admins. Exactly one is seeded from the pre-existing first user.
	IsSuperAdmin bool `json:"isSuperAdmin" gorm:"default:0"`

	// Permissions is the capability bitmask; ignored for a super admin, and
	// ignored for a reseller (whose mask is derived from the role, see Can).
	Permissions Permission `json:"-" gorm:"default:0"`

	// IsReseller marks an account that sells VPN accounts out of a traffic
	// balance. It is a ROLE and not a permission bit because it changes which
	// objects exist for the account rather than what it may do to them: a
	// reseller sees only the clients it created, even on an inbound it shares
	// with an admin. A mask cannot express that.
	//
	// Never true at the same time as IsSuperAdmin; ResellerService enforces it.
	// The quota levers live in ResellerProfile, one row per reseller, so this
	// table (read on EVERY request by session.loadLoginUser) stays narrow.
	IsReseller bool `json:"isReseller" gorm:"default:0"`

	// Enable gates login without deleting the account (and its owned inbounds).
	Enable bool `json:"enable" form:"enable" gorm:"default:1"`

	// Per-admin TOTP. Replaces the panel-global twoFactorEnable/twoFactorToken
	// settings pair, which leaked the shared secret to every logged-in user
	// through GetAllSetting.
	TwoFactorEnable bool   `json:"twoFactorEnable" gorm:"default:0"`
	TwoFactorToken  string `json:"-"`
}

// InboundAccess grants one admin access to one inbound.
//
// Access is ASSIGNED, not inferred from who created the row. A super admin ticks
// which inbounds each admin can see, and anything unticked does not exist as far as
// that admin is concerned. Inbound.UserId still records the creator (for the Admins
// list and Reassign), but it is bookkeeping: it does not decide access.
//
// Super admins are never listed here; they see every inbound by role.
type InboundAccess struct {
	Id        int `json:"id" gorm:"primaryKey;autoIncrement"`
	UserId    int `json:"userId" gorm:"index:idx_access_user_inbound,unique,priority:1;index"`
	InboundId int `json:"inboundId" gorm:"index:idx_access_user_inbound,unique,priority:2;index"`
}

// ResellerProfile holds one reseller's balance and the levers an admin sets on
// them. Split from User because these fields are meaningless for every admin
// row, and because the balance is written under transaction on every account
// create/edit/delete: keeping those writes off the row that every request reads
// is worth one join on the rare page that needs it.
type ResellerProfile struct {
	Id     int `json:"id" gorm:"primaryKey;autoIncrement"`
	UserId int `json:"userId" gorm:"uniqueIndex"`

	// AllowanceBytes is the cumulative traffic an admin has granted. SpentBytes
	// is what is currently committed to live accounts plus what past accounts
	// burned before being deleted. Available = Allowance - Spent.
	//
	// BYTES, never GB. Client.TotalGB is a byte count despite its name (see
	// web/assets/js/model/inbound.js _totalGB, which divides by ONE_GB purely
	// for display), and a unit mismatch on this pair is free traffic.
	AllowanceBytes int64 `json:"allowanceBytes" gorm:"default:0"`
	SpentBytes     int64 `json:"spentBytes" gorm:"default:0"`
	// Unlimited skips the balance CHECK but not the accrual: SpentBytes keeps
	// climbing, so an admin who later sets a limit correctly accounts for what
	// this reseller already sold. Stored explicitly rather than overloading
	// AllowanceBytes==0, so that an admin who leaves the field blank while
	// creating a reseller does not silently mint an unlimited one.
	Unlimited bool `json:"unlimited" gorm:"default:0"`

	// DaysPerGB > 0 FORCES an account's duration: expiry is GB * DaysPerGB, and
	// the reseller gets no expiry field at all. 0 leaves the choice to them.
	DaysPerGB int `json:"daysPerGb" gorm:"default:0"`
	// MinCreateGB is the smallest account they may create, MinAddGB the smallest
	// top-up in one edit. Whole GB, as an operator sets them; 0 means no floor.
	MinCreateGB int `json:"minCreateGb" gorm:"default:0"`
	MinAddGB    int `json:"minAddGb" gorm:"default:0"`

	// AllowExternalProxy lets the configs and links this reseller generates carry
	// the inbound's external-proxy endpoints. Off strips them.
	AllowExternalProxy bool `json:"allowExternalProxy" gorm:"default:0"`

	// AllowOverview lets this reseller open the panel overview: the reseller's
	// counterpart to PermAccessOverview, which their derived mask can never carry.
	// Off (the default) hides the nav entry entirely rather than greying it, and the
	// route itself refuses them: the overview is a HOST dashboard (kernel, CPU, disk,
	// public IP) and none of it is a reseller's to see unless an operator says so.
	AllowOverview bool `json:"allowOverview" gorm:"default:0"`

	// AllowOverviewManage is the reseller's counterpart to PermOverviewManage: off,
	// the overview they were let into is a read-only showcase. It has no effect
	// unless AllowOverview is on, since there is no page to scope otherwise.
	//
	// What it can actually reveal is narrow, and narrower than the admin bit. Every
	// control on that page requires a permission the reseller role does not carry
	// (resellerPerms holds no Xray, core or panel-settings bit) and the escalation
	// class is super-admin-only, so today this un-hides nothing a reseller could
	// then use. It exists so the two roles are configured the same way, and so the
	// day an action becomes reseller-reachable it is already gated.
	AllowOverviewManage bool `json:"allowOverviewManage" gorm:"default:0"`

	// CreatedBy is the admin who owns this reseller. A non-super admin holding
	// PermManageResellers sees and edits only their own: without this, one such
	// admin could edit another's reseller balance or reassign their inbounds.
	CreatedBy int `json:"createdBy" gorm:"index"`
}

// ResellerClient records that a reseller owns an account, and what that account
// currently costs them. Ownership and charge are one row because they are 1:1
// on the account, so two tables would only be two things to keep in sync.
//
// ABSENCE of a row means the house owns the account. Admins and super admins
// have no balance, so there is nothing to charge and their paths need no ledger
// awareness at all.
type ResellerClient struct {
	Id int `json:"id" gorm:"primaryKey;autoIncrement"`
	// Email is the panel-wide account identity. xray.ClientTraffic.Email carries
	// gorm:"unique", and AdminService.CanAccessClientEmail already keys on it, so
	// this matches the seam that exists rather than inventing a second notion of
	// "which client".
	Email string `json:"email" gorm:"uniqueIndex"`
	// InboundId is the HOME inbound: the one this account was first sold on. It is
	// DISPLAY ONLY, and nothing may decide anything by it.
	//
	// One account is served on N inbounds (see AccountInbound), and this column
	// holds exactly one of them, so every question of the form "which inbound is
	// this account on" has to be answered by resolving the memberships instead
	// (service.servingInboundIds). Reading it as THE inbound is what made deleting
	// a reseller remove one membership of three and leave the rest live and
	// unbilled, and what made deleting the inbound an account really sits on refund
	// nothing because the row named a different one.
	//
	// It is repointed when the inbound it names is deleted while the account lives
	// on elsewhere, so it keeps naming something real.
	InboundId int `json:"inboundId" gorm:"index"`
	UserId    int `json:"userId" gorm:"index"`

	// ChargedBytes is what this account currently holds against its reseller's
	// balance: raised on create and top-up, lowered on deduct and delete.
	ChargedBytes int64 `json:"chargedBytes" gorm:"default:0"`
	// AllTimeBase is ClientTraffic.AllTime at the moment of the charge, so
	// consumption is measured from the charge and not from the account's whole
	// life. AllTime is used rather than Up+Down because it is monotonic across a
	// traffic reset (see web/service/traffic_accounting_test.go), which is what
	// stops a reset from turning consumed bytes back into a refundable balance.
	AllTimeBase int64 `json:"allTimeBase" gorm:"default:0"`
}

// Inbound represents an Xray inbound configuration with traffic statistics and settings.
type Inbound struct {
	Id                   int                  `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`                                                    // Unique identifier
	UserId               int                  `json:"-"`                                                                                               // Associated user ID
	Up                   int64                `json:"up" form:"up"`                                                                                    // Upload traffic in bytes
	Down                 int64                `json:"down" form:"down"`                                                                                // Download traffic in bytes
	Total                int64                `json:"total" form:"total"`                                                                              // Total traffic limit in bytes
	AllTime              int64                `json:"allTime" form:"allTime" gorm:"default:0"`                                                         // All-time traffic usage
	Remark               string               `json:"remark" form:"remark"`                                                                            // Human-readable remark
	Enable               bool                 `json:"enable" form:"enable" gorm:"index:idx_enable_traffic_reset,priority:1"`                           // Whether the inbound is enabled
	ExpiryTime           int64                `json:"expiryTime" form:"expiryTime"`                                                                    // Expiration timestamp
	TrafficReset         string               `json:"trafficReset" form:"trafficReset" gorm:"default:never;index:idx_enable_traffic_reset,priority:2"` // Traffic reset schedule
	LastTrafficResetTime int64                `json:"lastTrafficResetTime" form:"lastTrafficResetTime" gorm:"default:0"`                               // Last traffic reset timestamp
	ClientStats          []xray.ClientTraffic `gorm:"foreignKey:InboundId;references:Id" json:"clientStats" form:"clientStats"`                        // Client traffic statistics

	// SortOrder is where this inbound sits in the panel's list, and nothing else. It
	// never reaches Xray, no protocol reads it, and the panel behaves identically
	// whatever it holds: the whole feature is the operator arranging their own table.
	//
	// 0 means "never positioned", and sorts LAST rather than first (see
	// inboundDisplayOrder), which is what makes the column safe to add to a live
	// panel: every existing row stays at 0 and keeps the id order it has always had,
	// and a newly added inbound appends to the end exactly as it used to.
	//
	// Deliberately has no form tag. UpdateInbound copies the editable fields one by
	// one onto the row it loaded, so a field that is not in that list survives an
	// edit; a form tag here would instead let the inbound edit form bind an absent
	// value and silently reset the position to 0 on every save.
	SortOrder int `json:"sortOrder" gorm:"default:0"`

	// Traffic Multiplier: weight a client's usage once they pass a threshold. Below
	// TrafficMultiplierAfter traffic counts 1:1; past it each byte counts
	// TrafficMultiplier times against the client's quota. Applies to every protocol.
	// The multiplier defaults to 1 (not 0) so existing rows keep counting 1:1.
	TrafficMultiplierEnable bool    `json:"trafficMultiplierEnable" form:"trafficMultiplierEnable" gorm:"default:0"` // Whether the multiplier applies
	TrafficMultiplierAfter  int64   `json:"trafficMultiplierAfter" form:"trafficMultiplierAfter" gorm:"default:0"`   // Threshold in bytes, counted on up+down
	TrafficMultiplier       float64 `json:"trafficMultiplier" form:"trafficMultiplier" gorm:"default:1"`             // Weight applied past the threshold

	// Speed Limit: throttle each account on this inbound to a fixed rate. Configured
	// per inbound but ENFORCED PER EMAIL: every account gets its OWN bucket at this
	// rate, so this is not a shared pool for the inbound. Applies to every protocol
	// (native Xray and the VPN ones alike) because the enforcement point is Xray's
	// dispatcher, which sits downstream of every inbound.
	//
	// These are columns rather than keys in Settings on purpose. Settings is passed
	// VERBATIM to Xray for native protocols (see GenXrayInboundConfig below), and only
	// settings["clients"] is rewritten on the way out, so a top-level key here would
	// leak into Xray's own config. Columns also give every protocol one shared form
	// instead of a copy per protocol.
	//
	// Rates are KB/s (1 KB = 1024 B) to match the UI. They are converted to bytes/s in
	// exactly one place, where the limiter sidecar is written, so the 1024-vs-1000
	// question lives there and nowhere else. 0 in a direction means that direction is
	// unlimited.
	SpeedLimitEnable   bool  `json:"speedLimitEnable" form:"speedLimitEnable" gorm:"default:0"`     // Whether the limiter applies
	SpeedLimitSeparate bool  `json:"speedLimitSeparate" form:"speedLimitSeparate" gorm:"default:0"` // false = SpeedLimitDown caps BOTH directions
	SpeedLimitDown     int   `json:"speedLimitDown" form:"speedLimitDown" gorm:"default:0"`         // KB/s, 0 = unlimited
	SpeedLimitUp       int   `json:"speedLimitUp" form:"speedLimitUp" gorm:"default:0"`             // KB/s, 0 = unlimited; unused when SpeedLimitSeparate is false
	SpeedLimitAfter    int64 `json:"speedLimitAfter" form:"speedLimitAfter" gorm:"default:0"`       // Threshold in bytes on up+down; 0 = apply immediately

	// IP Limit: the DEFAULT cap on how many distinct client source addresses ONE account
	// on this inbound may hold at once. 0 = no limit.
	//
	// Client.LimitIP (below, and long predating this) overrides it per client, so this is
	// the operator's baseline for the whole inbound rather than a second, competing cap:
	// see resolveIPLimit for the resolution, including why a client-level 0 inherits this
	// default instead of forcing "unlimited".
	//
	// It counts ADDRESSES, not devices: devices behind one NAT share one source address
	// and count as one. That undercount is irreducible rather than a defect (see
	// ip-limiter-plan.md), which is exactly why the name says IP and must keep saying IP.
	IPLimit int `json:"ipLimit" form:"ipLimit" gorm:"default:0"`

	// IP Limit Strategy: what happens when an account already at its IP Limit is seen
	// from a NEW source address. "reject" (the default) refuses the newcomer; "accept"
	// admits it and disconnects that account's oldest address.
	//
	// The words are the VPN User Limit's ("accept"/"reject", see normUserLimitStrategy)
	// on purpose: this is the same question asked at a different enforcement point, and
	// a synonym here would make the three points look like three features.
	//
	// Unlike the cap above, this has NO per-client override, and the asymmetry is
	// deliberate: how many addresses an account may hold is that account's entitlement, so
	// a client may carry its own, but what to do AT the cap is the operator's policy for
	// the whole inbound and not something an individual account should have a say in.
	//
	// A column rather than a key in Settings for the same reason as the SpeedLimit* block
	// above: Settings is passed VERBATIM to Xray for native protocols and only
	// settings["clients"] is rewritten on the way out, so a top-level key there would leak
	// into Xray's own config. AutoMigrate adds the column, and the gorm default is what
	// makes every pre-existing row read back "reject" instead of "" (readers normalize the
	// empty string to reject anyway, so the default is belt-and-braces, not the contract).
	IPLimitStrategy string `json:"ipLimitStrategy" form:"ipLimitStrategy" gorm:"default:reject"`

	// Xray configuration fields
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`
}

// OutboundTraffics tracks traffic statistics for Xray outbound connections.
type OutboundTraffics struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Tag   string `json:"tag" form:"tag" gorm:"unique"`
	Up    int64  `json:"up" form:"up" gorm:"default:0"`
	Down  int64  `json:"down" form:"down" gorm:"default:0"`
	Total int64  `json:"total" form:"total" gorm:"default:0"`
}

// InboundClientIps stores IP addresses associated with inbound clients for access control.
type InboundClientIps struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	ClientEmail string `json:"clientEmail" form:"clientEmail" gorm:"unique"`
	Ips         string `json:"ips" form:"ips"`
}

// HistoryOfSeeders tracks which database seeders have been executed to prevent re-running.
type HistoryOfSeeders struct {
	Id         int    `json:"id" gorm:"primaryKey;autoIncrement"`
	SeederName string `json:"seederName"`
}

// GenXrayInboundConfig generates an Xray inbound configuration from the Inbound model.
func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	// Default to 0.0.0.0 (all interfaces) when listen is empty
	// This ensures proper dual-stack IPv4/IPv6 binding in systems where bindv6only=0
	if listen == "" {
		listen = "0.0.0.0"
	}
	listen = fmt.Sprintf("\"%v\"", listen)
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       string(i.Protocol),
		Settings:       json_util.RawMessage(i.Settings),
		StreamSettings: json_util.RawMessage(i.StreamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
	}
}

// Setting stores key-value configuration settings for the vpn-ui panel.
type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}

type CustomGeoResource struct {
	Id            int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Type          string `json:"type" gorm:"not null;uniqueIndex:idx_custom_geo_type_alias;column:geo_type"`
	Alias         string `json:"alias" gorm:"not null;uniqueIndex:idx_custom_geo_type_alias"`
	Url           string `json:"url" gorm:"not null"`
	LocalPath     string `json:"localPath" gorm:"column:local_path"`
	LastUpdatedAt int64  `json:"lastUpdatedAt" gorm:"default:0;column:last_updated_at"`
	LastModified  string `json:"lastModified" gorm:"column:last_modified"`
	CreatedAt     int64  `json:"createdAt" gorm:"autoCreateTime;column:created_at"`
	UpdatedAt     int64  `json:"updatedAt" gorm:"autoUpdateTime;column:updated_at"`
}

// Client represents a client configuration for Xray inbounds with traffic limits and settings.
type Client struct {
	ID         string `json:"id,omitempty"`                 // Unique client identifier
	Security   string `json:"security"`                     // Security method (e.g., "auto", "aes-128-gcm")
	Password   string `json:"password,omitempty"`           // Client password
	Flow       string `json:"flow,omitempty"`               // Flow control (XTLS)
	Auth       string `json:"auth,omitempty"`               // Auth password (Hysteria)
	Email      string `json:"email"`                        // Client email identifier
	LimitIP    int    `json:"limitIp"`                      // IP limit for this client
	TotalGB    int64  `json:"totalGB" form:"totalGB"`       // Total traffic limit in GB
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"` // Expiration timestamp
	Enable     bool   `json:"enable" form:"enable"`         // Whether the client is enabled
	TgID       int64  `json:"tgId" form:"tgId"`             // Telegram user ID for notifications
	SubID      string `json:"subId" form:"subId"`           // Subscription identifier
	Comment    string `json:"comment" form:"comment"`       // Client comment
	Reset      int    `json:"reset" form:"reset"`           // Reset period in days

	// Shadowsocks per-client cipher. Multi-user shadowsocks lets each account carry
	// its own method, and the inbound-level one is only the default.
	//
	// Here for the same reason as Username, Slot, Secret, Peers and the MTProto block
	// below: AddInbound re-marshals every posted client through THIS struct, so a
	// field missing here is silently dropped no matter what was sent. The symptom was
	// narrow enough to hide: creating a multi-user shadowsocks inbound through the API
	// collapsed every client onto the inbound's cipher, while /addClient and
	// /updateClient (which splice the raw map) kept it, so the same account worked or
	// did not depending on which call created it. omitempty so no other protocol's
	// client JSON grows a byte.
	Method string `json:"method,omitempty"`

	// naive's HTTP Basic username. Empty means "use Email", which is what every naive
	// account created before this field existed relies on: nothing backfills them, so
	// the fallback is the compatibility guarantee, not a convenience.
	//
	// It is deliberately NOT the accounting identity. Email still keys client_traffics,
	// quota, expiry, the speed limit and the IP limit, and the core still hands Email to
	// the dispatcher; only the credential moved. Same trap as the MTProto block below:
	// every client posted to the panel is normalized through THIS struct, so without the
	// field here the UI's username would be silently dropped on the add path and the
	// account would quietly keep authenticating as its email. omitempty so no other
	// protocol's client JSON grows a byte.
	Username string `json:"username,omitempty"`

	// Slot is the account's index into its inbound's address pool: which tunnel
	// address(es) the data plane gives it. It is stored rather than derived from the
	// account's position in clients[], because a position moves. Deleting an account
	// compacted the list and renumbered every account after it, which silently moved
	// live sessions onto other accounts' addresses and, on WireGuard, broke the
	// already-installed client config outright (its Address is written into the file,
	// and the server routes the peer to whatever the panel computes now).
	//
	// A pointer so an absent value is distinguishable from slot 0: rows written before
	// slots existed have none, and every read falls back to the list index for them
	// (see slotOr) until MigrationAccountSlots stamps them. omitempty keeps the client
	// JSON of the protocols that have no address pool byte-identical.
	Slot *int `json:"slot,omitempty" form:"slot"`

	// MTProto Proxy per-account settings. Every client posted to the panel is
	// normalized through THIS struct, so a field missing here is silently dropped no
	// matter what the UI sent: which for mtproto means an account with no secret and
	// no modes, filtered out of the generated config, leaving the daemon refusing to
	// start with "No users configured". All are omitempty so no other protocol's
	// client JSON grows a single byte.
	Secret        string                `json:"secret,omitempty"`        // 32-hex credential (identity is Email)
	ModeClassic   bool                  `json:"modeClassic,omitempty"`   // accept this account's bare secret
	ModeSecure    bool                  `json:"modeSecure,omitempty"`    // accept its "dd" secret
	ModeTls       bool                  `json:"modeTls,omitempty"`       // accept its "ee" (FakeTLS) secret
	TlsDomain     string                `json:"tlsDomain,omitempty"`     // SNI its FakeTLS link fronts
	AdtagEnable   bool                  `json:"adtagEnable,omitempty"`   // credit sponsored channels to Adtag
	Adtag         string                `json:"adtag,omitempty"`         // 32 hex from @MTProxybot
	UserLimit     *int                  `json:"userLimit,omitempty"`     // max devices (distinct IPs); nil=absent, 0=no limit
	ExternalProxy []ClientExternalProxy `json:"externalProxy,omitempty"` // alternate link endpoints (links only)

	// GRE per-account peer slots, one entry per peer the account may connect from, sized to
	// the inbound's User Limit. Here for the same reason as the MTProto block above: creating
	// an inbound round-trips every client through THIS struct, so a pinned peer address sent
	// by the UI was silently dropped and the account came up as a dynamic peer instead --
	// wrong device, wrong reverse path, and no error anywhere. Editing an existing inbound
	// never hit it, because that path mutates the settings map in place and keeps keys it does
	// not know. omitempty so no other protocol's client JSON grows a byte.
	//
	// An EMPTY element is meaningful and must survive: it is a deliberately unpinned peer
	// slot, and the array's LENGTH is the slot count.
	Peers []ClientGrePeer `json:"peers,omitempty"`

	// WireGuard (C) / AmneziaWG key material. Same trap as the MTProto and GRE blocks
	// above, and the one that actually bit: creating an inbound round-trips every client
	// through THIS struct, so per-device keypairs posted to /panel/api/inbounds/add were
	// silently dropped. ReconcileKeys then saw an account with no devices, rebuilt device
	// 0 from the legacy PrivKey mirror and MINTED FRESH KEYS for devices 2..K, so every
	// config already handed out for those devices stopped authenticating with no error
	// anywhere. Editing an existing inbound never hit it, because that path mutates the
	// settings map in place and keeps keys it does not know about.
	//
	// The legacy single-keypair trio is here for the same reason: it is what deviceList()
	// reads for accounts written before per-device keys existed, and ReconcileKeys keeps
	// it mirroring device 0. All omitempty so no other protocol's client JSON grows a byte.
	PrivKey string         `json:"privKey,omitempty"`
	PubKey  string         `json:"pubKey,omitempty"`
	Psk     string         `json:"psk,omitempty"`
	Devices []ClientDevice `json:"devices,omitempty"`

	CreatedAt int64 `json:"created_at,omitempty"` // Creation timestamp
	UpdatedAt int64 `json:"updated_at,omitempty"` // Last update timestamp
}

// ClientDevice is one wg-c/awg device slot: its own keypair (and optional preshared
// key) and, from its index, its own /32 out of the account's block. The JSON tags MUST
// match the service-side wgcDevice/awgDevice, or normalizing a client through Client
// silently rewrites the key material the data plane loads into the interface.
//
// No omitempty inside the entry: the array's own LENGTH is the device-slot count, and a
// slot whose keys have not been minted yet is a real, meaningful element.
type ClientDevice struct {
	PrivKey string `json:"privKey"`
	PubKey  string `json:"pubKey"`
	Psk     string `json:"psk"`
}

// ClientGrePeer is one GRE peer slot. The JSON tags MUST match the service-side grePeer, or
// normalizing a client through Client silently rewrites what the data plane reads.
type ClientGrePeer struct {
	PeerIp string `json:"peerIp,omitempty"`
	Remark string `json:"remark,omitempty"`
}

// Account is one sellable identity, usable across SEVERAL inbounds of different
// protocols with ONE quota, ONE expiry and ONE subscription. Membership of an
// inbound is a separate row (AccountInbound).
//
// This table sits ABOVE the existing settings JSON rather than replacing it.
// Inbound.Settings keeps its clients[] array and is maintained as a PROJECTION of
// the account onto each member inbound (see web/service/accountproject.go). That is
// what leaves RADIUS, the slot allocator, every daemon config writer and
// GetXrayConfig working unchanged: all of them parse settings.clients, and none of
// them need to learn a new source of truth.
//
// Email stays the global account identity, exactly as before: it is the unique key
// of client_traffics, the name RADIUS authenticates, and the selector the
// per-account routing rules are built from. One email, one traffic row, one quota,
// now spread over N inbounds instead of forcing N separate accounts.
type Account struct {
	Id int `json:"id" gorm:"primaryKey;autoIncrement"`

	// Email is the identity, and is matched case-insensitively after trimming (see
	// AccountKey). uniqueIndex here mirrors xray.ClientTraffic.Email's own unique
	// constraint; relaxing either was rejected twice before (see
	// multi-inbound-client-plan.md section 8b).
	Email string `json:"email" gorm:"uniqueIndex;not null"`

	// SubID is the subscription key, and is now INDEXED. It was previously free
	// text with no index, so a typo silently merged an account into someone else's
	// subscription. ValidateClientSubID rejects that at the write path.
	SubID string `json:"subId" gorm:"index;column:sub_id"`

	// Credentials are per FIELD, not per inbound: one uuid serves every vmess/vless
	// membership, one password every trojan membership. The projection picks the
	// field its member inbound's protocol keys on (see ClientIdentityKey).
	//
	// This split is REQUIRED here and is not cosmetic: Client.ID is overloaded in
	// the legacy shape, holding a UUID for vmess/vless, a login name for the
	// credential VPNs and ssh, and the email itself for wg-c/awg/mtproto. Storing
	// one "id" column would make it impossible to say which of those an account
	// holds without knowing the protocol it is being rendered for.
	UUID        string `json:"uuid" gorm:"column:uuid"`                // vmess / vless / tuic
	VpnUsername string `json:"vpnUsername" gorm:"column:vpn_username"` // l2tp/pptp/openvpn/openconnect/sstp/ikev2/ssh login
	Password    string `json:"password" gorm:"column:password"`        // trojan/shadowsocks/anytls + every credential VPN
	Auth        string `json:"auth" gorm:"column:auth"`                // hysteria
	Security    string `json:"security" gorm:"column:security"`        // vmess
	Secret      string `json:"secret" gorm:"column:secret"`            // mtproto
	NaiveUser   string `json:"naiveUser" gorm:"column:naive_username"` // naive HTTP Basic username; empty means "use Email"

	// Quota and lifecycle: the entire point of the table. One set of these per
	// account, however many inbounds it is on.
	TotalGB    int64 `json:"totalGB" gorm:"column:total_gb"`
	ExpiryTime int64 `json:"expiryTime" gorm:"column:expiry_time"`
	// NO gorm default, deliberately. `default:1` makes GORM treat Go's false as
	// "unset" and write 1 instead, so a DISABLED client migrated to an ENABLED
	// account. The projection then rendered enable:true over the stored false, the
	// round-trip verification caught the difference, and the ENTIRE migration
	// rolled back. That would have hit most real panels: exceeding a quota
	// disables an account automatically, so a disabled client is the norm and not
	// an edge case.
	//
	// The default buys nothing here. This table is new, so there are no legacy
	// rows to backfill, and every writer sets the field explicitly.
	Enable  bool   `json:"enable"`
	Reset   int    `json:"reset" gorm:"default:0"`
	LimitIP int    `json:"limitIp" gorm:"column:limit_ip"`
	TgID    int64  `json:"tgId" gorm:"column:tg_id"`
	Comment string `json:"comment"`

	CreatedBy int `json:"createdBy" gorm:"index"`
	CreatedAt int64 `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt int64 `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

// TableName pins the table name so it does not collide with anything GORM would
// infer, and so a future rename of the Go type cannot silently orphan live data.
func (Account) TableName() string { return "accounts" }

// AccountInbound is ONE membership: this account is served on this inbound.
// Composite primary key, so the same pair cannot be inserted twice.
type AccountInbound struct {
	AccountId int `json:"accountId" gorm:"primaryKey;column:account_id;index"`
	InboundId int `json:"inboundId" gorm:"primaryKey;column:inbound_id;index"`

	// Slot is per MEMBERSHIP and never per account. It is defined as "the account's
	// index into THIS inbound's address pool", and one email on N pool inbounds
	// legitimately consumes N slots at N different addresses. A pointer for the same
	// reason as Client.Slot: absent must stay distinguishable from slot 0, because
	// rows predating slots fall back to their list index.
	Slot *int `json:"slot" gorm:"column:slot"`

	// Flow is a per-membership override (vless only). v3 calls it FlowOverride.
	// Empty means "whatever the account/protocol default is".
	Flow string `json:"flow" gorm:"column:flow"`

	// Enable is "is this account served on THIS inbound", which is a different
	// question from Account.Enable ("is this account live at all"). The projection
	// renders the AND of the two, so an account switched off here stops being served
	// on this inbound and keeps working on every other one.
	//
	// This column is what makes the Clients page's per-inbound switch honest. It used
	// to write Account.Enable, which is panel-wide: RADIUS reads it through
	// client_traffics (radius.go:769) and so does the rbridge sweep (radius.go:701),
	// so a switch documented as "takes the account off ONE inbound and leaves the rest
	// serving it" took the customer off ALL of them, while the other memberships'
	// stored entries were left reading enable:true so the page showed them as fine.
	//
	// A POINTER for the same reason Slot is one: every row that predates this column
	// is NULL, and NULL has to mean "served", not "switched off". A plain bool with
	// `default:true` is the trap that already cost this table one whole migration:
	// GORM treats Go's false as unset and writes the default over it, so a membership
	// the operator disabled would come back enabled on the next save.
	Enable *bool `json:"enable" gorm:"column:enable"`

	// Extra is the VERBATIM client entry this membership was migrated from, minus
	// nothing: the whole original JSON object. The projection starts from it and
	// overlays only the keys the account layer owns, so any field neither Account
	// nor this struct models survives untouched.
	//
	// This is load-bearing, not an optimization. wg-c and awg mint a keypair PER
	// DEVICE and store them as clients[].devices[]; GRE stores pinned peer slots as
	// clients[].peers[]. model.Client does not model devices at all. A projection
	// that rebuilt the entry from modelled fields alone would therefore silently
	// destroy every WireGuard keypair on the first write, invalidating every
	// already-installed client config on the box. Keeping the original object and
	// overlaying onto it makes that class of loss impossible, including for
	// protocol fields added after this code was written.
	Extra string `json:"-" gorm:"column:extra"`

	CreatedAt int64 `json:"createdAt" gorm:"autoCreateTime:milli"`
}

// TableName pins the table name. See Account.TableName.
func (AccountInbound) TableName() string { return "account_inbounds" }
