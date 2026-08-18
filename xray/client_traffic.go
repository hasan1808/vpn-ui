package xray

// ClientTraffic represents traffic statistics and limits for a specific client.
// It tracks upload/download usage, expiry times, and online status for inbound clients.
type ClientTraffic struct {
	Id int `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	// InboundId is the account's HOME inbound: whichever one it was created on.
	//
	// It is not "the inbound this account is served on", and must not be used as
	// though it were. Email below is unique panel-wide, so there is exactly ONE
	// row per account no matter how many inbounds serve it, and this column can
	// only ever name one of them. Every enforcement path that scoped itself with
	// `WHERE inbound_id = ?` therefore acted on one arbitrary membership and left
	// the rest unenforced; they now resolve by email instead.
	//
	// Indexed because Inbound.ClientStats is a has-many on it and the preload runs
	// on every inbound list.
	InboundId int  `json:"inboundId" form:"inboundId" gorm:"index"`
	Enable    bool `json:"enable" form:"enable"`
	// Email is the global account identity, unique across ALL inbounds (see the email
	// helpers in web/service/inbound.go). This index is the last line of defense, not
	// a formality: ImportDB (web/service/server.go) swaps the SQLite file wholesale
	// and so bypasses every service-level check, leaving the constraint as the only
	// thing standing between a hand-edited backup and two clients sharing an identity.
	Email string `json:"email" form:"email" gorm:"unique"`
	UUID  string `json:"uuid" form:"uuid" gorm:"-"`
	SubId string `json:"subId" form:"subId" gorm:"-"`
	// Up/Down/AllTime are the ACCOUNT's usage, panel-wide, and mean exactly what they
	// always have. The quota is an account-level limit, so every "how full is this
	// client" question - the progress bars, the usage colours, the depletion sweep,
	// the remaining-bytes figure - has to compare against these and not against one
	// inbound's slice of them.
	Up      int64 `json:"up" form:"up"`
	Down    int64 `json:"down" form:"down"`
	AllTime int64 `json:"allTime" form:"allTime"`

	// InboundUp/InboundDown/InboundAllTime are the same account's usage THROUGH THE
	// ONE INBOUND this row was rendered under, read from its membership row
	// (model.AccountInbound). Additive: nothing that existed before this field reads
	// them, so no quota or enforcement behaviour depends on them.
	//
	// Display only, hence gorm:"-": the authoritative counter is still the single
	// client_traffics row above. Set by InboundService.attachClientStats.
	InboundUp      int64 `json:"inboundUp" gorm:"-"`
	InboundDown    int64 `json:"inboundDown" gorm:"-"`
	InboundAllTime int64 `json:"inboundAllTime" gorm:"-"`

	// Shared says the three fields above are NOT this inbound's own share: they are
	// the bytes left over after every attributable inbound took its part, pooled
	// across each Xray-native inbound serving the account.
	//
	// The pooling cannot be undone here. Xray names its counter
	// "user>>><email>>>>traffic>>>{up,down}" with no inbound component (xray/api.go),
	// so an account on vless AND trojan gets ONE number covering both and there is
	// nothing to split it by. Showing those inbounds a zero instead would read as
	// "this customer never used it", which is simply false, so the page states the
	// caveat rather than inventing a number or hiding one.
	Shared bool `json:"shared" gorm:"-"`

	// CoreCounted marks a COLLECTED record (never a stored row) as Xray's own user
	// stat, which is the one measurement that arrives without knowing which inbound
	// it came through.
	//
	// It is what lets the panel finish the attribution the core cannot: an account's
	// bytes with no inbound on them can only have entered through one of the inbounds
	// that produce a user stat at all, so when exactly one of those is in play the
	// answer follows (see attributeCoreRecords). The flag has to be carried rather
	// than guessed, because a record naming no inbound may equally be a VPN session
	// the collector could not place, and those bytes did NOT come through an Xray
	// inbound - attributing them to one would be a fiction.
	CoreCounted bool `json:"-" gorm:"-"`

	ExpiryTime int64 `json:"expiryTime" form:"expiryTime"`
	Total      int64 `json:"total" form:"total"`
	Reset      int   `json:"reset" form:"reset" gorm:"default:0"`
	LastOnline int64 `json:"lastOnline" form:"lastOnline" gorm:"default:0"`
}
