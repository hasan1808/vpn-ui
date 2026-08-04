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
	Email      string `json:"email" form:"email" gorm:"unique"`
	UUID       string `json:"uuid" form:"uuid" gorm:"-"`
	SubId      string `json:"subId" form:"subId" gorm:"-"`
	Up         int64  `json:"up" form:"up"`
	Down       int64  `json:"down" form:"down"`
	AllTime    int64  `json:"allTime" form:"allTime"`
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"`
	Total      int64  `json:"total" form:"total"`
	Reset      int    `json:"reset" form:"reset" gorm:"default:0"`
	LastOnline int64  `json:"lastOnline" form:"lastOnline" gorm:"default:0"`
}
