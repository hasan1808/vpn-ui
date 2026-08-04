package service

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// The account-centric view behind the Clients page.
//
// Everything else in the panel is organised by INBOUND: an account is found by
// opening the inbound that serves it. That made sense while an account lived on
// exactly one, and stopped making sense the moment one account could be on
// several, because there was then no page that showed the account itself.
//
// This is a read model and nothing more. Every mutation the page performs goes
// back through the existing addClient / updateClient / delClientByEmail /
// bulkUpdateClients routes with an inboundIds set, so there is ONE write path for
// clients and not two to keep in step.

// AccountMembershipView is one inbound an account is served on, named the way an
// operator recognises it rather than by id alone.
type AccountMembershipView struct {
	InboundId int    `json:"inboundId"`
	Protocol  string `json:"protocol"`
	Remark    string `json:"remark"`
	Port      int    `json:"port"`
	Enable    bool   `json:"enable"`
	Slot      *int   `json:"slot"`
	// Method is the shadowsocks cipher, and empty for every other protocol. It is
	// reported because a 2022-blake3 cipher refuses a user password that is not
	// base64 of its exact key length, so a form offering ONE password for an
	// account spanning several protocols has to generate it in the strict shape
	// whenever one of these is in the set. Every other protocol takes any string,
	// so the strict shape satisfies all of them at once.
	Method string `json:"method,omitempty"`
	// ClientId is the value THIS protocol addresses the account by, which is the
	// path parameter /updateClient/:clientId and /delClient/:clientId take.
	//
	// It is protocol-dependent (a uuid for vmess and vless, the password for
	// trojan and the credential VPNs, the auth for hysteria, the email only for
	// shadowsocks), so a caller cannot derive it from the email. Without it the
	// Clients page sent the email and every edit came back "empty client ID" for
	// all but one protocol.
	ClientId string `json:"clientId"`
}

// AccountRow is one line of the Clients table.
type AccountRow struct {
	Id         int    `json:"id"`
	Email      string `json:"email"`
	Enable     bool   `json:"enable"`
	SubID      string `json:"subId"`
	Comment    string `json:"comment"`
	TotalGB    int64  `json:"totalGB"`    // bytes, despite the name
	ExpiryTime int64  `json:"expiryTime"` // ms; negative = delayed start
	Reset      int    `json:"reset"`
	LimitIP    int    `json:"limitIp"`
	// TgID is the Telegram chat the bot notifies. Reported so the Clients form can
	// edit it without a second read; 0 means the account is not linked.
	TgID        int64                   `json:"tgId"`
	Up          int64                   `json:"up"`
	Down        int64                   `json:"down"`
	Memberships []AccountMembershipView `json:"memberships"`
	// OwnedByReseller is the reseller's user id, or 0 for a house account. Shown
	// only to whoever may already see resellers.
	OwnedByReseller int `json:"ownedByReseller"`
}

// AccountListResult is one page of the Clients table.
type AccountListResult struct {
	Rows  []AccountRow `json:"rows"`
	Total int          `json:"total"` // rows matching the search, before paging
	Page  int          `json:"page"`
	Size  int          `json:"size"`
}

// ListAccounts returns the accounts the caller may see, filtered and paged.
//
// SCOPING IS THE WHOLE SECURITY SURFACE OF THIS ENDPOINT, and it fails closed.
// The underlying tables are panel-wide, so an unscoped list would hand every
// admin every other admin's customers and every reseller every other seller's:
//
//   - a super admin sees everything;
//   - a reseller sees ONLY the accounts they own (the ledger's OwnedEmails), which
//     is narrower than their inbound grants, because a shared inbound carries
//     other sellers' customers too;
//   - an ordinary admin sees accounts with at least one membership on an inbound
//     they hold, which is exactly what the Inbounds page already shows them.
func (s *AccountService) ListAccounts(user *model.User, page, size int, search string) (*AccountListResult, error) {
	if user == nil {
		// No identity, no rows. Never an unscoped list.
		return &AccountListResult{Rows: []AccountRow{}}, nil
	}
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}

	db := database.GetDB()

	var accounts []model.Account
	if err := db.Order("email ASC").Find(&accounts).Error; err != nil {
		return nil, err
	}

	memberships, err := s.membershipViews()
	if err != nil {
		return nil, err
	}

	// Usage comes from client_traffics, which is one row per account panel-wide.
	usage := map[string]*xray.ClientTraffic{}
	var traffics []xray.ClientTraffic
	if err := db.Find(&traffics).Error; err != nil {
		return nil, err
	}
	for i := range traffics {
		usage[accountKey(traffics[i].Email)] = &traffics[i]
	}

	owner := map[string]int{}
	var ledger []model.ResellerClient
	if err := db.Find(&ledger).Error; err != nil {
		return nil, err
	}
	for _, rc := range ledger {
		owner[accountKey(rc.Email)] = rc.UserId
	}

	visible, err := s.visibilityFilter(user)
	if err != nil {
		return nil, err
	}

	needle := strings.ToLower(strings.TrimSpace(search))
	rows := make([]AccountRow, 0, len(accounts))
	for i := range accounts {
		account := &accounts[i]
		key := accountKey(account.Email)
		mine := memberships[account.Id]
		if !visible(account, mine) {
			continue
		}
		if needle != "" && !accountMatches(account, mine, needle) {
			continue
		}
		row := AccountRow{
			Id: account.Id, Email: account.Email, Enable: account.Enable,
			SubID: account.SubID, Comment: account.Comment,
			TotalGB: account.TotalGB, ExpiryTime: account.ExpiryTime,
			Reset: account.Reset, LimitIP: account.LimitIP, TgID: account.TgID,
			Memberships: mine, OwnedByReseller: owner[key],
		}
		// client_traffics is one row per account panel-wide, and it is what the
		// enforcement paths actually read, so it wins over the account row for the
		// three fields both carry.
		//
		// Not belt-and-braces: several paths write settings.clients and
		// client_traffics without going through the accounts layer at all, the
		// depletion sweep in disableInvalidClients most of all. Reading enable off
		// the account row showed a depleted account as still on, days after the
		// data plane had cut it off.
		if t := usage[key]; t != nil {
			row.Up, row.Down = t.Up, t.Down
			row.Enable = t.Enable
			row.TotalGB = t.Total
			row.ExpiryTime = t.ExpiryTime
		}
		rows = append(rows, row)
	}

	total := len(rows)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return &AccountListResult{Rows: rows[start:end], Total: total, Page: page, Size: size}, nil
}

// membershipViews maps every account id to the inbounds serving it, named.
func (s *AccountService) membershipViews() (map[int][]AccountMembershipView, error) {
	db := database.GetDB()

	var inbounds []model.Inbound
	if err := db.Model(&model.Inbound{}).
		Select("id", "protocol", "remark", "port", "enable").Find(&inbounds).Error; err != nil {
		return nil, err
	}
	byId := make(map[int]*model.Inbound, len(inbounds))
	for i := range inbounds {
		byId[inbounds[i].Id] = &inbounds[i]
	}

	// The settings blob of each inbound, so the protocol-correct identity can be
	// read off the stored entry rather than guessed.
	var full []model.Inbound
	if err := db.Model(&model.Inbound{}).Select("id", "protocol", "settings").Find(&full).Error; err != nil {
		return nil, err
	}
	identityByInbound := make(map[int]map[string]string, len(full))
	for i := range full {
		clients, ok := parseSettingsClients(full[i].Settings)
		if !ok {
			continue
		}
		m := map[string]string{}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			if accountKey(email) == "" {
				continue
			}
			key := clientIdentityKey(full[i].Protocol)
			if v, isStr := entry[key].(string); isStr {
				m[accountKey(email)] = v
			}
		}
		identityByInbound[full[i].Id] = m
	}

	var rows []model.AccountInbound
	if err := db.Order("inbound_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	emailById := map[int]string{}
	var accts []model.Account
	if err := db.Select("id", "email").Find(&accts).Error; err != nil {
		return nil, err
	}
	for i := range accts {
		emailById[accts[i].Id] = accts[i].Email
	}
	out := make(map[int][]AccountMembershipView, len(rows))
	for i := range rows {
		m := &rows[i]
		inbound, ok := byId[m.InboundId]
		if !ok {
			// A membership whose inbound is gone. Skipped rather than shown as a
			// blank row: nothing serves it, so it is not somewhere the account is.
			continue
		}
		view := AccountMembershipView{
			InboundId: inbound.Id, Protocol: string(inbound.Protocol),
			Remark: inbound.Remark, Port: inbound.Port, Enable: inbound.Enable,
			Slot: m.Slot,
		}
		if ids := identityByInbound[inbound.Id]; ids != nil {
			view.ClientId = ids[accountKey(emailById[m.AccountId])]
		}
		out[m.AccountId] = append(out[m.AccountId], view)
	}
	return out, nil
}

// visibilityFilter returns the predicate deciding whether one account is the
// caller's to see. Built once per request rather than per row.
func (s *AccountService) visibilityFilter(user *model.User) (func(*model.Account, []AccountMembershipView) bool, error) {
	if user.IsSuperAdmin {
		return func(*model.Account, []AccountMembershipView) bool { return true }, nil
	}

	if user.IsReseller {
		// Narrower than their inbound grants on purpose: a reseller is legitimately
		// given a SHARED inbound, and that inbound carries other sellers' customers.
		// Scoping by grant would show them those.
		var resellerService ResellerService
		owned, err := resellerService.OwnedEmails(user.Id)
		if err != nil {
			return nil, err
		}
		return func(a *model.Account, _ []AccountMembershipView) bool {
			return owned[strings.ToLower(a.Email)]
		}, nil
	}

	var adminService AdminService
	ids, err := adminService.AccessibleInboundIds(user.Id)
	if err != nil {
		return nil, err
	}
	granted := make(map[int]bool, len(ids))
	for _, id := range ids {
		granted[id] = true
	}
	return func(_ *model.Account, memberships []AccountMembershipView) bool {
		for _, m := range memberships {
			if granted[m.InboundId] {
				return true
			}
		}
		return false
	}, nil
}

// accountMatches is the search predicate: email, comment, subId, or the name of
// any inbound it is served on.
func accountMatches(account *model.Account, memberships []AccountMembershipView, needle string) bool {
	if strings.Contains(strings.ToLower(account.Email), needle) ||
		strings.Contains(strings.ToLower(account.Comment), needle) ||
		strings.Contains(strings.ToLower(account.SubID), needle) {
		return true
	}
	for _, m := range memberships {
		if strings.Contains(strings.ToLower(m.Remark), needle) ||
			strings.Contains(strings.ToLower(m.Protocol), needle) {
			return true
		}
	}
	return false
}

// AssignableInboundsFor returns the inbounds the caller may put an account on,
// for the page's inbound picker. Same grant the write path enforces, so the
// picker cannot offer something the save would then refuse.
// settingsHoldClients reports whether an inbound's settings carry a clients array
// at all. dokodemo-door, socks, http and single-user shadowsocks legitimately do
// not, and parseSettingsClients cannot answer this: it returns ok=true for them,
// because "no clients array" and "unparseable" have to stay distinguishable there
// (treating the first as the second would delete every membership).
// inboundMethod reads settings.method, which only shadowsocks carries.
func inboundMethod(settings string) string {
	var root map[string]any
	if err := json.Unmarshal([]byte(settings), &root); err != nil || root == nil {
		return ""
	}
	m, _ := root["method"].(string)
	return m
}

func settingsHoldClients(settings string) bool {
	var root map[string]any
	if err := json.Unmarshal([]byte(settings), &root); err != nil || root == nil {
		return false
	}
	_, ok := root["clients"].([]any)
	return ok
}

func (s *AccountService) AssignableInboundsFor(user *model.User) ([]AccountMembershipView, error) {
	if user == nil {
		return nil, nil
	}
	db := database.GetDB()
	var inbounds []model.Inbound
	if err := db.Model(&model.Inbound{}).
		Select("id", "protocol", "remark", "port", "enable", "settings").
		Order("id ASC").Find(&inbounds).Error; err != nil {
		return nil, err
	}

	allowed := func(int) bool { return true }
	if !user.IsSuperAdmin {
		var adminService AdminService
		ids, err := adminService.AccessibleInboundIds(user.Id)
		if err != nil {
			return nil, err
		}
		granted := make(map[int]bool, len(ids))
		for _, id := range ids {
			granted[id] = true
		}
		allowed = func(id int) bool { return granted[id] }
	}

	out := make([]AccountMembershipView, 0, len(inbounds))
	for i := range inbounds {
		in := &inbounds[i]
		if !allowed(in.Id) {
			continue
		}
		// An inbound with no client list has nothing to be a member OF, and
		// offering it only produces a save the server refuses. Same rule the
		// client form's own checklist applies (modals/client_modal.html).
		if !settingsHoldClients(in.Settings) {
			continue
		}
		out = append(out, AccountMembershipView{
			InboundId: in.Id, Protocol: string(in.Protocol),
			Remark: in.Remark, Port: in.Port, Enable: in.Enable,
			Method: inboundMethod(in.Settings),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].InboundId < out[j].InboundId })
	return out, nil
}
