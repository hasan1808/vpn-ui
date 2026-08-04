package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"gorm.io/gorm"
)

// AdminService is the CRUD behind the Admins page. Every method here is reachable
// only by a super admin (enforced at the route), so it does not re-check the
// caller's role; it does enforce the invariants that keep the panel recoverable.
type AdminService struct{}

var (
	ErrAdminUsernameTaken = errors.New("that username is already taken")
	ErrAdminNotFound      = errors.New("admin not found")
	ErrLastSuperAdmin     = errors.New("this is the only super admin; promote another one first")
)

// AdminView is an admin as shown to the UI. Deliberately hand-built rather than
// returning model.User: it carries the permission slugs, and it keeps the password
// hash and TOTP secret from ever being serialized.
type AdminView struct {
	Id              int      `json:"id"`
	Username        string   `json:"username"`
	Nickname        string   `json:"nickname"`
	IsSuperAdmin    bool     `json:"isSuperAdmin"`
	Enable          bool     `json:"enable"`
	TwoFactorEnable bool     `json:"twoFactorEnable"`
	Permissions     []string `json:"permissions"`
	InboundCount    int64    `json:"inboundCount"`
	// InboundIds is what this admin may see, for the modal's checklist. Always [] for
	// a super admin: they see everything by role, not by grant.
	InboundIds []int `json:"inboundIds"`
}

func toAdminView(u *model.User, inbounds int64, inboundIds []int) AdminView {
	return AdminView{
		Id:              u.Id,
		Username:        u.Username,
		Nickname:        u.Nickname,
		IsSuperAdmin:    u.IsSuperAdmin,
		Enable:          u.Enable,
		TwoFactorEnable: u.TwoFactorEnable,
		Permissions:     u.Permissions.Slugs(),
		InboundCount:    inbounds,
		InboundIds:      inboundIds,
	}
}

// GetAdmins lists every admin, with how many inbounds each owns so the super admin
// can see what a delete would strand.
//
// Resellers are EXCLUDED. They live in the same table but are managed on their own
// page: listing one here would put it in a modal whose "Super Admin" tick promotes
// it, which is an escalation and not a cosmetic leak.
func (s *AdminService) GetAdmins() ([]AdminView, error) {
	db := database.GetDB()
	var users []*model.User
	if err := db.Model(model.User{}).Where("is_reseller = ?", false).
		Order("id asc").Find(&users).Error; err != nil {
		return nil, err
	}

	// One grouped count rather than a query per admin.
	type countRow struct {
		UserId int
		N      int64
	}
	var rows []countRow
	if err := db.Model(model.Inbound{}).
		Select("user_id as user_id, count(*) as n").Group("user_id").Scan(&rows).Error; err != nil {
		return nil, err
	}
	counts := make(map[int]int64, len(rows))
	for _, r := range rows {
		counts[r.UserId] = r.N
	}

	// One query for every grant rather than one per admin.
	var grants []model.InboundAccess
	if err := db.Model(&model.InboundAccess{}).Find(&grants).Error; err != nil {
		return nil, err
	}
	byUser := make(map[int][]int, len(users))
	for _, g := range grants {
		byUser[g.UserId] = append(byUser[g.UserId], g.InboundId)
	}

	out := make([]AdminView, 0, len(users))
	for _, u := range users {
		ids := byUser[u.Id]
		if ids == nil {
			ids = []int{} // marshal as [], not null: the UI ticks against it
		}
		out = append(out, toAdminView(u, counts[u.Id], ids))
	}
	return out, nil
}

// normalizeUsername trims and lowercases. Usernames are matched exactly at login
// against a unique index, so folding case here stops "Admin" and "admin" from
// being two accounts that look identical in the list.
func normalizeUsername(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (s *AdminService) usernameTaken(db *gorm.DB, username string, exceptId int) (bool, error) {
	var n int64
	q := db.Model(model.User{}).Where("username = ?", username)
	if exceptId > 0 {
		q = q.Where("id != ?", exceptId)
	}
	if err := q.Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// AdminSpec is the mutable shape of an admin as the Admins UI submits it. A struct
// rather than a positional list: the two adjacent int pairs (port range, subnet
// band) are trivially swappable at a call site, and the compiler cannot catch it.
type AdminSpec struct {
	Username string
	// Password empty on update means "keep the existing one".
	Password     string
	Nickname     string
	Permissions  model.Permission
	Enable       bool
	IsSuperAdmin bool
	// InboundIds is the exact set of inbounds this admin may see. Replaces whatever
	// they had. Empty means no access at all, which is a legitimate state (an admin
	// who has not been given anything yet), so it must not be read as "leave alone".
	InboundIds []int
}

// validate checks the parts that do not need the database.
func (spec *AdminSpec) validate() error {
	if spec.Username == "" {
		return errors.New("username is required")
	}
	return nil
}

// AddAdmin creates an admin. Password is required and always bcrypt-hashed here:
// nothing downstream will retro-hash it.
func (s *AdminService) AddAdmin(spec AdminSpec) (*model.User, error) {
	spec.Username = normalizeUsername(spec.Username)
	if err := spec.validate(); err != nil {
		return nil, err
	}
	if spec.Password == "" {
		return nil, errors.New("password is required")
	}
	username := spec.Username
	db := database.GetDB()
	taken, err := s.usernameTaken(db, username, 0)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrAdminUsernameTaken
	}
	hash, err := crypto.HashPasswordAsBcrypt(spec.Password)
	if err != nil {
		return nil, err
	}
	user := &model.User{
		Username:    username,
		Password:    hash,
		Nickname:    strings.TrimSpace(spec.Nickname),
		Permissions: spec.Permissions,
		Enable:      spec.Enable,
		// A super admin is never created through this path: promotion is a separate,
		// deliberate act (UpdateAdmin), so a misfiled create can't mint one.
		IsSuperAdmin: false,
	}
	// Enable carries gorm:"default:1" so rows predating the column read back enabled.
	// The cost is that GORM omits a zero-valued field that has a default from the
	// INSERT and lets the DB default win, so an admin created DISABLED would be
	// stored enable=1 and could log in. Force the intended value, in one transaction
	// so no window exists where the account is live.
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		if !spec.Enable {
			return tx.Model(model.User{}).Where("id = ?", user.Id).Update("enable", false).Error
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	user.Enable = spec.Enable
	if err := s.SetInboundAccess(user.Id, spec.InboundIds); err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateAdmin edits an admin. An empty password leaves the existing one alone, so
// the UI can save permission changes without asking for a password.
func (s *AdminService) UpdateAdmin(id int, spec AdminSpec) error {
	db := database.GetDB()
	existing := &model.User{}
	if err := db.Model(model.User{}).Where("id = ?", id).First(existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAdminNotFound
		}
		return err
	}

	// The Admins page must not reach a reseller. It is excluded from the list, but
	// the id travels in the URL and this is the only thing between a crafted POST
	// and a reseller being ticked into a super admin.
	if existing.IsReseller {
		return ErrAdminNotFound
	}

	spec.Username = normalizeUsername(spec.Username)
	if err := spec.validate(); err != nil {
		return err
	}
	username := spec.Username
	taken, err := s.usernameTaken(db, username, id)
	if err != nil {
		return err
	}
	if taken {
		return ErrAdminUsernameTaken
	}

	// Refuse to demote or disable the last super admin: either would leave nobody
	// able to manage admins, with no way back through the UI.
	if existing.IsSuperAdmin && (!spec.IsSuperAdmin || !spec.Enable) {
		last, err := s.isLastSuperAdmin(db, id)
		if err != nil {
			return err
		}
		if last {
			return ErrLastSuperAdmin
		}
	}

	updates := map[string]any{
		"username":       username,
		"nickname":       strings.TrimSpace(spec.Nickname),
		"permissions":    spec.Permissions,
		"enable":         spec.Enable,
		"is_super_admin": spec.IsSuperAdmin,
	}
	if spec.Password != "" {
		hash, err := crypto.HashPasswordAsBcrypt(spec.Password)
		if err != nil {
			return err
		}
		updates["password"] = hash
	}
	if err := db.Model(model.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	// Super admins see everything by role, so carrying explicit grants for one would
	// be dead rows that reappear if they are ever demoted.
	if spec.IsSuperAdmin {
		return s.SetInboundAccess(id, nil)
	}
	return s.SetInboundAccess(id, spec.InboundIds)
}

func (s *AdminService) isLastSuperAdmin(db *gorm.DB, id int) (bool, error) {
	var others int64
	err := db.Model(model.User{}).
		Where("is_super_admin = ? AND enable = ? AND id != ?", true, true, id).Count(&others).Error
	if err != nil {
		return false, err
	}
	return others == 0, nil
}

// DeleteAdmin removes an admin. Refuses the last super admin, and refuses while
// the account still owns inbounds: those would become invisible to everyone,
// while their daemons kept running and their clients kept connecting.
func (s *AdminService) DeleteAdmin(id int) error {
	db := database.GetDB()
	existing := &model.User{}
	if err := db.Model(model.User{}).Where("id = ?", id).First(existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAdminNotFound
		}
		return err
	}
	// Resellers are deleted from their own page, which also has to settle the
	// balance and the accounts they own. Deleting one from here would leave both
	// stranded.
	if existing.IsReseller {
		return ErrAdminNotFound
	}
	if existing.IsSuperAdmin {
		last, err := s.isLastSuperAdmin(db, id)
		if err != nil {
			return err
		}
		if last {
			return ErrLastSuperAdmin
		}
	}
	var owned int64
	if err := db.Model(model.Inbound{}).Where("user_id = ?", id).Count(&owned).Error; err != nil {
		return err
	}
	if owned > 0 {
		return fmt.Errorf("this admin still owns %d inbound(s); delete or reassign them first", owned)
	}
	return db.Where("id = ?", id).Delete(&model.User{}).Error
}

// ReassignInbounds moves every inbound owned by one admin to another, so a super
// admin can empty an account before deleting it.
func (s *AdminService) ReassignInbounds(fromId, toId int) (int64, error) {
	db := database.GetDB()
	if fromId == toId {
		return 0, errors.New("source and destination admin are the same")
	}
	var n int64
	if err := db.Model(model.User{}).Where("id = ?", toId).Count(&n).Error; err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, ErrAdminNotFound
	}
	res := db.Model(model.Inbound{}).Where("user_id = ?", fromId).Update("user_id", toId)
	return res.RowsAffected, res.Error
}

// --- Inbound access ------------------------------------------------------------
//
// Access is ASSIGNED: a super admin ticks which inbounds each admin may see, and
// anything unticked is invisible to them. Inbound.UserId records who CREATED a row
// and is bookkeeping only; it does not decide access.
//
// Every one of these fails CLOSED. An access question we cannot answer must never
// resolve to "allowed".

// AccessibleInboundIds lists the inbounds this admin may see. Super admins are not
// listed in the table (they see everything by role), so callers must check
// IsSuperAdmin first; this returns only explicit grants.
func (s *AdminService) AccessibleInboundIds(userId int) ([]int, error) {
	var ids []int
	err := database.GetDB().Model(&model.InboundAccess{}).
		Where("user_id = ?", userId).Pluck("inbound_id", &ids).Error
	return ids, err
}

// CanAccessInbound reports whether userId has been granted this inbound.
func (s *AdminService) CanAccessInbound(inboundId, userId int) (bool, error) {
	var n int64
	err := database.GetDB().Model(&model.InboundAccess{}).
		Where("inbound_id = ? AND user_id = ?", inboundId, userId).Count(&n).Error
	return n > 0, err
}

// CanAccessAllInbounds reports whether userId has been granted every one of ids.
// Used by the paths whose targets come from the request body rather than the path.
func (s *AdminService) CanAccessAllInbounds(ids []int, userId int) (bool, error) {
	if len(ids) == 0 {
		return true, nil
	}
	// Distinct: a body may name the same inbound twice, which would undercount.
	uniq := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		uniq[id] = struct{}{}
	}
	want := make([]int, 0, len(uniq))
	for id := range uniq {
		want = append(want, id)
	}
	var n int64
	err := database.GetDB().Model(&model.InboundAccess{}).
		Where("inbound_id IN (?) AND user_id = ?", want, userId).Count(&n).Error
	if err != nil {
		return false, err
	}
	return int(n) == len(want), nil
}

// CanAccessClientEmail reports whether userId has been granted ANY inbound serving
// this client. Client emails are a single panel-wide namespace, so an :email route
// reaches across admins without this.
//
// "Any", not "the": one account is served on N inbounds, and the join this used to
// be (inbound_accesses against client_traffics.inbound_id) asked about exactly one
// of them, the one that account's single traffic row happens to name. An admin
// holding inbound B but not A was therefore DENIED every :email route for a client
// sitting in their own inbound, which reads as the panel losing the account.
//
// Resolved through servingInboundIds so this and ClientEmailAccess answer the same
// question the same way; two access checks that disagree are how a route ends up
// enforcing something the payload producer never scoped for.
func (s *AdminService) CanAccessClientEmail(email string, userId int) (bool, error) {
	db := database.GetDB()
	ids, err := servingInboundIds(db, email)
	if err != nil {
		return false, err
	}
	if len(ids) == 0 {
		// No inbound serves it, so no grant can reach it. Fails closed, like every
		// other unanswerable access question here.
		return false, nil
	}
	var n int64
	err = db.Model(&model.InboundAccess{}).
		Where("inbound_id IN (?) AND user_id = ?", ids, userId).Count(&n).Error
	return n > 0, err
}

// GrantInbound gives one admin access to one inbound. Idempotent.
// Called when an admin creates an inbound: without it they could not see the thing
// they just made.
func (s *AdminService) GrantInbound(userId, inboundId int) error {
	if userId <= 0 || inboundId <= 0 {
		return nil
	}
	var n int64
	db := database.GetDB()
	if err := db.Model(&model.InboundAccess{}).
		Where("user_id = ? AND inbound_id = ?", userId, inboundId).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return db.Create(&model.InboundAccess{UserId: userId, InboundId: inboundId}).Error
}

// SetInboundAccess replaces an admin's grants with exactly inboundIds.
func (s *AdminService) SetInboundAccess(userId int, inboundIds []int) error {
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userId).Delete(&model.InboundAccess{}).Error; err != nil {
			return err
		}
		for _, id := range inboundIds {
			if id <= 0 {
				continue
			}
			if err := tx.Create(&model.InboundAccess{UserId: userId, InboundId: id}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeInboundEverywhere drops every grant for an inbound, for use when it is
// deleted. Without it the rows linger and a recycled inbound id would silently
// inherit the old grants.
func (s *AdminService) RevokeInboundEverywhere(inboundId int) error {
	return database.GetDB().Where("inbound_id = ?", inboundId).Delete(&model.InboundAccess{}).Error
}

// ClientEmailAccess maps every client email to the set of admins granted an inbound
// SERVING it, so a producer can scope a panel-wide payload down to each audience.
//
// The plural matters here for the same reason it does in CanAccessClientEmail: an
// account lives on N inbounds and the join this used to be resolved one of them, so
// an admin holding only the others saw none of their own clients in the traffic
// broadcast or the online list while the single-account check waved them through.
// Both now go through servingInboundIds, so they cannot disagree.
//
// Keyed by every spelling of an identity the panel stores, not just one. Callers
// index this with an email taken from wherever their payload came from
// (client_traffics for the traffic rows, an Xray stat name for the online list,
// which carries the settings spelling), and those differ in case on real panels.
// A single-spelling map silently hid a client from its own admin.
func (s *AdminService) ClientEmailAccess() (map[string]map[int]bool, error) {
	db := database.GetDB()

	var grants []model.InboundAccess
	if err := db.Model(&model.InboundAccess{}).Find(&grants).Error; err != nil {
		return nil, err
	}
	adminsByInbound := make(map[int]map[int]bool, len(grants))
	for _, g := range grants {
		if adminsByInbound[g.InboundId] == nil {
			adminsByInbound[g.InboundId] = map[int]bool{}
		}
		adminsByInbound[g.InboundId][g.UserId] = true
	}

	// key -> inbounds serving it, and key -> every spelling seen. Built from the
	// same three sources servingInboundIds unions, in one pass rather than one
	// query per account: this runs on the traffic broadcast's tick.
	idsByKey := map[string]map[int]bool{}
	spellings := map[string][]string{}
	note := func(email string, inboundId int) {
		key := accountKey(email)
		if key == "" {
			return
		}
		if idsByKey[key] == nil {
			idsByKey[key] = map[int]bool{}
			spellings[key] = []string{key}
		}
		if inboundId > 0 {
			idsByKey[key][inboundId] = true
		}
		for _, seen := range spellings[key] {
			if seen == email {
				return
			}
		}
		spellings[key] = append(spellings[key], email)
	}

	var inbounds []*model.Inbound
	if err := db.Model(&model.Inbound{}).Select("id", "settings").Find(&inbounds).Error; err != nil {
		return nil, err
	}
	live := make(map[int]bool, len(inbounds))
	for _, inbound := range inbounds {
		live[inbound.Id] = true
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			note(email, inbound.Id)
		}
	}

	type membershipRow struct {
		Email     string
		InboundId int
	}
	var members []membershipRow
	if err := db.Table("account_inbounds").
		Select("accounts.email as email, account_inbounds.inbound_id as inbound_id").
		Joins("JOIN accounts ON accounts.id = account_inbounds.account_id").
		Scan(&members).Error; err != nil {
		return nil, err
	}
	for _, m := range members {
		if !live[m.InboundId] {
			continue // a membership outliving its inbound grants nothing
		}
		note(m.Email, m.InboundId)
	}

	var traffics []xray.ClientTraffic
	if err := db.Model(&xray.ClientTraffic{}).Select("email", "inbound_id").Find(&traffics).Error; err != nil {
		return nil, err
	}
	for _, ct := range traffics {
		if !live[ct.InboundId] {
			note(ct.Email, 0) // record the spelling; a dead inbound grants nothing
			continue
		}
		note(ct.Email, ct.InboundId)
	}

	out := make(map[string]map[int]bool, len(idsByKey))
	for key, ids := range idsByKey {
		admins := map[int]bool{}
		for id := range ids {
			for userId := range adminsByInbound[id] {
				admins[userId] = true
			}
		}
		if len(admins) == 0 {
			continue
		}
		for _, spelling := range spellings[key] {
			out[spelling] = admins
		}
	}
	return out, nil
}

// SuperAdminIds returns the ids of enabled super admins.
func (s *AdminService) SuperAdminIds() (map[int]bool, error) {
	var ids []int
	err := database.GetDB().Model(model.User{}).
		Where("is_super_admin = ? AND enable = ?", true, true).Pluck("id", &ids).Error
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// InboundBrief is one inbound as the Admins access checklist needs it: enough to
// identify it, and nothing else. Deliberately not the whole row, which carries the
// Settings blob with every client's credentials.
type InboundBrief struct {
	Id       int    `json:"id"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// AllInboundsBrief lists every inbound for the access checklist.
func (s *AdminService) AllInboundsBrief() ([]InboundBrief, error) {
	var out []InboundBrief
	err := database.GetDB().Model(&model.Inbound{}).
		Select("id", "remark", "protocol", "port").Order("id asc").Scan(&out).Error
	if out == nil {
		out = []InboundBrief{}
	}
	return out, err
}

// MigrationOverviewAccess grants PermAccessOverview to the admins who predate that
// bit, exactly once per install.
//
// Before the bit existed the overview was ungated, so every admin could open it. A
// new bit defaults to 0, which means a plain upgrade-and-restart would silently take
// the panel's home page away from every non-super admin on the box, and the only
// clue would be admins reporting that logging in lands them somewhere else.
//
// Guarded by a SETTING and not by "does anybody hold the bit yet": an operator who
// deliberately revokes it must not have it handed back on the next restart, and
// without a marker every restart looks exactly like the first one.
//
// Super admins are skipped because they bypass the mask, and resellers because Can()
// ignores their stored mask in favour of their profile booleans, so bits written
// onto their row grant nothing and leave a misleading column behind.
//
// Called from main.go on every boot and NOT from MigrateDB: that function is reached
// only by `vpn-ui migrate`, a DB import and a restore, so a backfill placed there
// never runs on the upgrade path this exists for.
func (s *AdminService) MigrationOverviewAccess() {
	var settingService SettingService
	if settingService.GetOverviewAccessBackfilled() {
		return
	}
	// Bitwise OR in SQL rather than read-modify-write, so an admin's other
	// permissions cannot be clobbered by a stale in-memory copy of the mask. COALESCE
	// because NULL | anything is NULL in SQLite: one hand-edited or imported row with
	// a null mask would otherwise be written back as null rather than repaired.
	err := database.GetDB().Model(model.User{}).
		Where("is_super_admin = ? AND is_reseller = ?", false, false).
		Update("permissions", gorm.Expr("COALESCE(permissions, 0) | ?", model.PermAccessOverview)).Error
	if err != nil {
		logger.Warning("MigrationOverviewAccess - granting the overview permission failed: ", err)
		return
	}
	if err := settingService.SetOverviewAccessBackfilled(true); err != nil {
		// The grant landed but the marker did not, so this runs again on the next
		// start. Worth saying out loud: until the marker sticks, a revoked overview
		// permission comes back on every restart.
		logger.Warning("MigrationOverviewAccess - recording the backfill failed, it will run again: ", err)
	}
}
