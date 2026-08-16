package service

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/util/crypto"
	"github.com/xlzd/gotp"
)

func newAdminDB(t *testing.T) *AdminService {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	return &AdminService{}
}

// A fresh install must come up with exactly one usable super admin, or nobody can
// administer the panel.
func TestInitDBSeedsSuperAdmin(t *testing.T) {
	newAdminDB(t)
	user := &model.User{}
	if err := database.GetDB().Model(model.User{}).Order("id asc").First(user).Error; err != nil {
		t.Fatalf("no seeded admin: %v", err)
	}
	if !user.IsSuperAdmin {
		t.Error("seeded admin is not a super admin; nobody could manage the panel")
	}
	if !user.Enable {
		t.Error("seeded admin is disabled and could never log in")
	}
	// Zero permissions is correct: super admins bypass the mask.
	if !user.Can(model.PermAccessInbounds) || !user.Can(model.PermPanelSettings) {
		t.Error("super admin must bypass the permission mask")
	}
}

// The upgrade path. A pre-multi-admin row has is_super_admin=0 and permissions=0;
// left alone it would log in and be able to do nothing at all, with no way to grant
// itself anything back.
func TestMigrateSuperAdminPromotesExistingAdmin(t *testing.T) {
	newAdminDB(t)
	db := database.GetDB()

	// Reproduce the pre-upgrade shape.
	if err := db.Model(model.User{}).Where("1 = 1").Updates(map[string]any{
		"is_super_admin": false, "permissions": 0, "enable": false,
	}).Error; err != nil {
		t.Fatalf("simulate legacy row: %v", err)
	}
	// Re-open: InitDB runs the migrations.
	database.MigrateSuperAdminForTest()

	user := &model.User{}
	if err := db.Model(model.User{}).Order("id asc").First(user).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !user.IsSuperAdmin || !user.Enable {
		t.Errorf("legacy admin not promoted: isSuper=%v enable=%v", user.IsSuperAdmin, user.Enable)
	}
}

func TestPermissionMaskRoundTrip(t *testing.T) {
	slugs := []string{"accessInbounds", "editClient", "bulkOperation"}
	mask := model.PermissionsFromSlugs(slugs)

	if !mask.Has(model.PermAccessInbounds) || !mask.Has(model.PermEditClient) || !mask.Has(model.PermBulkOperation) {
		t.Error("mask lost a permission it was given")
	}
	if mask.Has(model.PermDeleteInbound) || mask.Has(model.PermPanelSettings) {
		t.Error("mask granted a permission it was never given")
	}
	got := mask.Slugs()
	if len(got) != 3 {
		t.Errorf("round-trip = %v; want 3 slugs", got)
	}
	// An unknown slug must cost only itself, not the whole save.
	mixed := model.PermissionsFromSlugs([]string{"accessInbounds", "nonsenseSlug"})
	if !mixed.Has(model.PermAccessInbounds) || mixed.Slugs()[0] != "accessInbounds" {
		t.Error("an unknown slug must be ignored, not poison the mask")
	}
}

// A non-super admin is confined to their own permission bits, and a disabled
// account can do nothing regardless of what it was granted.
func TestUserCan(t *testing.T) {
	limited := &model.User{
		Enable:      true,
		Permissions: model.PermAccessInbounds | model.PermEditClient,
	}
	if !limited.Can(model.PermAccessInbounds) || !limited.Can(model.PermEditClient) {
		t.Error("granted permission denied")
	}
	if limited.Can(model.PermDeleteInbound) || limited.Can(model.PermPanelSettings) {
		t.Error("ungranted permission allowed")
	}

	disabled := &model.User{Enable: false, Permissions: model.PermAccessInbounds, IsSuperAdmin: true}
	if disabled.Can(model.PermAccessInbounds) {
		t.Error("a disabled account must be able to do nothing, even as super admin")
	}

	var nilUser *model.User
	if nilUser.Can(model.PermAccessInbounds) {
		t.Error("a nil user must be able to do nothing")
	}
}

func TestAddAdminHashesPasswordAndRejectsDuplicates(t *testing.T) {
	s := newAdminDB(t)

	user, err := s.AddAdmin(AdminSpec{Username: "Reza", Password: "hunter2", Nickname: "Reza R", Permissions: model.PermAccessInbounds, Enable: true})
	if err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	if user.Password == "hunter2" {
		t.Fatal("password stored in plaintext")
	}
	if !crypto.CheckPasswordHash(user.Password, "hunter2") {
		t.Error("stored password does not verify")
	}
	if user.Username != "reza" {
		t.Errorf("username = %q; want it normalized to %q", user.Username, "reza")
	}
	if user.IsSuperAdmin {
		t.Error("AddAdmin must never mint a super admin")
	}

	// Case-folded duplicates must be refused: login matches exactly, and First()
	// would silently resolve to the lower id, making the second account dead.
	if _, err := s.AddAdmin(AdminSpec{Username: "REZA", Password: "other", Nickname: "", Permissions: 0, Enable: true}); !errors.Is(err, ErrAdminUsernameTaken) {
		t.Errorf("duplicate username error = %v; want ErrAdminUsernameTaken", err)
	}
	if _, err := s.AddAdmin(AdminSpec{Username: "nopass", Password: "", Nickname: "", Permissions: 0, Enable: true}); err == nil {
		t.Error("an admin with no password must be refused")
	}
}

// The panel must never be left with nobody who can administer it.
func TestCannotStrandPanelWithoutSuperAdmin(t *testing.T) {
	s := newAdminDB(t)
	db := database.GetDB()

	super := &model.User{}
	if err := db.Model(model.User{}).Where("is_super_admin = ?", true).First(super).Error; err != nil {
		t.Fatalf("no super admin: %v", err)
	}

	// Demoting the only super admin.
	err := s.UpdateAdmin(super.Id, AdminSpec{Username: super.Username, Permissions: 0, Enable: true, IsSuperAdmin: false})
	if !errors.Is(err, ErrLastSuperAdmin) {
		t.Errorf("demoting the last super admin: err = %v; want ErrLastSuperAdmin", err)
	}
	// Disabling the only super admin.
	err = s.UpdateAdmin(super.Id, AdminSpec{Username: super.Username, Permissions: 0, Enable: false, IsSuperAdmin: true})
	if !errors.Is(err, ErrLastSuperAdmin) {
		t.Errorf("disabling the last super admin: err = %v; want ErrLastSuperAdmin", err)
	}
	// Deleting the only super admin.
	if err := s.DeleteAdmin(super.Id); !errors.Is(err, ErrLastSuperAdmin) {
		t.Errorf("deleting the last super admin: err = %v; want ErrLastSuperAdmin", err)
	}

	// With a second super admin present, demoting the first is fine.
	second, err := s.AddAdmin(AdminSpec{Username: "second", Password: "pw", Nickname: "", Permissions: 0, Enable: true})
	if err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	if err := s.UpdateAdmin(second.Id, AdminSpec{Username: "second", Permissions: 0, Enable: true, IsSuperAdmin: true}); err != nil {
		t.Fatalf("promote second: %v", err)
	}
	if err := s.UpdateAdmin(super.Id, AdminSpec{Username: super.Username, Permissions: 0, Enable: true, IsSuperAdmin: false}); err != nil {
		t.Errorf("demoting with another super admin present should succeed: %v", err)
	}
}

// Deleting an admin who still owns inbounds would strand them: invisible to
// everyone, while their daemons keep running and their clients keep connecting.
func TestDeleteAdminRefusesWhileOwningInbounds(t *testing.T) {
	s := newAdminDB(t)
	db := database.GetDB()

	owner, err := s.AddAdmin(AdminSpec{Username: "owner", Password: "pw", Nickname: "", Permissions: model.PermAccessInbounds, Enable: true})
	if err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	ib := &model.Inbound{UserId: owner.Id, Tag: "inbound-30001", Port: 30001, Protocol: model.VMESS, Enable: true}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	if err := s.DeleteAdmin(owner.Id); err == nil {
		t.Error("deleting an admin who still owns inbounds must be refused")
	}

	// Reassigning to someone else empties them, and then the delete succeeds.
	other, err := s.AddAdmin(AdminSpec{Username: "other", Password: "pw", Nickname: "", Permissions: 0, Enable: true})
	if err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	moved, err := s.ReassignInbounds(owner.Id, other.Id)
	if err != nil || moved != 1 {
		t.Fatalf("ReassignInbounds = (%d, %v); want (1, nil)", moved, err)
	}
	if err := s.DeleteAdmin(owner.Id); err != nil {
		t.Errorf("delete after reassign: %v", err)
	}
}

// The access guard. Access is ASSIGNED: an admin sees exactly what a super admin
// ticked for them, and nothing else. Without these an admin reads and edits another
// admin's inbound by guessing a small integer.
func TestInboundAccessChecks(t *testing.T) {
	s := newAdminDB(t)
	db := database.GetDB()

	ali, _ := s.AddAdmin(AdminSpec{Username: "ali", Password: "pw", Permissions: model.PermAccessInbounds, Enable: true})
	reza, _ := s.AddAdmin(AdminSpec{Username: "reza", Password: "pw", Permissions: model.PermAccessInbounds, Enable: true})

	alisInbound := &model.Inbound{UserId: ali.Id, Tag: "inbound-31001", Port: 31001, Protocol: model.VMESS, Enable: true}
	rezasInbound := &model.Inbound{UserId: reza.Id, Tag: "inbound-31002", Port: 31002, Protocol: model.VMESS, Enable: true}
	for _, ib := range []*model.Inbound{alisInbound, rezasInbound} {
		if err := db.Create(ib).Error; err != nil {
			t.Fatalf("create inbound: %v", err)
		}
	}
	// Creating a row grants nothing on its own: access is assigned, and the creator's
	// grant is added by the controller. Assign it here explicitly.
	if err := s.GrantInbound(ali.Id, alisInbound.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := s.GrantInbound(reza.Id, rezasInbound.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if ok, _ := s.CanAccessInbound(alisInbound.Id, ali.Id); !ok {
		t.Error("Ali must reach the inbound granted to him")
	}
	if ok, _ := s.CanAccessInbound(alisInbound.Id, reza.Id); ok {
		t.Error("Reza must NOT reach an inbound he was never granted")
	}
	if ok, _ := s.CanAccessInbound(9999, ali.Id); ok {
		t.Error("a nonexistent inbound must not be accessible")
	}

	// A batch is refused unless EVERY id is granted; one foreign id poisons it.
	if ok, _ := s.CanAccessAllInbounds([]int{alisInbound.Id}, ali.Id); !ok {
		t.Error("Ali must reach a batch of only his own")
	}
	if ok, _ := s.CanAccessAllInbounds([]int{alisInbound.Id, rezasInbound.Id}, ali.Id); ok {
		t.Error("a batch containing an ungranted inbound must be refused")
	}
	if ok, _ := s.CanAccessAllInbounds([]int{}, ali.Id); !ok {
		t.Error("an empty batch is vacuously accessible")
	}
	// A duplicated id must not undercount the distinct set and pass by accident.
	if ok, _ := s.CanAccessAllInbounds([]int{alisInbound.Id, alisInbound.Id}, ali.Id); !ok {
		t.Error("a repeated id must not break the count")
	}

	// Granting is what the super admin's checklist does. It is idempotent.
	if err := s.GrantInbound(reza.Id, alisInbound.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := s.GrantInbound(reza.Id, alisInbound.Id); err != nil {
		t.Fatalf("re-grant must be idempotent: %v", err)
	}
	if ok, _ := s.CanAccessInbound(alisInbound.Id, reza.Id); !ok {
		t.Error("Reza must reach an inbound granted to him")
	}

	// SetInboundAccess REPLACES: an empty set means no access, not "leave alone".
	if err := s.SetInboundAccess(reza.Id, nil); err != nil {
		t.Fatalf("SetInboundAccess: %v", err)
	}
	if ok, _ := s.CanAccessInbound(alisInbound.Id, reza.Id); ok {
		t.Error("revoking must actually revoke")
	}
	if ok, _ := s.CanAccessInbound(rezasInbound.Id, reza.Id); ok {
		t.Error("an empty set must clear every grant, including his own")
	}

	// Deleting an inbound must drop its grants, or a stale row lingers forever.
	if err := s.SetInboundAccess(ali.Id, []int{alisInbound.Id}); err != nil {
		t.Fatalf("SetInboundAccess: %v", err)
	}
	if err := s.RevokeInboundEverywhere(alisInbound.Id); err != nil {
		t.Fatalf("RevokeInboundEverywhere: %v", err)
	}
	if ok, _ := s.CanAccessInbound(alisInbound.Id, ali.Id); ok {
		t.Error("a deleted inbound's grants must not survive")
	}
}

// TOTP must tolerate a little clock drift, or an admin with a slightly-off phone
// is locked out for good.
func TestVerifyTOTPSkewTolerance(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	totp := gotp.NewDefaultTOTP(secret)

	if !verifyTOTP(secret, totp.Now()) {
		t.Error("the current code must verify")
	}
	// One window either side.
	now := time.Now().Unix()
	if !verifyTOTP(secret, totp.At(now-30)) {
		t.Error("the previous window's code must verify (clock drift)")
	}
	if !verifyTOTP(secret, totp.At(now+30)) {
		t.Error("the next window's code must verify (clock drift)")
	}
	// Two windows out is too far.
	if verifyTOTP(secret, totp.At(now+120)) {
		t.Error("a far-future code must not verify")
	}
	if verifyTOTP(secret, "000000") && totp.Now() != "000000" {
		t.Error("a wrong code must not verify")
	}
	if verifyTOTP(secret, "") || verifyTOTP("", "123456") {
		t.Error("empty secret or code must not verify")
	}
}

// Enrolment must be verified server-side. The browser check alone could enrol a
// secret the admin cannot produce codes for, locking them out permanently.
func TestSetTwoFactorRoundTrip(t *testing.T) {
	newAdminDB(t)
	us := &UserService{}
	db := database.GetDB()

	super := &model.User{}
	if err := db.Model(model.User{}).Order("id asc").First(super).Error; err != nil {
		t.Fatalf("no admin: %v", err)
	}
	if super.TwoFactorEnable {
		t.Fatal("a fresh admin must not have 2FA on")
	}

	const secret = "JBSWY3DPEHPK3PXP"
	if err := us.SetTwoFactor(super.Id, true, secret); err != nil {
		t.Fatalf("SetTwoFactor: %v", err)
	}
	reloaded := &model.User{}
	if err := db.Model(model.User{}).Where("id = ?", super.Id).First(reloaded).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.TwoFactorEnable || reloaded.TwoFactorToken != secret {
		t.Errorf("2FA not stored: enable=%v token=%q", reloaded.TwoFactorEnable, reloaded.TwoFactorToken)
	}

	// Enabling without a secret is refused: it would lock the admin out of an
	// account whose second factor nothing can satisfy.
	if err := us.SetTwoFactor(super.Id, true, ""); err == nil {
		t.Error("enabling 2FA with no secret must be refused")
	}

	// Disabling must clear the secret, not just the flag: a stale secret would come
	// back to life the next time 2FA was turned on.
	if err := us.SetTwoFactor(super.Id, false, ""); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := db.Model(model.User{}).Where("id = ?", super.Id).First(reloaded).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.TwoFactorEnable || reloaded.TwoFactorToken != "" {
		t.Errorf("2FA not cleared: enable=%v token=%q", reloaded.TwoFactorEnable, reloaded.TwoFactorToken)
	}
}

// A password change is the documented recovery route for a lost authenticator, so
// it must clear THIS admin's 2FA, and only theirs. It used to wipe the panel-wide
// setting, disabling 2FA for everyone whenever anyone renamed themselves.
func TestUpdateUserClearsOnlyOwnTwoFactor(t *testing.T) {
	s := newAdminDB(t)
	us := &UserService{}
	db := database.GetDB()

	other, err := s.AddAdmin(AdminSpec{Username: "other", Password: "pw", Enable: true})
	if err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	super := &model.User{}
	db.Model(model.User{}).Where("is_super_admin = ?", true).First(super)

	const secret = "JBSWY3DPEHPK3PXP"
	if err := us.SetTwoFactor(super.Id, true, secret); err != nil {
		t.Fatalf("SetTwoFactor super: %v", err)
	}
	if err := us.SetTwoFactor(other.Id, true, secret); err != nil {
		t.Fatalf("SetTwoFactor other: %v", err)
	}

	// The super admin changes their own credentials.
	if err := us.UpdateUser(super.Id, "renamed", "newpw"); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	reloaded := &model.User{}
	db.Model(model.User{}).Where("id = ?", super.Id).First(reloaded)
	if reloaded.TwoFactorEnable || reloaded.TwoFactorToken != "" {
		t.Error("a credential change must clear that admin's own 2FA")
	}
	otherReloaded := &model.User{}
	if err := db.Model(model.User{}).Where("id = ?", other.Id).First(otherReloaded).Error; err != nil {
		t.Fatalf("reload other (id=%d): %v", other.Id, err)
	}
	if !otherReloaded.TwoFactorEnable || otherReloaded.TwoFactorToken != secret {
		t.Errorf("one admin's credential change must NOT touch another admin's 2FA: other(id=%d) enable=%v token=%q",
			other.Id, otherReloaded.TwoFactorEnable, otherReloaded.TwoFactorToken)
	}
}

// Enable carries gorm:"default:1", and GORM omits a zero-valued field that has a
// default from the INSERT, letting the DB default win. That silently created a
// "disabled" admin who could log in. Pins the Select("*") that fixes it.
func TestAddAdminDisabledActuallyPersists(t *testing.T) {
	s := newAdminDB(t)

	user, err := s.AddAdmin(AdminSpec{Username: "disabled", Password: "pw", Enable: false})
	if err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	row := &model.User{}
	if err := database.GetDB().Model(model.User{}).Where("id = ?", user.Id).First(row).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if row.Enable {
		t.Error("an admin created disabled is stored ENABLED and could log in")
	}
	// The whole point of the flag: a disabled account can do nothing.
	if row.Can(model.PermAccessInbounds) {
		t.Error("a disabled admin must not hold any permission")
	}

	// And the normal case still works. A FRESH struct: GORM infers a primary-key
	// condition from a non-zero destination, so reusing `row` would silently match
	// nothing and leave the previous values in place.
	enabled, err := s.AddAdmin(AdminSpec{Username: "enabled", Password: "pw", Enable: true})
	if err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	enabledRow := &model.User{}
	if err := database.GetDB().Model(model.User{}).Where("id = ?", enabled.Id).First(enabledRow).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !enabledRow.Enable {
		t.Error("an admin created enabled is stored DISABLED")
	}
}

// The old panel-wide TOTP secret is migrated onto the super admin, which makes it
// that admin's LIVE second factor. GetAllSetting serves the whole settings table
// to anyone holding accessPanelSettings, so the shared copy must not survive the
// migration or a sub-admin can read the super admin's TOTP and pass their 2FA.
func TestMigratedGlobalTwoFactorSecretIsNotServed(t *testing.T) {
	newAdminDB(t)
	db := database.GetDB()
	ss := SettingService{}

	// Reproduce a pre-upgrade panel with the global 2FA turned on.
	const secret = "JBSWY3DPEHPK3PXP"
	if err := ss.SetTwoFactorEnable(true); err != nil {
		t.Fatalf("seed twoFactorEnable: %v", err)
	}
	if err := ss.SetTwoFactorToken(secret); err != nil {
		t.Fatalf("seed twoFactorToken: %v", err)
	}
	// Nobody owns it yet, which is the pre-upgrade shape.
	db.Model(model.User{}).Where("1 = 1").Update("two_factor_enable", false)

	database.MigrateGlobalTwoFactorForTest()

	// It must have landed on the super admin...
	super := &model.User{}
	if err := db.Model(model.User{}).Where("is_super_admin = ?", true).First(super).Error; err != nil {
		t.Fatalf("no super admin: %v", err)
	}
	if !super.TwoFactorEnable || super.TwoFactorToken != secret {
		t.Fatalf("2FA did not migrate onto the super admin: enable=%v token=%q",
			super.TwoFactorEnable, super.TwoFactorToken)
	}

	// ...and the shared copy must be gone, or every admin who can read settings
	// holds the super admin's second factor.
	all, err := ss.GetAllSetting()
	if err != nil {
		t.Fatalf("GetAllSetting: %v", err)
	}
	if all.TwoFactorToken == secret {
		t.Error("GetAllSetting still serves the migrated TOTP secret: any admin with " +
			"panel-settings access can pass the super admin's 2FA")
	}
	if all.TwoFactorEnable {
		t.Error("the stale global twoFactorEnable survived the migration")
	}
}

// The upgrade path for a permission bit that did not exist yesterday. Every admin
// could open the overview while it was ungated, so the bit that now gates it has to
// be handed to the admins who predate it. Without this a plain upgrade-and-restart
// takes the panel's home page away from every non-super admin, silently, because a
// new bit reads as 0 on every row already in the database.
func TestMigrationOverviewAccessBackfillsExistingAdmins(t *testing.T) {
	s := newAdminDB(t)
	db := database.GetDB()

	// A delegated admin as it exists before the bit, a reseller (whose mask Can()
	// ignores in favour of their profile), and the seeded super admin.
	admin := &model.User{Username: "delegate", Enable: true, Permissions: model.PermAccessInbounds}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("seeding the admin: %v", err)
	}
	seller := &model.User{Username: "seller", Enable: true, IsReseller: true}
	if err := db.Create(seller).Error; err != nil {
		t.Fatalf("seeding the reseller: %v", err)
	}

	s.MigrationOverviewAccess()

	reload := func(id int) *model.User {
		t.Helper()
		u := &model.User{}
		if err := db.Model(model.User{}).Where("id = ?", id).First(u).Error; err != nil {
			t.Fatalf("reading user %d: %v", id, err)
		}
		return u
	}

	got := reload(admin.Id)
	if !got.Permissions.Has(model.PermAccessOverview) {
		t.Error("the existing admin did not get the overview permission, so the upgrade took the page away")
	}
	// OR'ed in SQL rather than written wholesale, so what they already held survives.
	if !got.Permissions.Has(model.PermAccessInbounds) {
		t.Error("the backfill overwrote the admin's other permissions instead of adding to them")
	}
	if p := reload(seller.Id).Permissions; p != 0 {
		t.Errorf("the reseller's mask was written (%d); their profile booleans are the source of truth", p)
	}
	if p := reload(1).Permissions; p != 0 {
		t.Errorf("the super admin's mask was written (%d); they bypass it entirely", p)
	}

	// The guard. An operator who takes the permission back must keep it taken back,
	// which is why this is marked in the settings table rather than inferred from
	// "does anybody hold the bit": every restart looks like the first one otherwise.
	var settingService SettingService
	if !settingService.GetOverviewAccessBackfilled() {
		t.Fatal("the backfill did not record that it ran, so it repeats on every restart")
	}
	if err := db.Model(model.User{}).Where("id = ?", admin.Id).
		Update("permissions", model.PermAccessInbounds).Error; err != nil {
		t.Fatalf("simulating the revoke: %v", err)
	}
	s.MigrationOverviewAccess()
	if reload(admin.Id).Permissions.Has(model.PermAccessOverview) {
		t.Error("a revoked overview permission was granted again on the next start")
	}
}
