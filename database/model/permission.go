package model

// Permission is a bitmask of what an admin may do, stored as an integer column on
// User. A super admin bypasses the mask entirely and is the only one who may
// manage other admins.
//
// The bitmask is a storage detail. Slugs (below) are what cross the wire to the
// API and the UI, so bits may be reordered freely but a slug rename is breaking.
type Permission int64

const (
	PermAccessInbounds Permission = 1 << iota
	PermCreateInbound
	PermEditInbound
	PermDeleteInbound
	PermCreateClient
	PermEditClient
	PermDeleteClient
	PermBulkOperation
	PermCoreSettings
	PermXraySettings
	PermPanelSettings
	// PermManageResellers gates the Resellers page and its API. APPENDED, never
	// inserted: the values are positional, so inserting a bit would shift every
	// mask already stored in the database by one.
	PermManageResellers
	// PermOverviewManage turns the overview from a read-only showcase into a page
	// that can act. Seeing the overview used to be ungated (it was where a denial
	// redirects to), so before this bit existed anyone who could log in was offered
	// its whole management column and found out which parts they held by clicking
	// and reading the refusal.
	//
	// It scopes a PAGE, not a capability: every action it reveals still needs its
	// own bit underneath, and this one grants none of them on its own. Deliberately
	// reaches nothing escalation-class either -- backup, restore, DB export/import,
	// logs, config.json and the panel update stay super-admin-only and stay hidden,
	// because those hand over the panel outright and no delegated bit should.
	//
	// APPENDED, for the reason above.
	PermOverviewManage
	// PermAccessOverview gates the overview page itself, which nothing gated before:
	// the overview is a HOST dashboard (kernel, CPU, disk, public IP, panel updates)
	// and an admin who only sells accounts has no business reading it.
	//
	// It stayed ungated only because deny() redirected every refusal to it, so gating
	// it would have looped. That is why this bit could not be added without a landing
	// page resolver first (see landingPath in web/controller/permission.go), which
	// sends a denial to the first page the caller can actually open and refuses
	// outright rather than redirecting when there is none.
	//
	// Deliberately NOT implied by PermOverviewManage, and it does not imply it
	// either: they are two answers ("may this page be opened", "may it act") and each
	// action behind the second still needs its own bit underneath.
	//
	// A reseller never holds this. Can() derives their whole mask from resellerPerms
	// and ignores the stored column, so their AllowOverview / AllowOverviewManage
	// profile booleans stay the source of truth for the role; the two columns are
	// resolved into one slug map for templates in web/controller/util.go.
	//
	// APPENDED, for the reason above.
	PermAccessOverview
)

// resellerPerms is what a reseller may do, derived from the role rather than
// read from User.Permissions.
//
// Derived on purpose. A stored mask drifts: an ImportDB of a hand-edited backup,
// or one save path that forgets to clamp, leaves a reseller holding
// PermPanelSettings and nothing in the code notices. Deriving makes the role the
// single source of truth.
//
// Deliberately excludes every *Inbound bit: a reseller sells accounts on inbounds
// an admin assigned them, and creates none of its own.
//
// PermBulkOperation IS included, but it does not mean here what it means for an
// admin. The bulk routes are defined over "every client on this inbound", which
// for a reseller reaches accounts they do not own, so each one is separately
// scoped to their own accounts and priced against their balance
// (ResellerService.PrepareBulk). The two that cannot be scoped that way,
// resetAllTraffics and resetAllClientTraffics, stay refused in the controller.
// The bit is the door; it is not the authorization.
const resellerPerms = PermAccessInbounds | PermCreateClient | PermEditClient |
	PermDeleteClient | PermBulkOperation

// PermissionDef pairs a bit with its stable wire slug.
type PermissionDef struct {
	Bit  Permission `json:"-"`
	Slug string     `json:"slug"`
}

// AllPermissions is the canonical list, in the order the Admins UI renders it.
//
// Slice order is RENDER order and is independent of bit position, which is why the
// two overview entries sit together at the end while their bits are appended: the
// pair reads as one group in the checkbox column ("may open it", "may act on it")
// even though inserting either bit would have shifted every stored mask.
var AllPermissions = []PermissionDef{
	{PermAccessInbounds, "accessInbounds"},
	{PermCreateInbound, "createInbound"},
	{PermEditInbound, "editInbound"},
	{PermDeleteInbound, "deleteInbound"},
	{PermCreateClient, "createClient"},
	{PermEditClient, "editClient"},
	{PermDeleteClient, "deleteClient"},
	{PermBulkOperation, "bulkOperation"},
	{PermCoreSettings, "accessCoreSettings"},
	{PermXraySettings, "accessXraySettings"},
	{PermPanelSettings, "accessPanelSettings"},
	{PermManageResellers, "manageResellers"},
	{PermAccessOverview, "accessOverview"},
	{PermOverviewManage, "manageOverview"},
}

// Has reports whether every bit in q is set in p.
func (p Permission) Has(q Permission) bool { return p&q == q }

// Slugs expands the mask into its wire slugs, for the API and the UI.
func (p Permission) Slugs() []string {
	out := make([]string, 0, len(AllPermissions))
	for _, d := range AllPermissions {
		if p.Has(d.Bit) {
			out = append(out, d.Slug)
		}
	}
	return out
}

// PermissionsFromSlugs folds wire slugs back into a mask. Unknown slugs are
// ignored rather than erroring: a client sending a stale slug should lose that
// one permission, not have the whole save rejected.
func PermissionsFromSlugs(slugs []string) Permission {
	var p Permission
	for _, s := range slugs {
		for _, d := range AllPermissions {
			if d.Slug == s {
				p |= d.Bit
				break
			}
		}
	}
	return p
}

// Can reports whether the user may do perm. Super admins may do anything, which
// is why they are the only account type that can reach the escalation-class
// endpoints (DB export/import, panel update, systemd unit, host reboot).
func (u *User) Can(perm Permission) bool {
	if u == nil || !u.Enable {
		return false
	}
	if u.IsSuperAdmin {
		return true
	}
	// A reseller's stored mask is ignored entirely, so a stale or tampered
	// permissions column cannot widen the role.
	if u.IsReseller {
		return resellerPerms.Has(perm)
	}
	return u.Permissions.Has(perm)
}
