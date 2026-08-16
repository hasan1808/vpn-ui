package controller

import (
	"errors"
	"strconv"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/web/session"

	"github.com/gin-gonic/gin"
)

// errRechargeRange refuses an amount that cannot be turned into bytes without
// wrapping. See maxRechargeGB.
var errRechargeRange = errors.New("that recharge amount is out of range")

// maxRechargeGB bounds one recharge. The conversion to bytes overflows int64
// somewhere above 8.5e9 GB, and a wrapped top-up reads as a huge deduction that
// clamps the allowance to zero, so an absurd number is rejected rather than
// quietly emptying a reseller's balance.
const maxRechargeGB = int64(1) << 30

// resellerForm is the add/edit payload. Bound by `form` tag through ShouldBind for
// the same reason adminForm is: axios Qs.stringify's every body, so none of this
// ever arrives as JSON.
type resellerForm struct {
	Username string `json:"username" form:"username"`
	// Password empty on update means "keep the existing one", which is what lets the
	// edit modal open without the panel ever shipping a hash to the browser.
	Password string `json:"password" form:"password"`
	Nickname string `json:"nickname" form:"nickname"`
	Enable   bool   `json:"enable" form:"enable"`

	Unlimited bool `json:"unlimited" form:"unlimited"`
	// AllowanceGB seeds the balance on create and is ignored on update, where
	// Recharge is the only way to move it. The field is still bound on both paths so
	// one modal can post one shape.
	AllowanceGB int `json:"allowanceGb" form:"allowanceGb"`

	DaysPerGB          int  `json:"daysPerGb" form:"daysPerGb"`
	MinCreateGB        int  `json:"minCreateGb" form:"minCreateGb"`
	MinAddGB           int  `json:"minAddGb" form:"minAddGb"`
	AllowExternalProxy bool `json:"allowExternalProxy" form:"allowExternalProxy"`
	// AllowOverview hands this reseller the panel overview, which is off by
	// default because it is a host dashboard and none of it is theirs to act on.
	AllowOverview bool `json:"allowOverview" form:"allowOverview"`
	// AllowOverviewManage turns that overview from a showcase into a page that can
	// act. No effect unless AllowOverview is on.
	AllowOverviewManage bool `json:"allowOverviewManage" form:"allowOverviewManage"`

	// InboundIds arrives as repeated `inboundIds` keys (Qs arrayFormat:'repeat').
	// A blank entry is how the UI sends "none": an omitted field would bind as nil
	// and could not be told apart from "leave alone".
	InboundIds []string `json:"inboundIds" form:"inboundIds"`
}

// inboundIds parses the wire form's ids, dropping blanks and unparseable entries
// rather than failing the whole save over one bad value.
func (f *resellerForm) inboundIds() []int {
	out := make([]int, 0, len(f.InboundIds))
	for _, raw := range f.InboundIds {
		if raw == "" {
			continue
		}
		if id, err := strconv.Atoi(raw); err == nil && id > 0 {
			out = append(out, id)
		}
	}
	return out
}

// spec maps the wire form onto the service's shape.
func (f *resellerForm) spec() service.ResellerSpec {
	return service.ResellerSpec{
		Username:            f.Username,
		Password:            f.Password,
		Nickname:            f.Nickname,
		Enable:              f.Enable,
		AllowanceGB:         f.AllowanceGB,
		Unlimited:           f.Unlimited,
		DaysPerGB:           f.DaysPerGB,
		MinCreateGB:         f.MinCreateGB,
		MinAddGB:            f.MinAddGB,
		AllowExternalProxy:  f.AllowExternalProxy,
		AllowOverview:       f.AllowOverview,
		AllowOverviewManage: f.AllowOverviewManage,
		InboundIds:          f.inboundIds(),
	}
}

// rechargeForm moves a reseller's allowance by whole GB. Signed on purpose: an
// admin takes balance back with a negative number, and the service clamps the
// resulting allowance at zero.
type rechargeForm struct {
	GB int64 `json:"gb" form:"gb"`
}

// deltaBytes converts to the unit every balance in the ledger is kept in.
func (f *rechargeForm) deltaBytes() (int64, error) {
	if f.GB > maxRechargeGB || f.GB < -maxRechargeGB {
		return 0, errRechargeRange
	}
	return f.GB * 1024 * 1024 * 1024, nil
}

// ResellerController serves the Resellers CRUD. Every route is gated on
// PermManageResellers by the group below, not by the handlers.
//
// Unlike admin.go there is no self-demote or self-delete guard, and none is
// possible: resellerPerms (database/model/permission.go) excludes
// PermManageResellers and a reseller's mask is DERIVED from the role, so a
// reseller can never hold the bit that reaches these routes. The caller is always
// someone else.
//
// What does need guarding is the caller's reach across other admins, and that
// lives one layer down in the service: AssignableInbounds and assertAssignable
// intersect with the caller's own grants, and manageable() scopes every :id to the
// resellers they created. The middleware here only proves they may open the page.
type ResellerController struct {
	BaseController

	resellerService service.ResellerService
}

// NewResellerController creates a ResellerController and initializes its routes.
func NewResellerController(g *gin.RouterGroup) *ResellerController {
	a := &ResellerController{}
	a.initRouter(g)
	return a
}

func (a *ResellerController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/resellers")
	g.Use(requirePerm(model.PermManageResellers))

	g.GET("/list", a.list)
	g.GET("/inbounds", a.inbounds)
	g.POST("/add", a.add)
	g.POST("/update/:id", a.update)
	g.POST("/del/:id", a.del)
	g.POST("/recharge/:id", a.recharge)
}

func (a *ResellerController) list(c *gin.Context) {
	resellers, err := a.resellerService.GetResellers(session.GetLoginUser(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.title"), err)
		return
	}
	jsonObj(c, resellers, nil)
}

// inbounds is the checklist a reseller may be given access to. NOT the panel-wide
// list the Admins page serves: this route is reachable by a non-super admin, so
// the set is intersected with what the caller holds themselves. Rendering the
// intersection is only half of it, the save re-checks (see assertAssignable).
func (a *ResellerController) inbounds(c *gin.Context) {
	list, err := a.resellerService.AssignableInbounds(session.GetLoginUser(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.title"), err)
		return
	}
	jsonObj(c, list, nil)
}

func (a *ResellerController) add(c *gin.Context) {
	form := &resellerForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.add"), err)
		return
	}
	_, err := a.resellerService.AddReseller(session.GetLoginUser(c), form.spec())
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.add"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.resellers.add"), nil)
}

func (a *ResellerController) update(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.edit"), err)
		return
	}
	form := &resellerForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.edit"), err)
		return
	}
	err = a.resellerService.UpdateReseller(session.GetLoginUser(c), id, form.spec())
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.edit"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.resellers.edit"), nil)
}

// delResellerForm carries the UI's choice when the reseller still owns accounts:
// "keep" hands them to the house, "cascade" deletes them. Empty still refuses, so
// the destructive path is never the default.
type delResellerForm struct {
	Mode string `json:"mode" form:"mode"`
}

func (a *ResellerController) del(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.del"), err)
		return
	}
	form := &delResellerForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.del"), err)
		return
	}
	res, err := a.resellerService.DeleteReseller(session.GetLoginUser(c), id, form.Mode)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.del"), err)
		return
	}
	reconfigureAfterCascade(res)
	jsonMsg(c, I18nWeb(c, "pages.resellers.del"), nil)
}

// reconfigureAfterCascade regenerates and restarts the daemons whose clients a
// cascade delete removed, reusing InboundController's per-protocol change hooks so
// the reconfigure sequence lives in one place (and matches the single-client
// delete route exactly). A zero-value InboundController is how NewInboundController
// builds it too: every service field it uses is a stateless value type.
func reconfigureAfterCascade(res service.DeleteResult) {
	if len(res.Protocols) == 0 && !res.NeedXrayRestart {
		return
	}
	ic := &InboundController{}
	for proto := range res.Protocols {
		switch proto {
		case model.L2TP:
			ic.onL2tpChanged()
		case model.PPTP:
			ic.onPptpChanged()
		case model.OPENVPN:
			ic.onOpenVpnChanged()
		case model.OPENCONNECT:
			ic.onOcservChanged()
		case model.SSTP:
			ic.onSstpChanged()
		case model.IKEV2:
			ic.onIkev2Changed()
		case model.WGC:
			ic.onWgcChanged()
		case model.AWG:
			ic.onAwgChanged()
		case model.GRE:
			ic.onGreChanged()
		case model.MTPROTO:
			ic.onMtprotoChanged()
		case model.SSH:
			ic.onSshChanged()
			// Native Xray protocols (vmess/vless/trojan/shadowsocks/wireguard) have no
			// daemon; the live RemoveUser already ran, so NeedXrayRestart covers them.
		}
	}
	if res.NeedXrayRestart {
		ic.xrayService.SetToNeedRestart()
	}
}

// recharge is its own route rather than a field on the edit form because the
// allowance is a running total: an admin typing over it would rewrite history and
// either free or strand every account already sold against it.
func (a *ResellerController) recharge(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.recharge"), err)
		return
	}
	form := &rechargeForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.recharge"), err)
		return
	}
	delta, err := form.deltaBytes()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.recharge"), err)
		return
	}
	if err := a.resellerService.Recharge(session.GetLoginUser(c), id, delta); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.resellers.recharge"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.resellers.recharge"), nil)
}
