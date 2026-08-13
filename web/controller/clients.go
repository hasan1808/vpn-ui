package controller

import (
	"strconv"

	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// The Clients page: the account-centric view of who exists, as opposed to the
// Inbounds page's view of what serves them.
//
// READ ONLY. Every mutation the page performs goes back through the existing
// client routes on /panel/api/inbounds (addClient, updateClient,
// delClientByEmail, bulkUpdateClients) carrying an inboundIds set. That is
// deliberate: those paths already carry the reseller pricing, the ownership
// assertions over every id, the same-protocol refusal and the projection, and a
// second write path would be a second place for all of that to drift out of step.
type ClientsController struct {
	BaseController
}

func NewClientsController(g *gin.RouterGroup) *ClientsController {
	a := &ClientsController{}
	a.initRouter(g)
	return a
}

func (a *ClientsController) initRouter(g *gin.RouterGroup) {
	// accessInbounds, the same claim the Inbounds page takes: this shows the same
	// accounts from the other side, so a caller who may see one may see the other.
	// The rows are then narrowed per caller inside ListAccounts.
	g.GET("/list", a.list)
	g.GET("/assignable", a.assignable)
}

// list returns one page of accounts the caller may see.
//
// The scoping lives in the service and is the whole security surface here: the
// accounts and memberships tables are panel-wide, so an unscoped read would hand
// every admin every other admin's customers and every reseller every other
// seller's. Passing the login user rather than a flag keeps that decision in one
// place.
func (a *ClientsController) list(c *gin.Context) {
	page, _ := strconv.Atoi(c.Query("page"))
	size, _ := strconv.Atoi(c.Query("size"))
	result, err := accountService.ListAccounts(session.GetLoginUser(c), page, size, c.Query("search"), c.Query("status"), c.Query("sort"), c.Query("protocol"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, result, nil)
}

// assignable lists the inbounds the caller may put an account on, for the page's
// inbound picker.
//
// Filtered by the same grant the write path enforces, so the picker cannot offer
// an inbound the save would then refuse: an operator ticking a box and getting
// "not found" back with no explanation is the worst version of this.
func (a *ClientsController) assignable(c *gin.Context) {
	rows, err := accountService.AssignableInboundsFor(session.GetLoginUser(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, rows, nil)
}
