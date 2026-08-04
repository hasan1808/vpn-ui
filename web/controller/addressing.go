package controller

import (
	"strconv"

	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
)

// Read-only endpoints over the VPN address plane. See web/service/vpnaddressing.go for
// why these exist at all: the pool, the slot and the resulting tunnel address are all
// decided by the panel and none of them were readable, so an API caller had to
// reimplement the allocator to find out what it had been given.
//
// Handlers live here rather than in inbound.go to keep that file's diff to the two
// route registrations, but they are methods on InboundController on purpose: the
// ownership seam (callerOwnsInbound, filterInboundForCaller) is already solved there and
// a second copy of it is exactly the kind of thing that drifts into an IDOR.

// getInboundAddressing reports one inbound's pool, its User Limit resolution and every
// account's slot and tunnel address(es).
//
// Route gating is `read` plus `owns`, so a reseller granted the inbound reaches it. What
// they get back is narrowed to their own accounts by filterInboundForCaller BEFORE the
// report is built, which is the only reason this is safe to expose: the addresses come
// from a panel-wide map, and an unfiltered report would hand a reseller the tunnel
// address of every other seller's customer on a shared inbound.
func (a *InboundController) getInboundAddressing(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	inbound, err := a.inboundService.GetInbound(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), err)
		return
	}
	// Fails closed: an ownership question the panel cannot answer is a refusal, never
	// an unfiltered answer.
	if !a.filterInboundForCaller(c, inbound) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}

	report, ok := service.InboundAddressing(inbound)
	if !ok {
		// Not an error: mtproto, ssh and every Xray-native protocol hand out no client
		// address at all. Saying so plainly beats an empty pool a caller would read as
		// "misconfigured".
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"),
			common.NewErrorf("protocol %q hands out no client address, so it has no address pool", inbound.Protocol))
		return
	}
	jsonObj(c, report, nil)
}

// getVpnPools reports which /24 of the VPN address space each inbound holds.
//
// Gated on createInbound rather than on the read bit, and that is deliberate on both
// counts. The map is what an operator consults before hand-picking a range, so it
// belongs to whoever may create an inbound; and because a reseller's mask is DERIVED
// from their role and carries no *Inbound bit beyond access, gating it this way excludes
// them by construction rather than by a check someone could later forget. They must not
// have it: the map names every inbound on the box, including the ones they were never
// granted, with its remark.
func (a *InboundController) getVpnPools(c *gin.Context) {
	jsonObj(c, service.VpnPoolOccupancy(), nil)
}
