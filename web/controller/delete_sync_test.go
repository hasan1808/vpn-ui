package controller

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
)

// The add and edit paths mirror into the accounts layer; the DELETE paths did
// not. Found on a live panel: deleting a client removed it from
// settings.clients (so the data plane was correct) while leaving its account row
// and every membership behind. The tables drifted, InboundIdsForEmail reported
// inbounds the account was no longer served on, and `vpn-ui revert-accounts` was
// blocked forever by a phantom multi-membership account that existed nowhere in
// settings.
func TestDeletingAClientPrunesItsAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newIdorFixture(t)

	// A SECOND client, because DelInboundClient refuses to remove the last one
	// ("no client remained in Inbound"). Without it the delete never happens and
	// this test would pass by doing nothing.
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", f.aliInbound.Id).
		Update("settings", `{"clients":[`+
			`{"id":"ali-uuid","email":"ali-client","enable":true},`+
			`{"id":"keep-uuid","email":"keep-client","enable":true}]}`).Error; err != nil {
		t.Fatalf("seed a second client: %v", err)
	}

	accounts := service.AccountService{}
	if err := accounts.SyncInboundAccounts(database.GetDB(), f.aliInbound.Id); err != nil {
		t.Fatalf("seed the accounts layer: %v", err)
	}
	if got, _ := accounts.InboundIdsForEmail(f.aliEmail); len(got) != 1 {
		t.Fatalf("setup: memberships = %v, want 1", got)
	}

	w := f.as(t, f.ali, http.MethodPost,
		fmt.Sprintf("/panel/api/inbounds/%d/delClientByEmail/%s", f.aliInbound.Id, f.aliEmail), "")
	// A denial in this panel is 200 with success:false, so the body is the check.
	if !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("delete did not happen: %s", w.Body.String())
	}

	ids, err := accounts.InboundIdsForEmail(f.aliEmail)
	if err != nil {
		t.Fatalf("InboundIdsForEmail: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("memberships = %v, want none: the account outlived the client it described", ids)
	}
	acct, err := accounts.GetAccountByEmail(f.aliEmail)
	if err != nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	if acct != nil {
		t.Error("the account row survived with no membership, which blocks revert-accounts forever")
	}
	// The account that was NOT deleted must survive untouched.
	if kept, _ := accounts.GetAccountByEmail("keep-client"); kept == nil {
		t.Error("the neighbouring account was pruned too")
	}
}

// Deleting the inbound itself must drop every membership pointing at it.
func TestDeletingAnInboundDropsItsMemberships(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newIdorFixture(t)

	accounts := service.AccountService{}
	if err := accounts.SyncInboundAccounts(database.GetDB(), f.aliInbound.Id); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := f.as(t, f.ali, http.MethodPost,
		fmt.Sprintf("/panel/api/inbounds/del/%d", f.aliInbound.Id), "")
	if w.Code != http.StatusOK {
		t.Fatalf("delete returned %d: %s", w.Code, w.Body.String())
	}

	var left int64
	if err := database.GetDB().Model(&model.AccountInbound{}).
		Where("inbound_id = ?", f.aliInbound.Id).Count(&left).Error; err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if left != 0 {
		t.Errorf("%d membership(s) still point at a deleted inbound", left)
	}
}
