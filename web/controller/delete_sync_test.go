package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/web/service"

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

	// A SECOND client, so the inbound is not left empty by the delete under test.
	// It used to be REQUIRED (the panel refused to remove the last client of an
	// inbound), and it is kept because it makes the assertion sharper: the account
	// pruned below is the deleted one and not "whatever was left".
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

// D3: renaming a client carries the ONE account onto the new email.
//
// The rename used to SPLIT the customer. UpdateInboundClient rewrote the inbound it
// was posted against, then the membership apply ran under the NEW email, found no
// account for that key, created a second one, and projected it ALONGSIDE the old
// entries instead of over them. The previous email was left behind as a live,
// working, billable account on every other inbound, under a customer who had been
// renamed away.
func TestRenamingAClientCarriesItsAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newIdorFixture(t)
	db := database.GetDB()

	// A SECOND inbound serving the same account, which is where the split showed:
	// the posted inbound was always rewritten correctly, the others were not.
	second := &model.Inbound{
		UserId: f.ali.Id, Tag: "inbound-41003", Port: 41003, Protocol: model.VMESS, Enable: true,
		Settings: `{"clients":[{"id":"ali-uuid","email":"ali-client","enable":true}]}`,
	}
	if err := db.Create(second).Error; err != nil {
		t.Fatalf("create the second inbound: %v", err)
	}
	if err := db.Create(&model.InboundAccess{UserId: f.ali.Id, InboundId: second.Id}).Error; err != nil {
		t.Fatalf("grant access: %v", err)
	}

	accounts := service.AccountService{}
	for _, id := range []int{f.aliInbound.Id, second.Id} {
		if err := accounts.SyncInboundAccounts(db, id); err != nil {
			t.Fatalf("seed the accounts layer: %v", err)
		}
	}
	before, err := accounts.GetAccountByEmail(f.aliEmail)
	if err != nil || before == nil {
		t.Fatalf("setup: no account for the old email: %v", err)
	}

	body := "id=" + fmt.Sprint(f.aliInbound.Id) +
		"&settings=" + url.QueryEscape(`{"clients":[{"id":"ali-uuid","email":"renamed-client","enable":true}]}`)
	w := f.as(t, f.ali, http.MethodPost, "/panel/api/inbounds/updateClient/ali-uuid", body)
	if !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("rename did not happen: %s", w.Body.String())
	}

	// ONE account, the same row, under the new email.
	var all []model.Account
	if err := db.Find(&all).Error; err != nil {
		t.Fatalf("read accounts: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("accounts = %d, want 1: the rename minted a second customer and left the first live", len(all))
	}
	if all[0].Id != before.Id || all[0].Email != "renamed-client" {
		t.Errorf("account = {id:%d email:%q}, want the original row carried to renamed-client", all[0].Id, all[0].Email)
	}
	if old, _ := accounts.GetAccountByEmail(f.aliEmail); old != nil {
		t.Error("the old email is still an account: a working client that nobody is billed for")
	}

	// And no inbound is left serving the old email.
	for _, id := range []int{f.aliInbound.Id, second.Id} {
		var stored model.Inbound
		if err := db.Where("id = ?", id).First(&stored).Error; err != nil {
			t.Fatalf("reload inbound %d: %v", id, err)
		}
		if strings.Contains(stored.Settings, f.aliEmail) {
			t.Errorf("inbound %d still carries the old email: %s", id, stored.Settings)
		}
		if !strings.Contains(stored.Settings, "renamed-client") {
			t.Errorf("inbound %d never got the new email: %s", id, stored.Settings)
		}
	}
}
