package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// The addressing endpoint answers with account emails and the tunnel addresses they
// hold, which is exactly the shape of data a shared inbound must not spill sideways.
// Its route gating (read + owns) is not enough on its own: a reseller legitimately
// holds the read bit and is legitimately granted the inbound, and the addresses come
// from a PANEL-WIDE map. What keeps it safe is the filter applied before the report is
// built, so these cases pin that rather than the route table.

// addressingBody decodes the response envelope of an addressing call.
func addressingBody(t *testing.T, raw []byte) (success bool, report struct {
	Protocol string `json:"protocol"`
	Subnets  []string
	Accounts []struct {
		Email     string   `json:"email"`
		Slot      int      `json:"slot"`
		Addresses []string `json:"addresses"`
	} `json:"accounts"`
}) {
	t.Helper()
	var envelope struct {
		Success bool            `json:"success"`
		Msg     string          `json:"msg"`
		Obj     json.RawMessage `json:"obj"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode envelope: %v\n%s", err, raw)
	}
	if envelope.Success && len(envelope.Obj) > 0 {
		if err := json.Unmarshal(envelope.Obj, &report); err != nil {
			t.Fatalf("decode report: %v\n%s", err, envelope.Obj)
		}
	}
	return envelope.Success, report
}

// makeAliInboundAddressed turns the fixture's inbound into an l2tp one with a real pool
// and two accounts, so there is something with addresses to leak.
func makeAliInboundAddressed(t *testing.T, f *idorFixture, extraEmail string) {
	t.Helper()
	settings := fmt.Sprintf(`{"ipRanges":["10.0.44.2-10.0.44.254"],"userLimit":1,"clients":[`+
		`{"id":"ali-client","password":"pw1","email":"%s","enable":true,"slot":0},`+
		`{"id":"%s","password":"pw2","email":"%s","enable":true,"slot":1}]}`,
		f.aliEmail, extraEmail, extraEmail)
	if err := database.GetDB().Model(model.Inbound{}).Where("id = ?", f.aliInbound.Id).
		Updates(map[string]any{"protocol": string(model.L2TP), "settings": settings}).Error; err != nil {
		t.Fatalf("re-seed Ali's inbound as l2tp: %v", err)
	}
}

// seedResellerOn creates a reseller granted the given inbound and owning one account on
// it, mirroring the production shape the IDOR suite already uses.
func seedResellerOn(t *testing.T, inboundId int, createdBy int, email string) *model.User {
	t.Helper()
	db := database.GetDB()
	// A full stored mask on purpose: Can() derives a reseller's rights from the role,
	// so this column must be inert. If it were read, the reseller would hold
	// createInbound and reach /pools.
	all := model.Permission(0)
	for _, d := range model.AllPermissions {
		all |= d.Bit
	}
	sara := &model.User{Username: "sara-addr", Password: "x", Enable: true, IsReseller: true, Permissions: all}
	if err := db.Create(sara).Error; err != nil {
		t.Fatalf("create reseller: %v", err)
	}
	if err := db.Create(&model.ResellerProfile{UserId: sara.Id, AllowanceBytes: 100 * testGB, CreatedBy: createdBy}).Error; err != nil {
		t.Fatalf("create reseller profile: %v", err)
	}
	if err := db.Create(&model.InboundAccess{UserId: sara.Id, InboundId: inboundId}).Error; err != nil {
		t.Fatalf("grant the reseller the shared inbound: %v", err)
	}
	if err := db.Create(&model.ResellerClient{Email: email, InboundId: inboundId, UserId: sara.Id}).Error; err != nil {
		t.Fatalf("create ownership row: %v", err)
	}
	return sara
}

func TestAddressingIsScopedToTheCaller(t *testing.T) {
	f := newIdorFixture(t)
	const saraEmail = "sara-addr-client"
	makeAliInboundAddressed(t, f, saraEmail)
	sara := seedResellerOn(t, f.aliInbound.Id, f.ali.Id, saraEmail)

	path := fmt.Sprintf("/panel/api/inbounds/%d/addressing", f.aliInbound.Id)

	t.Run("the owning admin sees every account", func(t *testing.T) {
		w := f.as(t, f.ali, http.MethodGet, path, "")
		success, report := addressingBody(t, w.Body.Bytes())
		if !success {
			t.Fatalf("the owner was refused: %s", w.Body.String())
		}
		if len(report.Accounts) != 2 {
			t.Fatalf("want both accounts, got %#v", report.Accounts)
		}
		for _, a := range report.Accounts {
			if len(a.Addresses) == 0 {
				t.Errorf("account %q reported no address", a.Email)
			}
		}
	})

	t.Run("a reseller sees only their own account", func(t *testing.T) {
		w := f.as(t, sara, http.MethodGet, path, "")
		success, report := addressingBody(t, w.Body.Bytes())
		if !success {
			t.Fatalf("the reseller holds the read bit and the grant, so this must succeed: %s", w.Body.String())
		}
		if len(report.Accounts) != 1 {
			t.Fatalf("want exactly the reseller's own account, got %#v", report.Accounts)
		}
		if report.Accounts[0].Email != saraEmail {
			t.Fatalf("the reseller was shown %q, another seller's account on a shared inbound", report.Accounts[0].Email)
		}
		// The pool itself is not secret: it is the inbound's own configuration, and
		// the reseller is granted the inbound.
		if len(report.Subnets) == 0 {
			t.Error("the pool should still be reported")
		}
	})

	t.Run("an admin without the grant is refused", func(t *testing.T) {
		w := f.as(t, f.reza, http.MethodGet, path, "")
		success, report := addressingBody(t, w.Body.Bytes())
		// A denial is 200 + success:false, never 403, so asserting on the status code
		// would pass no matter what this route did.
		if success {
			t.Fatalf("Reza read the addressing of an inbound he was never granted: %#v", report)
		}
		if strings.Contains(w.Body.String(), f.aliEmail) {
			t.Errorf("the refusal leaked an account email: %s", w.Body.String())
		}
	})
}

// The pool map names every inbound on the box, including ones the caller was never
// granted. It is gated on createInbound for that reason, and a reseller's mask is
// DERIVED from their role and carries no *Inbound bit beyond access, so they are
// excluded structurally rather than by a check someone could later drop.
func TestVpnPoolMapIsAdminOnly(t *testing.T) {
	f := newIdorFixture(t)
	const saraEmail = "sara-pool-client"
	makeAliInboundAddressed(t, f, saraEmail)
	sara := seedResellerOn(t, f.aliInbound.Id, f.ali.Id, saraEmail)

	const path = "/panel/api/inbounds/pools"

	t.Run("an admin with createInbound gets the map", func(t *testing.T) {
		w := f.as(t, f.ali, http.MethodGet, path, "")
		var envelope struct {
			Success bool `json:"success"`
			Obj     []struct {
				Subnet    string `json:"subnet"`
				InboundId int    `json:"inboundId"`
			} `json:"obj"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode: %v\n%s", err, w.Body.String())
		}
		if !envelope.Success {
			t.Fatalf("an admin holding createInbound was refused: %s", w.Body.String())
		}
		found := false
		for _, b := range envelope.Obj {
			if b.Subnet == "10.0.44" && b.InboundId == f.aliInbound.Id {
				found = true
			}
		}
		if !found {
			t.Errorf("the seeded pool is missing from the map: %s", w.Body.String())
		}
	})

	t.Run("a reseller cannot reach it at all", func(t *testing.T) {
		w := f.as(t, sara, http.MethodGet, path, "")
		var envelope struct {
			Success bool `json:"success"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &envelope)
		if envelope.Success {
			t.Fatalf("a reseller read the panel-wide pool map: %s", w.Body.String())
		}
	})
}
