package controller

import (
	"path/filepath"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/service"

	"github.com/op/go-logging"
)

// Adding or editing an account on an Xray-native inbound is applied to the RUNNING
// core over the Xray API (AddInboundClient / UpdateInboundClient do it and report
// needRestart=false when it worked). Restarting anyway throws that away and drops
// every live connection on the box, which is exactly what operators report as "the
// panel restarts the whole service when I add a user".
//
// The regression this pins: reconcileForInbounds' default branch used to force the
// restart flag on for every non-VPN protocol, so needRestart=false never reached the
// decision.
func newReconcileFixture(t *testing.T, protocol model.Protocol) (*InboundController, int) {
	t.Helper()
	logger.InitLogger(logging.CRITICAL)
	if err := database.InitDB(filepath.Join(t.TempDir(), "reconcile.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: "inbound-45001", Port: 45001, Protocol: protocol, Enable: true,
		Settings: `{"clients":[]}`,
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return &InboundController{}, inbound.Id
}

// drainRestartFlag clears whatever the flag currently holds and reports it, so each
// case starts from a known state and reads its own result.
func drainRestartFlag() bool {
	return (&service.XrayService{}).IsNeedRestartAndSetFalse()
}

func TestReconcileSkipsXrayRestartAfterLiveClientAdd(t *testing.T) {
	a, id := newReconcileFixture(t, model.VLESS)
	drainRestartFlag()

	a.reconcileForInbounds([]int{id}, false)

	if drainRestartFlag() {
		t.Error("an account the Xray API already accepted asked for a core restart anyway, " +
			"which drops every live connection for nothing")
	}
}

// The other half of the contract: when the live add could NOT be applied, the restart
// is the only thing that gets the account into the core, so it must still be asked for.
func TestReconcileRestartsXrayWhenLiveAddFailed(t *testing.T) {
	a, id := newReconcileFixture(t, model.VLESS)
	drainRestartFlag()

	a.reconcileForInbounds([]int{id}, true)

	if !drainRestartFlag() {
		t.Error("the Xray API could not take the account, so nothing but a restart applies it, " +
			"yet no restart was requested")
	}
}

// Xray-native WireGuard is the documented exception: its peers are synthesized from
// keys and tunnel addresses at config time and there is no API to add one, so a
// client change there does need the core rebuilt.
func TestReconcileStillRestartsForXrayWireguard(t *testing.T) {
	a, id := newReconcileFixture(t, model.WireGuard)
	drainRestartFlag()

	a.reconcileForInbounds([]int{id}, false)

	if !drainRestartFlag() {
		t.Error("Xray WireGuard peers only exist in the generated config, so a client " +
			"change there must still rebuild and restart the core")
	}
}
