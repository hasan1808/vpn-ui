package service

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// A wg-c inbound's 10.7 block is not stored as an assignment decision; it is
// re-derived from the inbound id every time anything about the inbound changes
// (wgcChanged -> AutoExpandVpnRanges -> normalizeRanges -> allocateAlignedBlock).
//
// That is only safe if the derivation is STABLE. It is load-bearing in a way nothing
// else in the panel is: a WireGuard client config hardcodes `Address = <block IP>/32`
// and the server cryptokey-routes that exact address. If the block moves under a
// live inbound, every config already handed out keeps sourcing packets from an
// address the peer entry no longer allows. The handshake still completes and the
// tunnel carries nothing, which is exactly what "this inbound stopped working"
// looks like from the outside.

// addWgcInbound mimics the controller's create path: NormalizeVpnRanges runs BEFORE
// the insert assigns an id (web/controller/inbound.go), so allocation happens with
// Id == 0 every time.
func addWgcInbound(t *testing.T, port int, clients int) *model.Inbound {
	t.Helper()
	list := make([]map[string]any, 0, clients)
	for i := 0; i < clients; i++ {
		list = append(list, map[string]any{"email": fmt.Sprintf("u%d-%d", port, i), "enable": true})
	}
	settings, err := json.Marshal(map[string]any{"clients": list, "userLimit": 1})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId:   1,
		Tag:      fmt.Sprintf("inbound-%d", port),
		Port:     port,
		Protocol: model.WGC,
		Enable:   true,
		Settings: string(settings),
	}
	if err := NormalizeVpnRanges(inbound, 0); err != nil {
		t.Fatalf("NormalizeVpnRanges: %v", err)
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return inbound
}

func wgcRangesOf(t *testing.T, id int) []string {
	t.Helper()
	var inbound model.Inbound
	if err := database.GetDB().First(&inbound, id).Error; err != nil {
		t.Fatalf("reload inbound %d: %v", id, err)
	}
	var settings struct {
		IpRanges []string `json:"ipRanges"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	return settings.IpRanges
}

func TestWgcBlocksSurviveRepeatedReconciliation(t *testing.T) {
	newInboundDB(t)

	first := addWgcInbound(t, 51820, 2)
	second := addWgcInbound(t, 51821, 2)

	before := map[int][]string{
		first.Id:  wgcRangesOf(t, first.Id),
		second.Id: wgcRangesOf(t, second.Id),
	}
	t.Logf("after create: inbound %d = %v, inbound %d = %v",
		first.Id, before[first.Id], second.Id, before[second.Id])

	if fmt.Sprint(before[first.Id]) == fmt.Sprint(before[second.Id]) {
		t.Fatalf("the two inbounds were given the SAME block: %v", before[first.Id])
	}

	// wgcChanged runs this on every add/edit/delete of an inbound OR a client, so
	// an inbound is re-normalized many times over its life.
	for round := 1; round <= 4; round++ {
		AutoExpandVpnRanges("wg-c")
		for id, want := range before {
			got := wgcRangesOf(t, id)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("round %d: inbound %d block MOVED %v -> %v; every client config already issued for it now sources an address the peer no longer allows",
					round, id, want, got)
				before[id] = got // report each move once
			}
		}
	}
}

// The same property with a gap in the id sequence, which is what an operator
// creating and deleting inbounds actually produces.
func TestWgcBlocksSurviveIdGaps(t *testing.T) {
	newInboundDB(t)

	a := addWgcInbound(t, 51820, 1)
	b := addWgcInbound(t, 51821, 1)
	c := addWgcInbound(t, 51822, 1)

	// Drop the middle one, the way the panel would.
	if err := database.GetDB().Delete(&model.Inbound{}, b.Id).Error; err != nil {
		t.Fatalf("delete inbound: %v", err)
	}

	before := map[int][]string{
		a.Id: wgcRangesOf(t, a.Id),
		c.Id: wgcRangesOf(t, c.Id),
	}
	t.Logf("after delete: inbound %d = %v, inbound %d = %v", a.Id, before[a.Id], c.Id, before[c.Id])

	for round := 1; round <= 3; round++ {
		AutoExpandVpnRanges("wg-c")
		for id, want := range before {
			got := wgcRangesOf(t, id)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("round %d: inbound %d block MOVED %v -> %v after an unrelated inbound was deleted",
					round, id, want, got)
				before[id] = got
			}
		}
	}
}

// Stability must not mean "frozen". An inbound whose account count outgrows its
// block still has to be given a bigger one, and the enlarged block must not land on
// top of a neighbour.
func TestWgcBlockStillGrowsWhenItRunsOut(t *testing.T) {
	newInboundDB(t)

	small := addWgcInbound(t, 51820, 2)
	neighbour := addWgcInbound(t, 51821, 2)

	start := wgcRangesOf(t, small.Id)
	if len(start) != 1 {
		t.Fatalf("expected a single /24 to start, got %v", start)
	}
	neighbourBefore := wgcRangesOf(t, neighbour.Id)

	// 300 accounts cannot fit in 253 addresses, so the block has to at least double.
	var inbound model.Inbound
	if err := database.GetDB().First(&inbound, small.Id).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	clients := make([]map[string]any, 0, 300)
	for i := 0; i < 300; i++ {
		clients = append(clients, map[string]any{"email": fmt.Sprintf("grow-%d", i), "enable": true})
	}
	settings["clients"] = clients
	grown, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", small.Id).
		Update("settings", string(grown)).Error; err != nil {
		t.Fatalf("persist grown settings: %v", err)
	}

	AutoExpandVpnRanges("wg-c")

	after := wgcRangesOf(t, small.Id)
	if len(after) < 2 {
		t.Errorf("block did not grow for 300 accounts: %v", after)
	}
	// And it must not have swallowed the neighbour's /24.
	occupied := map[string]bool{}
	for _, r := range after {
		occupied[rangeSubnet(r)] = true
	}
	for _, r := range wgcRangesOf(t, neighbour.Id) {
		if occupied[rangeSubnet(r)] {
			t.Errorf("grown block %v overlaps the neighbour's %v", after, r)
		}
	}
	if fmt.Sprint(wgcRangesOf(t, neighbour.Id)) != fmt.Sprint(neighbourBefore) {
		t.Errorf("neighbour was displaced by the growth: %v -> %v",
			neighbourBefore, wgcRangesOf(t, neighbour.Id))
	}
}
