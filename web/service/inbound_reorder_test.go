package service

import (
	"fmt"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// The inbound list's display order. It is presentation only, but it is stored, shared
// by every admin, and reachable by anyone holding editInbound, so the arithmetic that
// decides who moves where is worth pinning.

// orderableProtocol is L2TP rather than a native Xray protocol so UpdateInbound can be
// called below: the native path dials the live Xray to swap the inbound out, and there
// is no Xray here (newInboundDB leaves the API on port 0, where a call panics). A VPN
// protocol takes the derived-inbound branch instead, which touches no gRPC.
const orderableProtocol = model.L2TP

// seedOrderableInbounds creates n inbounds from basePort up and returns their ids in
// creation order. Disabled, for the reason newInboundDB documents: the enabled paths
// dial a live Xray.
func seedOrderableInbounds(t *testing.T, basePort, n int) []int {
	t.Helper()
	db := database.GetDB()
	ids := make([]int, 0, n)
	for i := 0; i < n; i++ {
		port := basePort + i
		inbound := &model.Inbound{
			UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port,
			Protocol: orderableProtocol, Enable: false, Settings: `{"clients":[]}`,
		}
		if err := db.Create(inbound).Error; err != nil {
			t.Fatalf("create inbound: %v", err)
		}
		ids = append(ids, inbound.Id)
	}
	return ids
}

// displayOrder is the ids in the order the panel's list hands them over.
func displayOrder(t *testing.T, s *InboundService) []int {
	t.Helper()
	inbounds, err := s.GetInboundsFor(&model.User{Id: 1, Enable: true, IsSuperAdmin: true})
	if err != nil {
		t.Fatalf("GetInboundsFor: %v", err)
	}
	ids := make([]int, 0, len(inbounds))
	for _, inbound := range inbounds {
		ids = append(ids, inbound.Id)
	}
	return ids
}

func sameOrder(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A panel that has never been reordered must look exactly as it always has. This is
// the whole reason sort_order sorts 0 LAST instead of first: the column arrives on an
// upgrade defaulted to 0 for every existing row.
func TestInboundOrderDefaultsToIdOrder(t *testing.T) {
	svc := newInboundDB(t)
	ids := seedOrderableInbounds(t, 42000, 4)

	if got := displayOrder(t, svc); !sameOrder(got, ids) {
		t.Errorf("display order = %v; want the id order %v on a panel nobody has reordered", got, ids)
	}
}

func TestReorderInboundsMovesARow(t *testing.T) {
	svc := newInboundDB(t)
	ids := seedOrderableInbounds(t, 42000, 4) // [1 2 3 4]

	// Drag the last one to the front.
	want := []int{ids[3], ids[0], ids[1], ids[2]}
	if err := svc.ReorderInbounds(want); err != nil {
		t.Fatalf("ReorderInbounds: %v", err)
	}
	if got := displayOrder(t, svc); !sameOrder(got, want) {
		t.Errorf("display order = %v; want %v", got, want)
	}

	// And it sticks: a second call that changes nothing must not disturb it.
	if err := svc.ReorderInbounds(want); err != nil {
		t.Fatalf("ReorderInbounds (idempotent run): %v", err)
	}
	if got := displayOrder(t, svc); !sameOrder(got, want) {
		t.Errorf("display order = %v after a no-op reorder; want %v", got, want)
	}
}

// The case that makes this more than a renumbering. An admin sees only the inbounds
// granted to them, so the list they send is a SUBSET, and the ones they cannot see
// must not be shuffled underneath the admin who can.
func TestReorderInboundsSubsetLeavesOthersInPlace(t *testing.T) {
	svc := newInboundDB(t)
	ids := seedOrderableInbounds(t, 42000, 5) // positions 1..5

	// This admin holds the 2nd and 4th, and swaps them.
	if err := svc.ReorderInbounds([]int{ids[3], ids[1]}); err != nil {
		t.Fatalf("ReorderInbounds: %v", err)
	}

	// Only slots 2 and 4 changed hands. 1, 3 and 5 are untouched.
	want := []int{ids[0], ids[3], ids[2], ids[1], ids[4]}
	if got := displayOrder(t, svc); !sameOrder(got, want) {
		t.Errorf("display order = %v; want %v (only the two named inbounds may move)", got, want)
	}
}

// A new inbound goes to the END of a list that has already been arranged, not to the
// top. It is created with sort_order 0, and 0 is "unpositioned", which sorts last.
func TestNewInboundLandsAtTheEndOfAReorderedList(t *testing.T) {
	svc := newInboundDB(t)
	ids := seedOrderableInbounds(t, 42000, 3)

	if err := svc.ReorderInbounds([]int{ids[2], ids[1], ids[0]}); err != nil {
		t.Fatalf("ReorderInbounds: %v", err)
	}
	fresh := seedOrderableInbounds(t, 43000, 1)[0]

	want := []int{ids[2], ids[1], ids[0], fresh}
	if got := displayOrder(t, svc); !sameOrder(got, want) {
		t.Errorf("display order = %v; want %v (a new inbound appends, as it always did)", got, want)
	}
}

// A body naming an inbound that does not exist, or naming one twice, is refused
// outright rather than applied halfway: half a reorder is an order nobody asked for.
func TestReorderInboundsRejectsBadInput(t *testing.T) {
	svc := newInboundDB(t)
	ids := seedOrderableInbounds(t, 42000, 3)

	for _, tc := range []struct {
		name string
		ids  []int
	}{
		{"unknown id", []int{ids[0], 9999}},
		{"same id twice", []int{ids[0], ids[0]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := svc.ReorderInbounds(tc.ids); err == nil {
				t.Fatal("want an error")
			}
			if got := displayOrder(t, svc); !sameOrder(got, ids) {
				t.Errorf("display order = %v; a refused reorder must write nothing (was %v)", got, ids)
			}
		})
	}
}

// Nothing to do is not an error: the page fires a reorder for a drag that landed
// where it started, and for a panel holding a single inbound.
func TestReorderInboundsNoOpOnShortLists(t *testing.T) {
	svc := newInboundDB(t)
	ids := seedOrderableInbounds(t, 42000, 2)

	for _, in := range [][]int{nil, {}, {ids[0]}} {
		if err := svc.ReorderInbounds(in); err != nil {
			t.Errorf("ReorderInbounds(%v) = %v; want no error", in, err)
		}
	}
	if got := displayOrder(t, svc); !sameOrder(got, ids) {
		t.Errorf("display order = %v; want %v untouched", got, ids)
	}
}

// The position must survive an ordinary inbound edit. UpdateInbound copies the
// editable fields onto the row it loaded, so a field missing from that list is
// preserved; sort_order also carries no form tag, so a save cannot bind 0 over it.
func TestInboundEditKeepsItsPosition(t *testing.T) {
	svc := newInboundDB(t)
	ids := seedOrderableInbounds(t, 42000, 3)

	if err := svc.ReorderInbounds([]int{ids[2], ids[0], ids[1]}); err != nil {
		t.Fatalf("ReorderInbounds: %v", err)
	}

	edited, err := svc.GetInbound(ids[2])
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	edited.Remark = "renamed"
	edited.SortOrder = 0 // what a form bind would leave behind
	if _, _, err := svc.UpdateInbound(edited); err != nil {
		t.Fatalf("UpdateInbound: %v", err)
	}

	want := []int{ids[2], ids[0], ids[1]}
	if got := displayOrder(t, svc); !sameOrder(got, want) {
		t.Errorf("display order = %v; want %v (an edit must not reset the position)", got, want)
	}
}
