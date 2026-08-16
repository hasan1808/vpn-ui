package service

import (
	"encoding/json"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

func slotPtr(v int) *int { return &v }

// slotOr is what every allocator reads its index through. The fallback is the whole
// compatibility story: a row the startup migration has not stamped keeps the address it has
// been using instead of collapsing onto slot 0.
func TestSlotOrFallsBackToListPosition(t *testing.T) {
	cases := []struct {
		name  string
		slot  *int
		index int
		want  int
	}{
		{"stored slot wins", slotPtr(7), 2, 7},
		{"stored slot zero is a real slot", slotPtr(0), 3, 0},
		{"absent falls back to the position", nil, 3, 3},
		{"negative is treated as absent", slotPtr(-1), 4, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := slotOr(c.slot, c.index); got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestSlotsForNewAccounts(t *testing.T) {
	cases := []struct {
		name     string
		existing []model.Client
		n        int
		want     []int
	}{
		{"empty inbound", nil, 3, []int{0, 1, 2}},
		{"appends after contiguous accounts", []model.Client{
			{Slot: slotPtr(0)}, {Slot: slotPtr(1)}}, 2, []int{2, 3}},
		{"fills the hole a delete left", []model.Client{
			{Slot: slotPtr(0)}, {Slot: slotPtr(2)}}, 2, []int{1, 3}},
		{"unstamped accounts hold their positions", []model.Client{
			{}, {}, {}}, 1, []int{3}},
		{"mixed stamped and unstamped", []model.Client{
			{Slot: slotPtr(5)}, {}}, 2, []int{0, 2}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := slotsForNewAccounts(c.existing, c.n)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

// The add/update paths splice raw client JSON, so the stamping happens on maps. What matters
// per case: an existing slot is never overwritten, a returning email keeps its address, and
// a genuinely new account cannot land on an address in use.
func TestAssignSlotsToClientMaps(t *testing.T) {
	parse := func(t *testing.T, s string) []any {
		t.Helper()
		var list []any
		if err := json.Unmarshal([]byte(s), &list); err != nil {
			t.Fatal(err)
		}
		return list
	}
	slotOf := func(t *testing.T, c any) any {
		t.Helper()
		m, ok := c.(map[string]any)
		if !ok {
			t.Fatalf("not a client map: %v", c)
		}
		return m["slot"]
	}

	t.Run("new accounts take the lowest free slots", func(t *testing.T) {
		existing := []model.Client{{Email: "a@t", Slot: slotPtr(0)}, {Email: "c@t", Slot: slotPtr(2)}}
		list := parse(t, `[{"email":"d@t"},{"email":"e@t"}]`)
		assignSlotsToClientMaps(model.L2TP, existing, list)
		if got := slotOf(t, list[0]); got != 1 {
			t.Fatalf("first new account got slot %v, want the freed 1", got)
		}
		if got := slotOf(t, list[1]); got != 3 {
			t.Fatalf("second new account got slot %v, want 3", got)
		}
	})

	t.Run("a returning email keeps its address", func(t *testing.T) {
		// This is the whole-inbound save: the form posts every client, none carrying a
		// slot. Re-deriving from order is exactly the bug.
		existing := []model.Client{{Email: "a@t", Slot: slotPtr(4)}, {Email: "b@t", Slot: slotPtr(9)}}
		list := parse(t, `[{"email":"b@t"},{"email":"a@t"},{"email":"new@t"}]`)
		assignSlotsToClientMaps(model.OPENVPN, existing, list)
		if got := slotOf(t, list[0]); got != 9 {
			t.Fatalf("b@t moved to slot %v, want its 9", got)
		}
		if got := slotOf(t, list[1]); got != 4 {
			t.Fatalf("a@t moved to slot %v, want its 4", got)
		}
		if got := slotOf(t, list[2]); got != 0 {
			t.Fatalf("the new account got slot %v, want the free 0", got)
		}
	})

	t.Run("email matching ignores case and padding", func(t *testing.T) {
		existing := []model.Client{{Email: "Bob@T", Slot: slotPtr(6)}}
		list := parse(t, `[{"email":" bob@t "}]`)
		assignSlotsToClientMaps(model.PPTP, existing, list)
		if got := slotOf(t, list[0]); got != 6 {
			t.Fatalf("got slot %v, want the matched 6", got)
		}
	})

	t.Run("an existing slot is never overwritten", func(t *testing.T) {
		list := parse(t, `[{"email":"a@t","slot":11}]`)
		assignSlotsToClientMaps(model.WGC, nil, list)
		if got := slotOf(t, list[0]); got != float64(11) {
			t.Fatalf("got slot %v, want the carried 11", got)
		}
	})

	t.Run("unstamped existing accounts still hold their positions", func(t *testing.T) {
		existing := []model.Client{{Email: "a@t"}, {Email: "b@t"}}
		list := parse(t, `[{"email":"new@t"}]`)
		assignSlotsToClientMaps(model.AWG, existing, list)
		if got := slotOf(t, list[0]); got != 2 {
			t.Fatalf("got slot %v, want 2 (0 and 1 are in use by position)", got)
		}
	})

	t.Run("protocols with no address pool are left alone", func(t *testing.T) {
		for _, proto := range []model.Protocol{model.VMESS, model.VLESS, model.MTPROTO, model.SSH} {
			list := parse(t, `[{"email":"a@t"}]`)
			assignSlotsToClientMaps(proto, nil, list)
			if got := slotOf(t, list[0]); got != nil {
				t.Fatalf("%s client was stamped with slot %v", proto, got)
			}
		}
	})
}

func TestHighestSlot(t *testing.T) {
	if got := highestSlot(nil); got != -1 {
		t.Fatalf("no accounts: got %d, want -1", got)
	}
	if got := highestSlot([]model.Client{{Slot: slotPtr(3)}, {Slot: slotPtr(1)}}); got != 3 {
		t.Fatalf("got %d, want 3", got)
	}
	// Unstamped accounts count as their positions, which is what they are using.
	if got := highestSlot([]model.Client{{}, {}, {}}); got != 2 {
		t.Fatalf("got %d, want 2", got)
	}
}

// The startup migration is what makes an upgrade a no-op: every existing account keeps the
// address it is on, which is its current position.
func TestMigrationAccountSlotsStampsCurrentPositions(t *testing.T) {
	svc := newInboundDB(t)
	l2tp := seedInboundWithClients(t, model.L2TP, 41201, []map[string]any{
		{"id": "a", "email": "a@t", "password": "p"},
		{"id": "b", "email": "b@t", "password": "p", "slot": 9}, // already stamped
		{"id": "c", "email": "c@t", "password": "p"},
	})
	// A protocol with no address pool must not grow the field.
	vmess := seedInboundWithClients(t, model.VMESS, 41202, []map[string]any{
		{"id": "u", "email": "v@t"},
	})

	svc.MigrationAccountSlots()

	got := readClients(t, l2tp.Id)
	for i, want := range []any{float64(0), float64(9), float64(2)} {
		if got[i]["slot"] != want {
			t.Fatalf("client %d: slot %v, want %v", i, got[i]["slot"], want)
		}
	}
	if s, has := readClients(t, vmess.Id)[0]["slot"]; has {
		t.Fatalf("vmess client was stamped with slot %v", s)
	}

	// Idempotent: a second pass changes nothing.
	svc.MigrationAccountSlots()
	again := readClients(t, l2tp.Id)
	for i := range got {
		if again[i]["slot"] != got[i]["slot"] {
			t.Fatalf("client %d moved on the second pass: %v -> %v",
				i, got[i]["slot"], again[i]["slot"])
		}
	}
}

// A copied account must not carry the SOURCE inbound's slot: that pool is a different
// pool, and the value could name an address an account in the target already holds.
func TestCopiedClientDropsTheSourceSlot(t *testing.T) {
	svc := &InboundService{}
	source := model.Client{Email: "a@t", ID: "a", Password: "p", Slot: slotPtr(7)}
	target, err := svc.buildTargetClientFromSource(source, model.L2TP, "b@t", "")
	if err != nil {
		t.Fatal(err)
	}
	if target.Slot != nil {
		t.Fatalf("the copy kept slot %d from the source inbound", *target.Slot)
	}
}

// Pool sizing must cover the highest SLOT, not the number of accounts: delete the middle of
// three and two accounts remain with an account sitting at slot 2.
func TestDecodeHighestSlot(t *testing.T) {
	raw := func(clients string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(`{"clients":`+clients+`}`), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	cases := []struct {
		name    string
		clients string
		want    int
	}{
		{"no clients key", "null", -1},
		{"stamped, contiguous", `[{"slot":0},{"slot":1}]`, 1},
		{"stamped with a hole", `[{"slot":0},{"slot":2}]`, 2},
		{"unstamped counts as its position", `[{},{},{}]`, 2},
		{"mixed", `[{"slot":7},{}]`, 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decodeHighestSlot(raw(c.clients)); got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
	if got := decodeHighestSlot(map[string]json.RawMessage{}); got != -1 {
		t.Fatalf("empty settings: got %d, want -1", got)
	}
}
