package service

import (
	"path/filepath"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// What the Traffic column of the outbounds table reads. A VPN tunnel is an ordinary
// tagged outbound by the time it reaches here, so these cover every outbound; they
// exist because the tunnel rows are the ones whose numbers an operator checks against
// a bill.

func seedOutboundTrafficDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
}

func outboundRows(t *testing.T) map[string]model.OutboundTraffics {
	t.Helper()
	var rows []model.OutboundTraffics
	if err := database.GetDB().Find(&rows).Error; err != nil {
		t.Fatalf("read outbound_traffics: %v", err)
	}
	out := make(map[string]model.OutboundTraffics, len(rows))
	for _, r := range rows {
		if _, dup := out[r.Tag]; dup {
			t.Fatalf("two rows carry the tag %q, so the column would show whichever the query returned first", r.Tag)
		}
		out[r.Tag] = r
	}
	return out
}

// Xray's stats are drained on every poll (QueryStats with reset), so each tick is a
// DELTA and the row has to accumulate. One tick can also carry the same tag twice.
//
// The upsert is a FirstOrCreate keyed by a `tag = ?` expression rather than by a
// struct, which is the shape GORM does not always fold into the created row, so this
// asserts the tag actually lands rather than trusting that it does.
func TestAddOutboundTrafficAccumulatesPerTag(t *testing.T) {
	seedOutboundTrafficDB(t)
	s := &OutboundService{}

	if err := s.addOutboundTraffic(database.GetDB(), []*xray.Traffic{
		{Tag: "vpn-l2tp", IsOutbound: true, Up: 10, Down: 100},
		{Tag: "direct", IsOutbound: true, Up: 20, Down: 200},
		{Tag: "vpn-l2tp", IsOutbound: true, Up: 1, Down: 2},
	}); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if err := s.addOutboundTraffic(database.GetDB(), []*xray.Traffic{
		{Tag: "vpn-l2tp", IsOutbound: true, Up: 5, Down: 50},
		{Tag: "vpn-wg", IsOutbound: true, Up: 7, Down: 70},
	}); err != nil {
		t.Fatalf("second tick: %v", err)
	}

	rows := outboundRows(t)
	for tag, want := range map[string]model.OutboundTraffics{
		"vpn-l2tp": {Up: 16, Down: 152, Total: 168},
		"direct":   {Up: 20, Down: 200, Total: 220},
		"vpn-wg":   {Up: 7, Down: 70, Total: 77},
	} {
		got, ok := rows[tag]
		if !ok {
			t.Errorf("no row for %q, so its Traffic column reads 0 B / 0 B", tag)
			continue
		}
		if got.Up != want.Up || got.Down != want.Down || got.Total != want.Total {
			t.Errorf("%s = up %d / down %d / total %d, want %d / %d / %d",
				tag, got.Up, got.Down, got.Total, want.Up, want.Down, want.Total)
		}
	}
	if len(rows) != 3 {
		t.Errorf("got %d rows, want 3: %v", len(rows), rows)
	}
}

// Inbound and outbound stats arrive in ONE slice and share the Traffic struct, so the
// only thing separating them is the flag the tag parser set. An inbound record that
// leaked through here would invent an outbound row whose tag matches an inbound and
// show that inbound's bytes in the outbounds table.
func TestAddOutboundTrafficIgnoresInboundRecords(t *testing.T) {
	seedOutboundTrafficDB(t)
	s := &OutboundService{}

	if err := s.addOutboundTraffic(database.GetDB(), []*xray.Traffic{
		{Tag: "inbound-20001", IsInbound: true, Up: 999, Down: 999},
		{Tag: "vpn-gre", IsOutbound: true, Up: 3, Down: 4},
	}); err != nil {
		t.Fatal(err)
	}

	rows := outboundRows(t)
	if _, leaked := rows["inbound-20001"]; leaked {
		t.Error("an inbound record produced an outbound_traffics row")
	}
	if got := rows["vpn-gre"].Total; got != 7 {
		t.Errorf("vpn-gre total = %d, want 7", got)
	}
}

// The per-tag reset the outbounds table offers has to reach a tunnel's row, and the
// all-tags reset has to not miss it. Both go through a raw where clause built by
// string concatenation, which is easy to get subtly wrong and impossible to see.
func TestResetOutboundTrafficReachesATunnelRow(t *testing.T) {
	seedOutboundTrafficDB(t)
	s := &OutboundService{}
	seed := []*xray.Traffic{
		{Tag: "vpn-l2tp", IsOutbound: true, Up: 10, Down: 100},
		{Tag: "direct", IsOutbound: true, Up: 20, Down: 200},
	}
	if err := s.addOutboundTraffic(database.GetDB(), seed); err != nil {
		t.Fatal(err)
	}

	if err := s.ResetOutboundTraffic("vpn-l2tp"); err != nil {
		t.Fatalf("reset one tag: %v", err)
	}
	rows := outboundRows(t)
	if rows["vpn-l2tp"].Total != 0 {
		t.Errorf("vpn-l2tp total = %d after its own reset, want 0", rows["vpn-l2tp"].Total)
	}
	if rows["direct"].Total != 220 {
		t.Errorf("direct total = %d, want the untargeted row left alone", rows["direct"].Total)
	}

	if err := s.ResetOutboundTraffic("-alltags-"); err != nil {
		t.Fatalf("reset all tags: %v", err)
	}
	for tag, row := range outboundRows(t) {
		if row.Total != 0 || row.Up != 0 || row.Down != 0 {
			t.Errorf("%s survived the all-tags reset: %+v", tag, row)
		}
	}
}
