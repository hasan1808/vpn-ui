package job

import (
	"testing"

	"github.com/hasan1808/pro-ui/xray"
)

func ct(email string, up, down int64) *xray.ClientTraffic {
	return &xray.ClientTraffic{Email: email, Up: up, Down: down}
}

func totals(recs []*xray.ClientTraffic) map[string]int64 {
	out := make(map[string]int64, len(recs))
	for _, r := range recs {
		out[r.Email] += r.Up + r.Down
	}
	return out
}

// The relay protocols measure the SAME bytes twice: once as an Xray socks user stat, once
// in their own tally. addClientTraffic sums every record for an email, so exactly one of
// the two has to reach it.
func TestAppendUnrecordedDropsRelayCopyWhenXrayAlreadyHasTheAccount(t *testing.T) {
	xrayRecords := []*xray.ClientTraffic{ct("ssh-user", 1_000, 100_000_000)}
	relay := []*xray.ClientTraffic{ct("ssh-user", 1_000, 100_000_000)}

	got := totals(appendUnrecorded(xrayRecords, relay))
	if got["ssh-user"] != 100_001_000 {
		t.Errorf("billed %d; want 100001000 (the transfer counted once, not twice)", got["ssh-user"])
	}
}

// The regression that made a 100MiB SSH pull bill 1.67x: Xray and the relay flush on
// different boundaries, so Xray legitimately reports ZERO for an account in the tick where
// the relay reports its bytes, then reports those same bytes a tick later. A predicate of
// "did Xray move bytes this tick" admits both copies; presence must win regardless of size.
func TestAppendUnrecordedDropsRelayCopyEvenWhenXrayReportsZeroThisTick(t *testing.T) {
	xrayRecords := []*xray.ClientTraffic{ct("ssh-user", 0, 0)}
	relay := []*xray.ClientTraffic{ct("ssh-user", 0, 50_000_000)}

	got := totals(appendUnrecorded(xrayRecords, relay))
	if got["ssh-user"] != 0 {
		t.Errorf("billed %d; want 0: Xray tracks this account, so its own later record is "+
			"authoritative and the relay copy must not be added on top", got["ssh-user"])
	}
}

// The fallback has to survive: an account Xray does not track at all still bills.
func TestAppendUnrecordedKeepsRelayRecordForUntrackedAccount(t *testing.T) {
	xrayRecords := []*xray.ClientTraffic{ct("someone-else", 5, 5)}
	relay := []*xray.ClientTraffic{ct("mtproto-user", 10, 20)}

	got := totals(appendUnrecorded(xrayRecords, relay))
	if got["mtproto-user"] != 30 {
		t.Errorf("billed %d; want 30 (no Xray record exists, so the relay tally is the source)",
			got["mtproto-user"])
	}
	if got["someone-else"] != 10 {
		t.Errorf("unrelated account changed: %d", got["someone-else"])
	}
}

// Two relays reporting the same account in one tick must contribute once.
func TestAppendUnrecordedAddsAnAccountOnlyOnceAcrossRelays(t *testing.T) {
	got := totals(appendUnrecorded(nil, []*xray.ClientTraffic{
		ct("shared", 1, 2),
		ct("shared", 100, 200),
	}))
	if got["shared"] != 3 {
		t.Errorf("billed %d; want 3 (first record only)", got["shared"])
	}
}

func TestAppendUnrecordedHandlesEmptyInputs(t *testing.T) {
	if got := appendUnrecorded(nil, nil); len(got) != 0 {
		t.Errorf("appendUnrecorded(nil, nil) = %v; want empty", got)
	}
	base := []*xray.ClientTraffic{ct("a", 1, 1)}
	if got := appendUnrecorded(base, nil); len(got) != 1 {
		t.Errorf("appendUnrecorded(base, nil) = %v; want the base untouched", got)
	}
}
