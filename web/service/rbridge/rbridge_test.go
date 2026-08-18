package rbridge

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

// s builds a Live tunnel whose age is set by sec (smaller sec = older = evicted first under
// "accept", kept first under "reject").
func s(key string, sec int) Live {
	return Live{Protocol: "test", InboundID: 1, Email: "u", IP: "10.7.0." + key, DeviceKey: key, Since: time.Unix(int64(sec), 0)}
}

func keys(ls []Live) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.DeviceKey
	}
	return out
}

func TestTrimToLimit(t *testing.T) {
	// a<b<c<d by age (a oldest).
	a, b, c, d := s("a", 1), s("b", 2), s("c", 3), s("d", 4)

	tests := []struct {
		name     string
		in       []Live
		k        int
		strategy string
		survive  []string
		evict    []string
	}{
		{"no limit k=0", []Live{a, b, c}, 0, "reject", []string{"a", "b", "c"}, nil},
		{"no limit k negative", []Live{a, b, c}, -1, "accept", []string{"a", "b", "c"}, nil},
		{"under limit", []Live{a, b}, 3, "reject", []string{"a", "b"}, nil},
		{"exactly at limit", []Live{a, b, c}, 3, "accept", []string{"a", "b", "c"}, nil},
		{"reject keeps oldest K", []Live{a, b, c}, 2, "reject", []string{"a", "b"}, []string{"c"}},
		{"accept keeps newest K", []Live{a, b, c}, 2, "accept", []string{"b", "c"}, []string{"a"}},
		{"reject K=1 keeps oldest", []Live{a, b, c}, 1, "reject", []string{"a"}, []string{"b", "c"}},
		{"accept K=1 keeps newest", []Live{a, b, c}, 1, "accept", []string{"c"}, []string{"a", "b"}},
		{"unsorted input ordered by Since", []Live{c, a, d, b}, 2, "reject", []string{"a", "b"}, []string{"c", "d"}},
		{"empty accept default (non-reject strategy)", []Live{a, b, c}, 2, "", []string{"b", "c"}, []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			survivors, evicted := TrimToLimit(tt.in, tt.k, tt.strategy)
			if got := keys(survivors); !sameSlice(got, tt.survive) {
				t.Errorf("survivors = %v, want %v", got, tt.survive)
			}
			if got := keys(evicted); !sameSet(got, tt.evict) {
				t.Errorf("evicted = %v, want (any order) %v", got, tt.evict)
			}
		})
	}
}

func TestTrimToLimitDoesNotMutateInput(t *testing.T) {
	in := []Live{s("c", 3), s("a", 1), s("b", 2)}
	before := keys(in)
	_, _ = TrimToLimit(in, 1, "accept")
	if after := keys(in); !sameSlice(before, after) {
		t.Errorf("input mutated: before %v, after %v", before, after)
	}
}

// --- Sweeper.Tick: disabled eviction + limit trim + survivor hand-off end to end ---

type fakeSink struct {
	disabled map[string]bool
	got      map[string]map[string]Reconciled // protocol -> desired ip->(email, inbound)
}

func (f *fakeSink) DisabledEmails() map[string]bool { return f.disabled }
func (f *fakeSink) ReconcileLocalSessions(protocol string, desired map[string]Reconciled) {
	if f.got == nil {
		f.got = map[string]map[string]Reconciled{}
	}
	f.got[protocol] = desired
}

type fakeAdapter struct {
	proto    string
	poll     []Live
	k        int
	strategy string
	evicted  []string
}

func (a *fakeAdapter) Protocol() string        { return a.proto }
func (a *fakeAdapter) Poll() ([]Live, error)   { return a.poll, nil }
func (a *fakeAdapter) Limit(int) (int, string) { return a.k, a.strategy }
func (a *fakeAdapter) Evict(l Live) error      { a.evicted = append(a.evicted, l.DeviceKey); return nil }

func TestSweeperTickEnforcesDisabledThenLimit(t *testing.T) {
	// One inbound: a disabled account's tunnel, plus three tunnels for an enabled account
	// (ages 1,2,3) under an accept-strategy limit of 2.
	banned := Live{Protocol: "test", InboundID: 1, Email: "banned", IP: "10.7.0.9", DeviceKey: "banned", Since: time.Unix(0, 0)}
	a := Live{Protocol: "test", InboundID: 1, Email: "ok", IP: "10.7.0.1", DeviceKey: "a", Since: time.Unix(1, 0)}
	b := Live{Protocol: "test", InboundID: 1, Email: "ok", IP: "10.7.0.2", DeviceKey: "b", Since: time.Unix(2, 0)}
	c := Live{Protocol: "test", InboundID: 1, Email: "ok", IP: "10.7.0.3", DeviceKey: "c", Since: time.Unix(3, 0)}

	ad := &fakeAdapter{proto: "test", poll: []Live{banned, a, b, c}, k: 2, strategy: "accept"}
	sink := &fakeSink{disabled: map[string]bool{"banned": true}}

	sw := New(sink)
	sw.Register(ad)
	sw.Tick()

	// banned (disabled) + a (oldest, over the accept limit of 2) must be evicted.
	if !sameSet(ad.evicted, []string{"banned", "a"}) {
		t.Errorf("evicted = %v, want {banned, a}", ad.evicted)
	}
	// Survivors b and c are handed to the sink under the adapter's protocol.
	want := map[string]Reconciled{
		"10.7.0.2": {Email: "ok", InboundID: 1},
		"10.7.0.3": {Email: "ok", InboundID: 1},
	}
	if got := sink.got["test"]; !reflect.DeepEqual(got, want) {
		t.Errorf("desired = %v, want %v", got, want)
	}
}

func TestSweeperTickEvictsSettingsDisabled(t *testing.T) {
	// A tunnel whose account is disabled in protocol settings (Disabled=true) must be evicted
	// even though it is not in the sink's client_traffics disabled set.
	d := Live{Protocol: "test", InboundID: 1, Email: "x", IP: "10.7.0.5", DeviceKey: "d", Disabled: true, Since: time.Unix(1, 0)}
	ad := &fakeAdapter{proto: "test", poll: []Live{d}, k: 0}
	sink := &fakeSink{disabled: map[string]bool{}}

	sw := New(sink)
	sw.Register(ad)
	sw.Tick()

	if !sameSet(ad.evicted, []string{"d"}) {
		t.Errorf("evicted = %v, want {d}", ad.evicted)
	}
	if len(sink.got["test"]) != 0 {
		t.Errorf("desired = %v, want empty", sink.got["test"])
	}
}

func TestSweeperTickPerAccountLimit(t *testing.T) {
	// Two accounts under one inbound, each with 2 tunnels, K=1 accept: each account keeps its
	// own newest tunnel. Proves the limit is per account, not per inbound.
	a1 := Live{InboundID: 1, Email: "a", IP: "10.7.0.1", DeviceKey: "a1", Since: time.Unix(1, 0)}
	a2 := Live{InboundID: 1, Email: "a", IP: "10.7.0.2", DeviceKey: "a2", Since: time.Unix(2, 0)}
	b1 := Live{InboundID: 1, Email: "b", IP: "10.7.0.3", DeviceKey: "b1", Since: time.Unix(1, 0)}
	b2 := Live{InboundID: 1, Email: "b", IP: "10.7.0.4", DeviceKey: "b2", Since: time.Unix(2, 0)}

	ad := &fakeAdapter{proto: "test", poll: []Live{a1, a2, b1, b2}, k: 1, strategy: "accept"}
	sink := &fakeSink{disabled: map[string]bool{}}

	sw := New(sink)
	sw.Register(ad)
	sw.Tick()

	if !sameSet(ad.evicted, []string{"a1", "b1"}) {
		t.Errorf("evicted = %v, want {a1, b1} (oldest of each account)", ad.evicted)
	}
	want := map[string]Reconciled{
		"10.7.0.2": {Email: "a", InboundID: 1},
		"10.7.0.4": {Email: "b", InboundID: 1},
	}
	if got := sink.got["test"]; !reflect.DeepEqual(got, want) {
		t.Errorf("desired = %v, want %v", got, want)
	}
}

func TestSweeperTickNilSinkNoPanic(t *testing.T) {
	sw := New(nil)
	sw.Register(&fakeAdapter{proto: "test"})
	sw.Tick() // must not panic
}

// --- helpers ---

func sameSlice(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func sameSet(a, b []string) bool {
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return sameSlice(ac, bc)
}
