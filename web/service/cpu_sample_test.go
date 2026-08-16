package service

import (
	"sync"
	"testing"

	"github.com/hasan1808/pro-ui/util/sys"
)

// CPU utilization is a ratio of DELTAS between two reads of a cumulative counter,
// so whoever owns the previous read owns the measurement interval. That baseline
// used to be a package-level variable in util/sys, shared by every caller: the
// dashboard's 2s poll and the Telegram bot's usage report (a separate ServerService)
// each consumed the other's interval, and whichever ran second reported a percentage
// measured over a window that had already been reset.

// The sampler must be a pure reader: calling it cannot change what the next caller
// sees. Deltas taken over sub-intervals must therefore sum to the delta over the
// whole span, which is exactly the property the old shared baseline destroyed.
func TestCPUTimesRawIsStateless(t *testing.T) {
	firstIdle, firstTotal, err := sys.CPUTimesRaw()
	if err != nil {
		t.Skipf("no native CPU counters on this platform: %v", err)
	}

	var sumIdle, sumTotal uint64
	prevIdle, prevTotal := firstIdle, firstTotal
	for i := 0; i < 4; i++ {
		// Burn a little CPU so the counters actually advance between reads.
		busyWork()
		idle, total, err := sys.CPUTimesRaw()
		if err != nil {
			t.Fatalf("CPUTimesRaw: %v", err)
		}
		if total < prevTotal || idle < prevIdle {
			t.Fatalf("counters went backwards: idle %d->%d, total %d->%d", prevIdle, idle, prevTotal, total)
		}
		if idle > total {
			t.Fatalf("idle %d exceeds total %d", idle, total)
		}
		sumIdle += idle - prevIdle
		sumTotal += total - prevTotal
		prevIdle, prevTotal = idle, total
	}

	if sumTotal == 0 {
		t.Skip("counters did not advance; machine too idle to measure")
	}
	if got, want := sumIdle, prevIdle-firstIdle; got != want {
		t.Errorf("sub-interval idle deltas sum to %d, whole-span delta is %d: a read consumed state", got, want)
	}
	if got, want := sumTotal, prevTotal-firstTotal; got != want {
		t.Errorf("sub-interval total deltas sum to %d, whole-span delta is %d: a read consumed state", got, want)
	}
}

// Two services sampling on their own schedules must each keep their own baseline.
// Interleaved here on purpose: with a shared one, the second service's read would
// leave the first service's stored counters behind the truth.
func TestCPUBaselineIsPerService(t *testing.T) {
	if _, _, err := sys.CPUTimesRaw(); err != nil {
		t.Skipf("no native CPU counters on this platform: %v", err)
	}
	dashboard := &ServerService{}
	bot := &ServerService{}

	// First call on each establishes its baseline and reports nothing yet.
	for _, s := range []*ServerService{dashboard, bot} {
		if pct, err := s.sampleCPUUtilization(); err != nil {
			t.Fatalf("first sample: %v", err)
		} else if pct != 0 {
			t.Errorf("first sample = %v, want 0 while the baseline is being set", pct)
		}
	}

	busyWork()
	if _, err := dashboard.sampleCPUUtilization(); err != nil {
		t.Fatalf("dashboard sample: %v", err)
	}
	busyWork()
	if _, err := bot.sampleCPUUtilization(); err != nil {
		t.Fatalf("bot sample: %v", err)
	}

	// Each service advanced its OWN baseline. The bot read last, so its stored
	// counters must be at or ahead of the dashboard's, and neither may be zero.
	if dashboard.lastCPUTotal == 0 || bot.lastCPUTotal == 0 {
		t.Fatal("a service kept no baseline of its own")
	}
	if bot.lastCPUTotal < dashboard.lastCPUTotal {
		t.Errorf("bot baseline %d is behind the dashboard's %d despite reading later",
			bot.lastCPUTotal, dashboard.lastCPUTotal)
	}
	if pct, err := dashboard.sampleCPUUtilization(); err != nil {
		t.Fatalf("dashboard resample: %v", err)
	} else if pct < 0 || pct > 100 {
		t.Errorf("utilization %v out of range", pct)
	}
}

// The sampler is read from a cron goroutine and from request handlers, so it has to
// be safe to call concurrently. Run under -race to mean anything.
func TestCPUTimesRawIsConcurrencySafe(t *testing.T) {
	if _, _, err := sys.CPUTimesRaw(); err != nil {
		t.Skipf("no native CPU counters on this platform: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, _, err := sys.CPUTimesRaw(); err != nil {
					t.Errorf("CPUTimesRaw: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// busyWork advances the CPU counters by a measurable amount without sleeping, so
// the tests do not depend on wall-clock timing.
func busyWork() {
	x := 0
	for i := 0; i < 4_000_000; i++ {
		x += i % 7
	}
	_ = x
}
