package service

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// resetUpdateStateForTest clears the package-level update state between cases.
func resetUpdateStateForTest() {
	panelUpdateInFlight.Store(false)
	resetUpdateCounters()
	setUpdateProgress("", 0)
	setPanelUpdateCancel(nil)
}

// The progress bar reads these counters, so a short read must publish bytes even
// when the server sends no Content-Length (chunked), where percent is meaningless.
func TestProgressReaderPublishesCounters(t *testing.T) {
	resetUpdateStateForTest()

	body := bytes.Repeat([]byte("x"), 1000)
	pr := newProgressReader(bytes.NewReader(body), int64(len(body)))
	if _, err := io.Copy(io.Discard, pr); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if got := panelUpdateBytes.Load(); got != 1000 {
		t.Errorf("bytes = %d; want 1000", got)
	}
	if got := panelUpdateTotal.Load(); got != 1000 {
		t.Errorf("total = %d; want 1000", got)
	}
	// Percent tops out at 99: the last 1% is the install phase.
	if got := panelUpdatePercent.Load(); got != 99 {
		t.Errorf("percent = %d; want 99", got)
	}

	// Unknown length: bytes still count, total/percent stay 0.
	resetUpdateStateForTest()
	pr = newProgressReader(bytes.NewReader(body), -1)
	if _, err := io.Copy(io.Discard, pr); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if got := panelUpdateBytes.Load(); got != 1000 {
		t.Errorf("chunked bytes = %d; want 1000", got)
	}
	if got := panelUpdateTotal.Load(); got != 0 {
		t.Errorf("chunked total = %d; want 0 (unknown)", got)
	}
	if got := panelUpdatePercent.Load(); got != 0 {
		t.Errorf("chunked percent = %d; want 0 (no total to divide by)", got)
	}
}

// sampleSpeed must publish a rate only once per interval, and must not divide by a
// near-zero elapsed time (which would report an absurd speed).
func TestProgressReaderSampleSpeed(t *testing.T) {
	resetUpdateStateForTest()

	start := time.Now()
	pr := &progressReader{r: strings.NewReader(""), lastSampleAt: start}

	// Too soon: no sample published.
	pr.read = 1 << 20
	pr.sampleSpeed(start.Add(10 * time.Millisecond))
	if got := panelUpdateSpeed.Load(); got != 0 {
		t.Errorf("speed published before the sample interval elapsed: %d", got)
	}

	// 1 MiB over 1s => 1 MiB/s. First sample has no previous value to smooth against.
	pr.sampleSpeed(start.Add(time.Second))
	if got := panelUpdateSpeed.Load(); got != 1<<20 {
		t.Errorf("speed = %d; want %d (1 MiB/s)", got, 1<<20)
	}

	// Second sample at the same rate must stay at the same rate: an EMA of a constant
	// signal is that constant, whatever alpha is.
	pr.read += 1 << 20
	pr.sampleSpeed(start.Add(2 * time.Second))
	if got := panelUpdateSpeed.Load(); got != 1<<20 {
		t.Errorf("steady-rate speed = %d; want %d", got, 1<<20)
	}

	// A drop to zero throughput must decay toward 0, not snap to it.
	pr.sampleSpeed(start.Add(3 * time.Second))
	got := panelUpdateSpeed.Load()
	if got == 0 {
		t.Error("speed snapped straight to 0; want a smoothed decay")
	}
	if got >= 1<<20 {
		t.Errorf("speed = %d; want a decay below the previous 1 MiB/s", got)
	}
}

// Cancel is only legal during the download. Once installing starts, the DB snapshot
// and binary swap must run to completion.
func TestCancelPanelUpdateGating(t *testing.T) {
	s := &ServerService{}

	t.Run("no update in flight", func(t *testing.T) {
		resetUpdateStateForTest()
		if err := s.CancelPanelUpdate(); err == nil {
			t.Error("cancelling with no update in flight should fail")
		}
	})

	t.Run("cancels while downloading", func(t *testing.T) {
		resetUpdateStateForTest()
		panelUpdateInFlight.Store(true)
		defer resetUpdateStateForTest()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		setPanelUpdateCancel(cancel)
		setUpdateProgress(updatePhaseDownloading, 10)

		if err := s.CancelPanelUpdate(); err != nil {
			t.Fatalf("cancel during download: %v", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Error("cancel did not abort the download context")
		}
	})

	t.Run("refuses once installing", func(t *testing.T) {
		resetUpdateStateForTest()
		panelUpdateInFlight.Store(true)
		defer resetUpdateStateForTest()

		// UpdatePanel drops the cancel hook when it enters the install phase.
		setPanelUpdateCancel(nil)
		setUpdateProgress(updatePhaseInstalling, 99)

		if err := s.CancelPanelUpdate(); err == nil {
			t.Error("cancelling during install should be refused")
		}
	})
}
