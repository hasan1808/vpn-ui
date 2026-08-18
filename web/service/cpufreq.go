package service

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The CPU's CURRENT clock, as opposed to the one it is rated for.
//
// cpu.Info().Mhz, which the spec readouts use, is the RATED figure on Linux: on
// the machine this was written on it reports 4900, which is exactly
// /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq, and it never moves. The
// panel cached it on top of that, so a row rendered from it was a constant
// pretending to be a measurement. Measured on the same host one second apart,
// the live values ranged from 798 MHz to 4500 MHz across cores.
//
// AVERAGED over the online cores rather than maxed. A ten-core chip sitting at
// 800 MHz on nine cores and 4.5 GHz on one is mostly idle, and the max would
// report it as flat out. The average is also what desktop monitors show.
//
// Three sources, in order of how directly they answer the question:
//
//  1. cpufreq sysfs. The scaling driver's own reading, exact where it exists.
//  2. /proc/cpuinfo "cpu MHz", but ONLY once it has been seen to move. On x86 the
//     kernel fills it from the aperf/mperf counters even with no cpufreq driver,
//     which is a real live reading; on a virtual machine it is a constant copied
//     from the host's TSC frequency at boot, and reporting that as "current" is
//     the bug this file exists to remove.
//  3. A measurement (see estimatedCpuMhz), for everything else. A guest has no
//     cpufreq tree and no moving cpuinfo, so nothing it can READ will ever change;
//     what it can still do is time a known amount of work and see how fast the
//     vCPU actually got through it.
//
// The readers take their paths as arguments purely so the tests can drive them
// against a fixture tree; production always passes the constants below.

const (
	// cpuFreqSysfsGlob matches one file per CPU, holding that CPU's current kHz.
	cpuFreqSysfsGlob = "/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq"
	// cpuFreqHwGlob is the same reading straight from the hardware. Some drivers
	// (acpi-cpufreq on certain boards, several arm64 ones) publish only this, and
	// it is root-readable, which the panel is.
	cpuFreqHwGlob = "/sys/devices/system/cpu/cpu[0-9]*/cpufreq/cpuinfo_cur_freq"
	// cpuFreqPolicyGlob is the per-POLICY view of the same values, for a tree whose
	// cpuN/cpufreq symlinks are missing. One entry per policy rather than per CPU,
	// so a big.LITTLE machine averages its clusters rather than its cores; that is
	// a fallback, not the first choice.
	cpuFreqPolicyGlob = "/sys/devices/system/cpu/cpufreq/policy[0-9]*/scaling_cur_freq"
	procCpuinfoPath   = "/proc/cpuinfo"
)

// liveCpuMhz returns the current average clock in MHz, or 0 when the host cannot
// report one and none can be estimated either.
//
// ratedMhz is the chip's rated speed (Status.CpuSpeedMhz), used only by the
// estimator, which measures a RATIO and needs something to scale it by. Pass 0 if
// it is not known yet; the readable sources are unaffected.
func liveCpuMhz(ratedMhz float64) float64 {
	for _, glob := range []string{cpuFreqSysfsGlob, cpuFreqHwGlob, cpuFreqPolicyGlob} {
		if mhz := avgSysfsMhz(glob); mhz > 0 {
			return mhz
		}
	}
	if mhz := movingCpuinfoMhz(procCpuinfoPath); mhz > 0 {
		return mhz
	}
	return estimatedCpuMhz(ratedMhz)
}

// avgSysfsMhz averages one kHz-per-file glob across the online CPUs.
//
// This is the cpufreq driver's own answer and the first choice. The glob is not
// cached: CPUs can be hotplugged, and a stale list would either miss a new core
// or keep reading a file that has gone. Unreadable entries are skipped, which is
// what an offline core looks like; so is "<unknown>", which some drivers answer
// with and which must not be read as zero.
func avgSysfsMhz(glob string) float64 {
	paths, err := filepath.Glob(glob)
	if err != nil || len(paths) == 0 {
		return 0
	}
	var sum float64
	var n int
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		khz, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if err != nil || khz <= 0 {
			continue
		}
		sum += khz / 1000
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// avgCpuinfoMhz averages the "cpu MHz" lines, for a host with no cpufreq sysfs.
//
// One file read rather than one per core, so it is the cheaper of the two, but it
// is second because it is the less reliable: on x86 the kernel fills it from the
// same live counters, while on some virtualised hosts it is a constant, and on
// arm64 the field is absent entirely.
func avgCpuinfoMhz(path string) float64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var sum float64
	var n int
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(key) != "cpu MHz" {
			continue
		}
		mhz, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil || mhz <= 0 {
			continue
		}
		sum += mhz
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// cpuinfoWatch remembers whether /proc/cpuinfo's "cpu MHz" has ever changed on this
// host, which is the only way to tell a live reading from a constant.
var cpuinfoWatch struct {
	sync.Mutex
	last  float64
	moves bool
}

// movingCpuinfoMhz returns the cpuinfo reading, but only once it has been observed
// to change - that is, only when it is really a measurement.
//
// A guest reports the host's boot-time TSC frequency here forever. Serving that as
// the live clock is what made the readout look frozen on every VPS, and it is worse
// than serving nothing: nothing falls through to a figure that does move.
//
// The verdict is one-way. Two consecutive polls can legitimately read the same value
// on a genuinely live source (an idle machine parked at its floor), so a source is
// promoted the first time it moves and never demoted afterwards.
func movingCpuinfoMhz(path string) float64 {
	mhz := avgCpuinfoMhz(path)
	if mhz <= 0 {
		return 0
	}
	cpuinfoWatch.Lock()
	defer cpuinfoWatch.Unlock()
	if cpuinfoWatch.last != 0 && mhz != cpuinfoWatch.last {
		cpuinfoWatch.moves = true
	}
	cpuinfoWatch.last = mhz
	if !cpuinfoWatch.moves {
		return 0
	}
	return mhz
}

// -----------------------------------------------------------------------------
// The estimate, for hosts that cannot report a clock at all
// -----------------------------------------------------------------------------

// A virtual machine has no cpufreq tree (the hypervisor owns the P-states) and a
// frozen "cpu MHz", so every readable source is a constant. That is not a gap in
// this code: the guest genuinely is not told what the physical core is doing.
//
// What it can measure is how much work its vCPU actually gets through, which is the
// number an operator wants anyway. A host that has throttled, or that is handing
// this guest a contended core, delivers less of it, and that shows up here where a
// static "3.0 GHz" never would.
//
// Reported as a RATIO of this machine's own best, scaled by the rated speed, rather
// than as an absolute derived from cycles per iteration. The ratio cancels the
// per-microarchitecture constant, which is the part that would not survive the move
// from x86 to arm64: xorshift is six dependent 1-cycle ALU ops on a modern x86 core
// (measured here at 0.99 of the kernel's own figure) and rather fewer effective
// cycles on an arm64 core that folds a shifted operand into the xor. Dividing two
// measurements taken the same way on the same chip leaves that unknown out of it.
//
// The reference is the best rate seen since the panel started, so:
//   - the first reading lands at the rated speed and moves down from there, which is
//     the honest direction: the panel cannot know a boost clock it has never seen.
//   - a machine that spends its first minutes contended corrects itself upward the
//     moment it gets a clean run.
//   - the figure is bounded by the rated speed, so it can never claim a clock the
//     chip does not have.

// cpuSpinIters is how many xorshift rounds one burst runs, tuned at runtime so a
// burst lands near cpuSpinTarget on whatever this CPU turns out to be. It starts
// low so the first poll on a slow core is cheap.
var cpuSpin struct {
	sync.Mutex
	iters int
	best  float64 // best iterations/second seen on this host
}

const (
	// cpuSpinTarget is how long one burst should take. Long enough to be well clear
	// of the clock's resolution and of the P-state ramp, short enough that three of
	// them per poll are noise: 3 x 250us every two seconds is under 0.04% of one core.
	cpuSpinTarget = 250 * time.Microsecond
	cpuSpinMin    = 20_000
	cpuSpinMax    = 40_000_000
	// cpuSpinBursts is how many bursts a poll takes. The FASTEST is kept: every way a
	// burst can go wrong (a preemption, an interrupt, a migration) makes it look
	// slower, never faster, so the maximum is the least-disturbed sample rather than
	// the luckiest one.
	cpuSpinBursts = 3
)

// cpuSpinSink keeps the compiler from deciding the loop below has no effect.
var cpuSpinSink uint64

// spinXorshift runs a strictly dependent chain of shifts and xors: every round needs
// the previous round's result, so the loop advances at the core's own pace and not at
// the pace of however many of these the machine could do in parallel.
//
//go:noinline
func spinXorshift(iters int) uint64 {
	x := uint64(0x2545F4914F6CDD1D)
	for i := 0; i < iters; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
	}
	return x
}

// estimatedCpuMhz measures this machine against its own best and scales the result by
// the rated clock. Returns 0 when there is no rated clock to scale by, which is the
// caller's signal to fall back to showing the rated figure alone.
func estimatedCpuMhz(ratedMhz float64) float64 {
	if ratedMhz <= 0 {
		return 0
	}

	cpuSpin.Lock()
	iters := cpuSpin.iters
	if iters == 0 {
		iters = cpuSpinMin
	}
	best := cpuSpin.best
	cpuSpin.Unlock()

	rate := 0.0
	for i := 0; i < cpuSpinBursts; i++ {
		start := time.Now()
		cpuSpinSink += spinXorshift(iters)
		elapsed := time.Since(start)
		if elapsed <= 0 {
			continue
		}
		if r := float64(iters) / elapsed.Seconds(); r > rate {
			rate = r
		}
		// Re-tune towards a burst of about cpuSpinTarget. Done inside the loop so a
		// first poll that guessed badly still gets a usable sample out of this call.
		if elapsed < cpuSpinTarget/2 && iters < cpuSpinMax {
			iters *= 2
		} else if elapsed > cpuSpinTarget*2 && iters > cpuSpinMin {
			iters /= 2
		}
	}
	if rate <= 0 {
		return 0
	}

	cpuSpin.Lock()
	cpuSpin.iters = iters
	if rate > cpuSpin.best {
		cpuSpin.best = rate
	}
	best = cpuSpin.best
	cpuSpin.Unlock()

	if best <= 0 {
		return 0
	}
	return ratedMhz * (rate / best)
}
