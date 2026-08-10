package backend

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// startBusyBinary copies a real ELF into dir, runs it, and returns its path once
// the kernel has actually marked the image busy. Replicates a bundle's live musl
// loader: the file setup would overwrite while a daemon still executes it.
func startBusyBinary(t *testing.T, dir string) (string, *exec.Cmd) {
	t.Helper()

	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no 'sleep' binary to borrow: %v", err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("cannot read %s: %v", src, err)
	}
	dest := filepath.Join(dir, "busyd")
	if err := os.WriteFile(dest, data, 0o755); err != nil {
		t.Fatalf("seed the fake daemon: %v", err)
	}

	cmd := exec.Command(dest, "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the fake daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Start returns once the fork is done, which can precede the execve landing.
	deadline := time.Now().Add(5 * time.Second)
	for {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid))
		if err == nil && link == dest {
			return dest, cmd
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the fake daemon to exec %s", dest)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The bug: re-running setup overwrote bundle files in place. For the one file the
// kernel protects (the musl loader each bundle wrapper execs) that fails with
// ETXTBSY. This pins the fix: WriteFileAtomic must replace a file that a live
// process is executing, without disturbing that process.
func TestWriteFileAtomicOverRunningBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ETXTBSY semantics and /proc are Linux-specific")
	}
	dir := t.TempDir()
	dest, cmd := startBusyBinary(t, dir)

	// Establish the precondition: the in-place write setup used to do really does
	// fail here. Without this the rest of the test would prove nothing.
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err == nil {
		_ = f.Close()
		t.Skip("kernel did not mark the running binary busy; nothing to prove")
	}
	if !errors.Is(err, syscall.ETXTBSY) {
		t.Fatalf("in-place overwrite: got %v; want ETXTBSY", err)
	}

	// The fix must succeed against that very same live binary.
	want := []byte("replaced\n")
	if err := WriteFileAtomic(dest, want, 0o755); err != nil {
		t.Fatalf("WriteFileAtomic over a running binary: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q; want %q", got, want)
	}

	// The daemon must survive on its old, now-unlinked inode. Replacing a live
	// daemon's files must not kill it: that's the whole point of rename over
	// truncate, and it's why setup can run without dropping VPN sessions.
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Errorf("the running daemon died when its binary was replaced: %v", err)
	}

	// No temp file may survive a successful write.
	if _, err := os.Stat(dest + ".new"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: stat err = %v", err)
	}
}

// Bundles carry 0755 binaries next to 0644 configs and RADIUS dictionaries, so the
// mode must survive the write regardless of the process umask.
func TestWriteFileAtomicPreservesMode(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o755, 0o644, 0o600} {
		dest := filepath.Join(dir, fmt.Sprintf("f%o", mode))
		if err := WriteFileAtomic(dest, []byte("x"), mode); err != nil {
			t.Fatalf("WriteFileAtomic(%o): %v", mode, err)
		}
		fi, err := os.Stat(dest)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := fi.Mode().Perm(); got != mode {
			t.Errorf("mode = %o; want %o", got, mode)
		}
	}
}

// A failed write must not leave a partial file behind.
//
// The obvious version of this test (a destination whose parent is missing) is FALSE
// COVERAGE: it fails at open, before any file exists, so it passes whether or not
// the cleanup is there. This drives the case that actually leaks, a write that fails
// PART-WAY: os.WriteFile opens O_CREATE|O_TRUNC and only then writes, so an
// ENOSPC/EIO/RLIMIT_FSIZE mid-write leaves a partial .new and returns an error.
func TestWriteFileAtomicCleansUpPartialWrite(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("RLIMIT_FSIZE handling is Linux-specific")
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "daemon.bin")

	// Cap the file size this process may create, then exceed it. The write starts,
	// hits the limit, and fails: exactly the shape of a full disk.
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		t.Skipf("getrlimit: %v", err)
	}
	restore := lim
	lim.Cur = 64 * 1024
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		t.Skipf("setrlimit (needs an unprivileged-lowerable RLIMIT_FSIZE): %v", err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &restore) })

	// Exceeding RLIMIT_FSIZE raises SIGXFSZ, whose default action kills the process.
	// Ignore it so the write returns EFBIG instead.
	signal.Ignore(syscall.SIGXFSZ)
	t.Cleanup(func() { signal.Reset(syscall.SIGXFSZ) })

	err := WriteFileAtomic(dest, make([]byte, 1<<20), 0o755)
	if err == nil {
		t.Skip("the write unexpectedly succeeded; RLIMIT_FSIZE not enforced here")
	}
	if _, serr := os.Stat(dest + ".new"); !os.IsNotExist(serr) {
		t.Errorf("a part-way write left a partial temp file behind: stat err = %v", serr)
	}
	// And the destination must be untouched.
	if _, serr := os.Stat(dest); !os.IsNotExist(serr) {
		t.Errorf("destination should not exist after a failed write: stat err = %v", serr)
	}
}

// ExtractOnly's empty case is a trap worth pinning: several cores (SSTP, IKEv2,
// WireGuard, AmneziaWG) own no bundled daemon at all, so they ask for an empty
// set on every install. An "empty means everything" contract silently laid down
// the whole bundle for them, which made every other core report itself
// installed. "Extract only these" of nothing must extract nothing.
func TestExtractOnlyEmptyExtractsNothing(t *testing.T) {
	files, err := ExtractOnly(nil)
	if err != nil {
		t.Fatalf("ExtractOnly(nil): %v", err)
	}
	if len(files) != 0 {
		t.Errorf("ExtractOnly(nil) wrote %d file(s), want none: %v", len(files), files)
	}
	files, err = ExtractOnly([]string{})
	if err != nil {
		t.Fatalf("ExtractOnly([]): %v", err)
	}
	if len(files) != 0 {
		t.Errorf("ExtractOnly([]) wrote %d file(s), want none: %v", len(files), files)
	}
}

// Bundled must never answer yes for a name it cannot resolve to a flat embedded
// binary. The guard matters because status cards (mtprotoStatus) use Bundled to
// tell "this arch can never run the core" apart from "not installed yet", and a
// hostile/broken name must not flip that into a false positive.
func TestBundledGuards(t *testing.T) {
	for _, name := range []string{"", "../escape", "a/b", "telemt.tgz"} {
		if Bundled(name) {
			t.Errorf("Bundled(%q) = true, want false", name)
		}
	}
}
