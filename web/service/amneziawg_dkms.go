package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hasan1808/pro-ui/awgsrc"
)

// awgBuildDir is where the embedded module source is extracted for the DKMS build.
const awgBuildDir = "/usr/src/vpn-ui-amneziawg"

// ensureAmneziawg builds + loads the out-of-tree `amneziawg` kernel module from the vendored
// source via DKMS, installing the toolchain + kernel headers first. This is the ONLY on-host
// compile in the project (a kernel module must match the running kernel, so it can't be
// prebuilt like the static daemons). On any failure it returns a Warn step (AmneziaWG
// unavailable, every other protocol keeps working) with the build log , there is no userspace
// fallback by design. DKMS registration makes the module auto-rebuild on kernel upgrade.
func ensureAmneziawg() ProvisionStep {
	name := "AmneziaWG (amneziawg kernel module)"

	// The question is NOT "is the module loadable right now" but "is it built for every
	// kernel this host might boot". Asking the former is what made setup a no-op on the
	// cloud-image path: the module was loadable for the running cloud kernel, so this
	// returned early and never built for the fuller kernel that provisioning had just
	// installed, and AmneziaWG came back missing after the reboot.
	missing := awgKernelsMissingModule()
	if len(missing) == 0 && moduleAvailable(amneziawgModule) {
		return ProvisionStep{Name: name, OK: true,
			Msg: "amneziawg module already built for every installed kernel"}
	}

	// Refuse up front on hosts where the module provably cannot build, instead of pulling
	// in a compiler, DKMS and kernel headers (80+ packages) to reach a compile error. The
	// operator gets told what actually works rather than a wall of make output. This gate
	// runs AFTER the already-built check above, so a host that obtained the module some
	// other way is never second-guessed.
	if ok, why := awgKernelModuleSupported(); !ok {
		return ProvisionStep{Name: name, OK: true, Warn: true, Msg: why}
	}

	pm := detectPackageManager()
	if pm == nil {
		return ProvisionStep{Name: name, OK: true, Warn: true,
			Msg: "no supported package manager , install dkms, kernel headers and a C toolchain, then re-run setup"}
	}

	var log strings.Builder
	warn := func(msg string) ProvisionStep {
		return ProvisionStep{Name: name + " via " + pm.name, OK: true, Warn: true, Msg: msg, Log: log.String()}
	}

	// EPEL first on EL (dkms lives in EPEL there). Best-effort.
	if isEnterpriseLinux() {
		out, err := pm.installPackage("epel-release")
		log.WriteString(out)
		if err != nil {
			log.WriteString("\n(epel-release install failed; dkms may be unavailable: " + err.Error() + ")\n")
		}
	}

	// Build prerequisites: dkms, a C toolchain (gcc+make), and headers for the running kernel.
	for _, pkg := range awgBuildDeps() {
		if pkg == "" {
			continue
		}
		out, err := pm.installPackage(pkg)
		log.WriteString(out)
		if err != nil {
			// A header package pinned to the exact running kernel can be gone (box behind the
			// archive); try the generic fallback before giving up.
			installed := false
			for _, fb := range awgHeaderFallbacks(pkg) {
				fout, ferr := pm.installPackage(fb)
				log.WriteString(fout)
				if ferr == nil {
					installed = true
					break
				}
			}
			if !installed {
				return warn("failed to install build prerequisite '" + pkg + "', AmneziaWG unavailable: " + err.Error())
			}
		}
	}

	// DKMS builds against the RUNNING kernel, so its build tree has to be on disk before
	// we start. Check explicitly rather than letting `dkms build` fail: the generic
	// header fallback above can install headers for a DIFFERENT (newer) kernel than the
	// one booted, which leaves the build failing for a reason the raw dkms output states
	// only obliquely. Naming the exact missing package is what makes this fixable.
	if kver := runningKernel(); kver != "" {
		if !fileExists("/lib/modules/" + kver + "/build") {
			return warn("no kernel headers for the RUNNING kernel " + kver +
				" (looked for /lib/modules/" + kver + "/build). AmneziaWG unavailable. " +
				"Install '" + awgKernelHeadersPackage() + "'; if your distro no longer ships headers for " +
				kver + ", update the kernel and reboot so the running kernel matches the available headers")
		}
	}

	// Extract the vendored source and DKMS-build it (mirrors the proven manual flow:
	// make dkms-install -> dkms add/build/install -> modprobe).
	_ = os.RemoveAll(awgBuildDir)
	if err := awgsrc.Extract(awgBuildDir); err != nil {
		return warn("failed to extract bundled amneziawg source: " + err.Error())
	}
	steps := [][]string{
		{"make", "-C", awgBuildDir, "dkms-install"},
		{"dkms", "add", "-m", amneziawgModule, "-v", awgsrc.Version},
		{"dkms", "build", "-m", amneziawgModule, "-v", awgsrc.Version},
		{"dkms", "install", "-m", amneziawgModule, "-v", awgsrc.Version},
	}
	for _, st := range steps {
		out, err := awgRunCmd(st[0], st[1:]...)
		log.WriteString(fmt.Sprintf("\n$ %s\n%s", strings.Join(st, " "), out))
		if err != nil {
			// `dkms add` errors if the module is already registered , not fatal.
			if st[1] == "add" && strings.Contains(strings.ToLower(out), "already") {
				continue
			}
			return warn("DKMS build failed at '" + strings.Join(st, " ") + "', AmneziaWG unavailable: " + err.Error())
		}
	}

	// Build for EVERY installed kernel that has headers, not just the running one.
	// Provisioning above may install a fuller kernel (cloud images ship no PPP/L2TP) and
	// ask for a reboot, so the kernel this host will actually boot is usually NOT the one
	// running now. Without this the module exists only for the kernel being left behind
	// and AmneziaWG comes back "module not found" after the reboot.
	//
	// Done per kernel with an explicit -k rather than `dkms autoinstall`: autoinstall only
	// considers the RUNNING kernel, so on this exact path it silently does nothing (the
	// running kernel was already handled by the install above) and the incoming kernel is
	// left without a module. Each build is best-effort so one bad kernel tree cannot fail
	// the step for the kernel that matters.
	running := runningKernel()
	var built, failed []string
	for _, kver := range awgKernelsMissingModule() {
		if kver == running {
			continue // the dkms install above already covered the running kernel
		}
		out, err := awgRunCmd("dkms", "install", "-m", amneziawgModule, "-v", awgsrc.Version, "-k", kver, "--force")
		log.WriteString(fmt.Sprintf("\n$ dkms install -k %s\n%s", kver, out))
		if err != nil {
			failed = append(failed, kver)
			log.WriteString("(build for " + kver + " failed; DKMS will retry when that kernel is booted)\n")
			continue
		}
		built = append(built, kver)
	}
	extra := ""
	if len(built) > 0 {
		extra = "; also built for " + strings.Join(built, ", ")
	}
	if len(failed) > 0 {
		extra += "; FAILED for " + strings.Join(failed, ", ")
	}

	modprobeOut, _ := awgRunCmd("modprobe", amneziawgModule)
	log.WriteString("\n$ modprobe amneziawg\n" + modprobeOut)

	if !moduleAvailable(amneziawgModule) {
		return warn("amneziawg built but not loadable (check Secure Boot / dmesg), AmneziaWG unavailable")
	}

	// Persist so the module autoloads at boot.
	_ = os.WriteFile("/etc/modules-load.d/amneziawg.conf", []byte("amneziawg\n"), 0644)
	return ProvisionStep{Name: name + " via " + pm.name, OK: true,
		Msg: "amneziawg module built + loaded (DKMS " + awgsrc.Version + ")" + extra, Log: log.String()}
}

// kernelsWithHeaders returns every installed kernel version under /lib/modules that has a
// usable build tree, i.e. the kernels DKMS can actually compile a module for. A kernel
// without headers is skipped rather than attempted, so the log shows real failures only.
func kernelsWithHeaders() []string {
	entries, err := os.ReadDir("/lib/modules")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if fileExists("/lib/modules/" + e.Name() + "/build") {
			out = append(out, e.Name())
		}
	}
	return out
}

// isEnterpriseLinux reports whether the host is an EL rebuild (Alma/Rocky/CentOS/RHEL), where
// dkms comes from EPEL.
func isEnterpriseLinux() bool {
	switch strings.ToLower(osReleaseField("ID")) {
	case "almalinux", "rocky", "centos", "rhel":
		return true
	}
	return strings.Contains(strings.ToLower(osReleaseField("ID_LIKE")), "rhel")
}

// awgBuildDeps returns the packages to install before the DKMS build: dkms, a C toolchain,
// the headers for the RUNNING kernel, and the headers METAPACKAGE.
//
// The metapackage is not redundant. Cloud images boot a cut-down kernel (Debian's
// "cloud" flavour has no PPP/L2TP), so provisioning installs a fuller kernel and asks for a
// reboot: the kernel this host will actually run is NOT the one running now. Pulling in the
// tracking metapackage means the incoming kernel arrives WITH its headers, which is what
// lets `dkms autoinstall` build the module for it before the reboot, and what keeps DKMS
// able to rebuild after every future kernel upgrade.
func awgBuildDeps() []string {
	hdrs := []string{awgKernelHeadersPackage()}
	if meta := awgKernelHeadersMetaPackage(); meta != "" && meta != hdrs[0] {
		hdrs = append(hdrs, meta)
	}
	switch {
	case commandExists("apt-get"):
		return append([]string{"dkms", "build-essential"}, hdrs...)
	case commandExists("dnf"), commandExists("yum"):
		return append([]string{"dkms", "gcc", "make"}, hdrs...)
	case commandExists("zypper"):
		return append([]string{"dkms", "gcc", "make"}, hdrs...)
	case commandExists("pacman"):
		return append([]string{"dkms", "base-devel"}, hdrs...)
	default:
		return nil
	}
}

// awgKernelHeadersMetaPackage returns the headers package that TRACKS the distro's current
// kernel (rather than pinning one version), so a kernel installed later gets headers with it.
func awgKernelHeadersMetaPackage() string {
	switch {
	case commandExists("apt-get"):
		if isUbuntu() {
			return "linux-headers-generic"
		}
		return "linux-headers-" + debKernelArch()
	case commandExists("dnf"), commandExists("yum"):
		return "kernel-devel"
	case commandExists("zypper"):
		return "kernel-default-devel"
	case commandExists("pacman"):
		return "linux-headers"
	default:
		return ""
	}
}

// awgKernelHeadersPackage returns the header/devel package matching the running kernel,
// mirroring KernelModulesPackage. DKMS needs headers for `uname -r`.
func awgKernelHeadersPackage() string {
	switch {
	case commandExists("apt-get"):
		if r := runningKernel(); r != "" {
			return "linux-headers-" + r
		}
		if isUbuntu() {
			return "linux-headers-generic"
		}
		return "linux-headers-" + debKernelArch()
	case commandExists("dnf"), commandExists("yum"):
		if r := runningKernel(); r != "" {
			return "kernel-devel-" + r
		}
		return "kernel-devel"
	case commandExists("zypper"):
		return "kernel-default-devel"
	case commandExists("pacman"):
		return "linux-headers"
	default:
		return ""
	}
}

// awgHeaderFallbacks lists generic header packages to try if the exact running-kernel header
// package isn't available (box behind the archive, cut-down flavour).
func awgHeaderFallbacks(pkg string) []string {
	switch {
	case strings.HasPrefix(pkg, "linux-headers-") && isUbuntu():
		return []string{"linux-headers-generic"}
	case strings.HasPrefix(pkg, "linux-headers-"):
		return []string{"linux-headers-" + debKernelArch()}
	case strings.HasPrefix(pkg, "kernel-devel-"):
		return []string{"kernel-devel"}
	default:
		return nil
	}
}

// awgRunCmd runs a command and returns combined output + error (for the setup log).
func awgRunCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// removeAmneziawgModule unwinds ensureAmneziawg when the AmneziaWG core is
// uninstalled: deregister the DKMS module (which removes the built .ko for every
// kernel it was installed into and stops it rebuilding on the next kernel
// upgrade) and drop the extracted source tree.
//
// The module is NOT rmmod'd. Unloading a live data-plane module would drop any
// interface still using it, and a module that stays resident until the next boot
// costs nothing now that DKMS will not rebuild it. The toolchain and kernel
// headers the build pulled in are distro packages and are kept, like every other
// package the panel installs.
func removeAmneziawgModule() ProvisionStep {
	name := "remove AmneziaWG kernel module"
	var log strings.Builder
	if !commandExists("dkms") {
		_ = os.RemoveAll(awgBuildDir)
		return ProvisionStep{Name: name, OK: true, Msg: "dkms not present; removed the source tree only"}
	}
	out, err := awgRunCmd("dkms", "remove", "-m", amneziawgModule, "-v", awgsrc.Version, "--all")
	log.WriteString(out)
	_ = os.RemoveAll(awgBuildDir)
	if err != nil {
		// Already deregistered, or built by a different version string. Not a
		// failure: the source tree is gone and nothing will rebuild it.
		return ProvisionStep{Name: name, OK: true, Warn: true,
			Msg: "dkms remove reported an error; source tree removed", Log: log.String()}
	}
	return ProvisionStep{Name: name, OK: true,
		Msg: "deregistered from DKMS (stays loaded until reboot)", Log: log.String()}
}

// awgModuleBuiltFor reports whether a DKMS-installed amneziawg module exists for kver.
func awgModuleBuiltFor(kver string) bool {
	matches, _ := filepath.Glob("/lib/modules/" + kver + "/updates/dkms/amneziawg.ko*")
	return len(matches) > 0
}

// awgKernelsMissingModule returns the kernels that CAN be built for (they have headers) but
// have no amneziawg module yet. Driving the build off this, rather than off "is the module
// loadable right now", is what makes setup cover a kernel that was installed alongside it and
// will only be booted later.
func awgKernelsMissingModule() []string {
	var out []string
	for _, k := range kernelsWithHeaders() {
		if !awgModuleBuiltFor(k) {
			out = append(out, k)
		}
	}
	return out
}

// awgSupportedDistros is what the operator is told to use when their host cannot build the
// module. Keep in sync with awgKernelModuleSupported and the matrix results below.
const awgSupportedDistros = "Debian 12, Debian 13, Ubuntu 24.04 or Ubuntu 26.04"

// awgKernelModuleSupported reports whether the AmneziaWG kernel module can build on this
// host, and when it cannot, a message naming the reason and the distros that do work.
//
// Verified 2026-07-19 by building on all 13 supported targets. The module built and loaded
// on the Debian/Ubuntu family only (Debian 12/13, Ubuntu 24.04/26.04). The other nine fail
// for two UPSTREAM reasons, neither of which is anything the panel can configure around:
//
//   - Linux 7.1 removed `ipv6_stub` (the net/ipv6_stubs.h header is gone). socket.c still
//     calls ipv6_stub->ipv6_dst_lookup_flow, and the module's own shim for that symbol is
//     gated to kernels older than 3.12, so nothing covers the removal. Hits Fedora 43/44
//     and Arch. Upstream PRs #176, #184 and #185 fix it; none merged as of this writing.
//   - RHEL-family kernels backport features while keeping an old LINUX_VERSION_CODE, so the
//     module's version-gated shims (netif_threaded_enable, timer_container_of) collide with
//     what the kernel already has. EL10 is worse: compat.h only knows RHEL_MAJOR 7, 8 and 9,
//     so EL10 is not detected at all. Hits Alma/Rocky/CentOS 9 and 10. Upstream PRs #174 and
//     #183 fix it; also unmerged. Amnezia's own COPR sidesteps this by shipping the much
//     older v1.0.20241112, which predates the offending shims.
//
// The kernel test comes first because it is the real constraint: a Debian or Ubuntu release
// that ships 7.1 will fail too, and should say so rather than be trusted by family name.
func awgKernelModuleSupported() (bool, string) {
	if maj, min, ok := runningKernelVersion(); ok && (maj > 7 || (maj == 7 && min >= 1)) {
		return false, fmt.Sprintf(
			"not supported on Linux %d.%d: the AmneziaWG module does not build on kernel 7.1 or newer "+
				"(the kernel removed ipv6_stub and upstream has not adapted yet). Every other protocol "+
				"is unaffected. For AmneziaWG use %s.", maj, min, awgSupportedDistros)
	}

	id := strings.ToLower(strings.TrimSpace(osReleaseField("ID")))
	like := strings.ToLower(osReleaseField("ID_LIKE"))
	switch {
	case id == "debian" || id == "ubuntu" ||
		strings.Contains(like, "debian") || strings.Contains(like, "ubuntu"):
		return true, ""
	case isEnterpriseLinux() || id == "fedora" || strings.Contains(like, "fedora"):
		return false, fmt.Sprintf(
			"not supported on %s: the AmneziaWG module fails to build against RHEL-family and Fedora "+
				"kernels (their backported kernels break the module's compatibility layer upstream). "+
				"Every other protocol is unaffected. For AmneziaWG use %s.",
			distroPretty(), awgSupportedDistros)
	default:
		return false, fmt.Sprintf(
			"%s is not a tested host for the AmneziaWG module, so setup did not attempt the build. "+
				"Every other protocol is unaffected. For AmneziaWG use %s.",
			distroPretty(), awgSupportedDistros)
	}
}

// runningKernelVersion is parseKernelVersion applied to the running kernel.
func runningKernelVersion() (int, int, bool) { return parseKernelVersion(runningKernel()) }

// parseKernelVersion pulls the major and minor out of a `uname -r` string. It has to cope
// with every shape the supported matrix produces: "6.8.0-136-generic", "7.1.3-arch2-2",
// "5.14.0-687.26.1.el9_8.x86_64" and Debian's "6.12.95+deb13-cloud-amd64".
func parseKernelVersion(r string) (int, int, bool) {
	if r == "" {
		return 0, 0, false
	}
	// cut at the first character that is not part of the dotted numeric prefix
	end := strings.IndexFunc(r, func(c rune) bool { return c != '.' && (c < '0' || c > '9') })
	if end > 0 {
		r = r[:end]
	}
	parts := strings.Split(r, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, min, true
}
