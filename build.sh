#!/usr/bin/env bash
#
# build.sh — build the complete, self-contained vpn-ui binary. Run it, that's it.
#
#   ./build.sh
#
# The Xray core is pinned as a git submodule (third_party/Xray-core, at a fixed
# commit). On every run it syncs that submodule, builds the Xray core from it, and
# fetches the latest geo files — then compiles build/out/vpn-ui-<arch> with everything
# baked in via go:embed. warpcli.sh is committed project source
# (web/service/warpcli.sh) and embedded directly. The static VPN daemon bundle is
# pinned + slow to build, so it is reused when already present.
#
# Escape hatches for iterative dev:
#   SUBMODULES_LATEST=1  pull the LATEST upstream commit for the submodule
#                        (git --remote, tracks the branch in .gitmodules) and
#                        rebuild the core from it. Use after pushing new Xray-core
#                        commits. The pin is moved in the working tree but NOT
#                        committed — `git add third_party/Xray-core` + commit to
#                        persist the bump for everyone else.
#   SUBMODULES_UPDATE=1  force a sync to the RECORDED pin (not the branch tip)
#   SKIP_SUBMODULES=1  don't touch the submodule (use whatever is checked out)
#   SKIP_CORE=1        reuse the cached Xray core + geo files
#   GEO_LEAN=1         embed ONLY geoip.dat + geosite.dat, dropping the ~118MB
#                      of country files (geo{ip,site}_{IR,RU}.dat) that the
#                      routing editor's Iran/Russia entries reference. All six
#                      are embedded by default; with GEO_LEAN the panel
#                      downloads a country file the first time a rule needs it.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
ARCH="$(go env GOARCH)"

# Colored logging (step/ok/info/warn/err). Falls back to plain echo if the shared
# lib is ever missing, so the build never breaks on it.
# shellcheck source=build/lib/log.sh
source "$REPO_ROOT/build/lib/log.sh" 2>/dev/null || { step(){ echo "==> $*"; }; ok(){ echo "  - $*"; }; info(){ echo "  $*"; }; warn(){ echo "  ! $*" >&2; }; err(){ echo "  x $*" >&2; }; hr(){ :; }; }

hr
step "vpn-ui build ${_CD:-}(${ARCH})${_CR:-}"
hr

# 0. Pinned upstream (third_party/Xray-core). Clone it
#    ONCE, then reuse. `git submodule status` prefixes a line with '-' when a
#    submodule is uninitialised and '+' when checked out at a different commit
#    than recorded; a leading space means it already matches the pin and there's
#    nothing to fetch. So we only sync when something actually needs it — repeat
#    builds don't re-clone/re-fetch. Set SUBMODULES_UPDATE=1 to force a sync
#    (e.g. after bumping a pin), or SKIP_SUBMODULES=1 to skip entirely.
if [[ "${SKIP_SUBMODULES:-0}" != "1" && -f .gitmodules ]]; then
    if [[ "${SUBMODULES_LATEST:-0}" == "1" ]]; then
        # --remote fetches each submodule's tracked branch (branch= in .gitmodules)
        # and moves the working tree to its tip — this is how new upstream commits
        # (e.g. a freshly-pushed Xray-core) actually get pulled in. The core rebuild
        # in step 1 then triggers automatically because the .xray.commit marker no
        # longer matches the new HEAD. The parent's recorded pin is left dirty on
        # purpose; commit third_party/* yourself to persist the bump.
        step "pulling LATEST upstream submodule commits (--remote)"
        git submodule update --init --remote --recursive
        info "submodules moved to branch tips — 'git add third_party/*' + commit to persist the new pin"
    elif [[ "${SUBMODULES_UPDATE:-0}" == "1" ]]; then
        step "syncing pinned submodules (SUBMODULES_UPDATE=1)"
        git submodule update --init --recursive
    # Capture ONCE into a variable and match with a here-string. Piping into `grep -q`
    # is broken under this script's `set -o pipefail`: grep exits at the first match,
    # git gets SIGPIPE, and the pipeline reports 141 even though the pattern matched,
    # so the check silently evaluated FALSE and this whole block never ran.
    elif sub_status="$(git submodule status --recursive 2>/dev/null || true)"; grep -q '^-' <<<"$sub_status"; then
        # '-' means NOT INITIALISED (fresh clone): there is nothing local to lose, so
        # checking it out at the recorded pin is always safe.
        step "initialising submodules"
        git submodule update --init --recursive
    elif grep -q '^+' <<<"$sub_status"; then
        # '+' means the submodule sits at a DIFFERENT commit than the parent's recorded
        # pin — i.e. someone has local work there (a patch to the Xray-core or telemt
        # fork). `git submodule update` would hard-reset it back to the pin and the build
        # would silently produce a binary WITHOUT that patch, which is exactly how the
        # telemt patches were lost once before. Never rewind implicitly: build what is
        # checked out and say so. Use SUBMODULES_UPDATE=1 to force the reset on purpose.
        warn "submodule(s) AHEAD of the recorded pin — building what is checked out, NOT rewinding:"
        grep '^+' <<<"$sub_status" | sed 's/^/    /' || true
        warn "commit the gitlink (git add third_party/<name>) to persist this, or SUBMODULES_UPDATE=1 to discard it"
    else
        ok "submodules already at pinned commits — skipping clone/sync"
    fi
fi

# 1. Xray core (built from the pinned third_party/Xray-core submodule) + latest geo.
if [[ "${SKIP_CORE:-0}" != "1" ]]; then
    step "Xray core (third_party/Xray-core) + geo files"
    bash build/core/build.sh "$ARCH"
fi

# 2. Static VPN daemon bundle (built in Docker/Alpine — pinned + slow, so cached).
#    The cache is keyed on the artifacts themselves: every bundle added since the
#    original build is named here, so a checkout that predates one still picks it
#    up instead of quietly shipping a binary that is missing a whole protocol.
#    Each entry is either a .tgz relocatable tree or a flat binary, by its own name.
BUNDLE_ARTIFACTS=(
    libreswan-bundle.tgz     # IPsec, ALL_ALGS / MODP1024
    accel-ppp-bundle.tgz     # SSTP server
    strongswan-bundle.tgz    # IKEv2
    telemt                   # MTProto Proxy
    pptp                     # PPTP client
    openconnect              # OpenConnect client
    vpnc-script              # its routing/DNS hook
    sstpc-bundle.tgz         # SSTP client (a tree: sstpc needs a dlopen'd OpenSSL provider)
    sstp-pppd-plugin.so      # and the pppd plugin it cannot handshake without
)
bundle_stale=0
if ! compgen -G "backend/bin/$ARCH/*" > /dev/null 2>&1; then
    bundle_stale=1
else
    for a in "${BUNDLE_ARTIFACTS[@]}"; do
        [[ -f "backend/bin/$ARCH/$a" ]] || { bundle_stale=1; info "bundle artifact missing: $a"; }
    done
    # Presence is not enough for openvpn: a bundle built before compression was
    # turned on has the file but cannot dial a server that insists on comp-lzo,
    # and an existence-only check would keep that binary forever. --version exits
    # non-zero by design, hence the `|| true`.
    if [[ -x "backend/bin/$ARCH/openvpn" && "$ARCH" == "$(go env GOARCH)" ]]; then
        ovpn_ver="$("backend/bin/$ARCH/openvpn" --version 2>&1 || true)"
        for feat in "[LZO]" "[LZ4]"; do
            if [[ "$ovpn_ver" != *"$feat"* ]]; then
                bundle_stale=1
                info "bundled openvpn was built without $feat"
            fi
        done
    fi
fi
if (( bundle_stale )); then
    step "VPN daemon bundle"
    bash build/backend/build.sh "$ARCH"
else
    ok "VPN daemon bundle already present — skipping"
fi

# 3. Panel binary (cgo required for sqlite). Output goes to build/out/.
OUT_DIR="$REPO_ROOT/build/out"
OUT_BIN="$OUT_DIR/vpn-ui-$ARCH"
step "compiling vpn-ui"
mkdir -p "$OUT_DIR"
CGO_ENABLED=1 go build -o "$OUT_BIN" main.go

hr
ok "done: ${_CB:-}$(ls -lh "$OUT_BIN" | awk '{print $5}')${_CR:-} -> ${_CB:-}build/out/vpn-ui-${ARCH}${_CR:-}"
info "run it:  ./build/out/vpn-ui-${ARCH}"
hr
