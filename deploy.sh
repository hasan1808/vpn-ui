#!/usr/bin/env bash
# MmD
set -euo pipefail

REPO="hasan1808/vpn-ui"
ASSET="vpn-ui-amd64"
# Install location; override with VPN_UI_DIR=... to use a filesystem with more room.
DEST_DIR="${VPN_UI_DIR:-/opt/vpn-ui}"
DEST="$DEST_DIR/$ASSET"
UNIT="vpn-ui"
# The management menu (`vpn-ui`). Installed from INSIDE the binary we just placed
# ($DEST install-menu), never curled from the repo's default branch: that would pin
# a menu from a different release than the binary it drives.
MENU="/usr/bin/vpn-ui"
DL_URL="https://github.com/$REPO/releases/latest/download/$ASSET"
# The panel keeps its SQLite DB next to the binary (exe dir). Backups go beside it.
DB="$DEST_DIR/vpn-ui.db"
BACKUP_DIR="$DEST_DIR/backups"
# Real-SSL (Let's Encrypt via acme.sh: Cloudflare DNS-01 or standalone HTTP-01).
# DEPLOY_DOMAIN / DEPLOY_EMAIL preset these for a non-interactive issuance;
# otherwise prompted. DEPLOY_CF_TOKEN (+ optional DEPLOY_WILDCARD=1) picks the
# Cloudflare path, and is read by the sourced obtain_letsencrypt_cert itself.
#
# A DEPLOY_DOMAIN holding a public IP rather than a name issues a certificate for
# that address, for a host with no domain at all. That path needs nothing new here:
# obtain_letsencrypt_cert recognises the literal and switches itself. Read its
# caveats before using it in an unattended install. The short version is that such a
# certificate lasts 160 hours rather than 90 days, so it renews every few days, and
# TCP :80 has to be reachable each time.
CERT_DIR="$DEST_DIR/cert"
DOMAIN="${DEPLOY_DOMAIN:-}"
EMAIL="${DEPLOY_EMAIL:-}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
    BLUE=$'\e[38;5;39m'; GREEN=$'\e[38;5;114m'; RED=$'\e[38;5;203m'
    YELLOW=$'\e[38;5;221m'; TEAL=$'\e[38;5;44m'; WHITE=$'\e[1;38;5;255m'
else
    B= D= R= BLUE= GREEN= RED= YELLOW= TEAL= WHITE=
fi

# ":: text"  bold-blue header + bold-white message (pacman's step style)
msg()  { printf '%s::%s %s%s%s\n' "$B$BLUE" "$R" "$WHITE" "$*" "$R"; }
# "  -> text"  blue action arrow
act()  { printf '  %s->%s %s\n' "$BLUE" "$R" "$*"; }
ok()   { printf '  %s->%s %s%s%s\n' "$GREEN" "$R" "$GREEN" "$*" "$R"; }
warn() { printf '%swarning:%s %s\n' "$B$YELLOW" "$R" "$*" >&2; }
die()  { printf '%serror:%s %s\n'   "$B$RED" "$R" "$*" >&2; exit 1; }
hr()   { printf '%s%s%s\n' "$D" "$(printf '%.0s-' {1..60})" "$R"; }

# Byte counts the way a human reads them (one decimal from KB up). Shared by the
# live download line and its final summary, so the two can never disagree about
# units. Integer-only maths: no awk/bc dependency for something this small.
fmt_bytes() {
    local b="$1" div unit
    if   (( b >= 1073741824 )); then div=1073741824; unit=GB
    elif (( b >= 1048576    )); then div=1048576;    unit=MB
    elif (( b >= 1024       )); then div=1024;       unit=KB
    else printf '%d B' "$b"; return 0
    fi
    printf '%d.%d %s' "$(( b / div ))" "$(( b * 10 / div % 10 ))" "$unit"
}

# Compact durations for the ETA and the elapsed time: "45s", "2m07s".
fmt_time() {
    local s="$1"
    if (( s >= 60 )); then printf '%dm%02ds' "$(( s / 60 ))" "$(( s % 60 ))"
    else printf '%ds' "$s"
    fi
}

# Real-SSL (Let's Encrypt via acme.sh) lives in ONE place: obtain_letsencrypt_cert
# in vpn-ui.sh, which is sourced further below once the menu script is installed.
# It used to be defined here and copied into the menu, which is exactly how two
# acme.sh flows drift apart. Sourcing (rather than running `vpn-ui ssl`) keeps it
# in THIS shell, so its DOMAIN/EMAIL prompts fill in the variables the completion
# message below prints.

# Acquire root: re-exec through sudo when not already root, so `./deploy.sh`
# just works. If invoked piped (no script file) or without sudo, bail with
# instructions instead of failing obscurely.
if [[ $EUID -ne 0 ]]; then
    if [[ -f "$0" ]] && command -v sudo >/dev/null 2>&1; then
        exec sudo -- bash "$0" "$@"
    fi
    die "must run as root — use: sudo $0   (piped: curl -fsSL <url> | sudo bash)"
fi

# Preflight
hr
printf '%s[%sVPN-UI%s]%s deploy\n' "$B$TEAL" "$GREEN" "$TEAL" "$R"
hr

command -v systemctl >/dev/null 2>&1 || die "systemctl not found — this host isn't running systemd."

arch="$(uname -m)"
[[ "$arch" == "x86_64" || "$arch" == "amd64" ]] || \
    warn "host architecture is '$arch' — this installs the amd64 build, which may not run here."

# Fresh install vs in-place update: an already-installed binary means UPDATE. On
# update we must NOT re-randomize credentials (that would lock the operator out of
# their own panel) and we snapshot the DB before the new binary can migrate it.
MODE="install"; OLD_VER=""
if [[ -e "$DEST" ]]; then
    MODE="update"
    OLD_VER="$("$DEST" -v 2>/dev/null | tr -d '[:space:]')"
fi

if   command -v curl >/dev/null 2>&1; then DL="curl"
elif command -v wget >/dev/null 2>&1; then DL="wget"
else die "need 'curl' or 'wget' to download the release."; fi

# Resolve + download the latest release asset
msg "Fetching latest release of $REPO"

# Best-effort: read the release tag from the /releases/latest redirect (display only).
ver=""
if [[ "$DL" == "curl" ]]; then
    ver="$(curl -sILo /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null \
           | grep -oE 'tag/[^/[:space:]]+$' | sed 's#tag/##' || true)"
fi
[[ -n "$ver" ]] && act "latest release: ${GREEN}${ver}${R}" || act "asset: ${GREEN}${ASSET}${R}"
if [[ "$MODE" == "update" ]]; then
    act "mode:   ${YELLOW}update${R} (${OLD_VER:-unknown} -> ${ver:-latest})"
else
    act "mode:   ${GREEN}fresh install${R}"
fi

# GitHub serves release assets off objects.githubusercontent.com, which is
# blocked/throttled in some regions even though github.com itself is reachable.
# Try the direct URL first, then community GitHub proxies that fetch the asset
# server-side and re-serve it to the client. (A proxy is a MITM by design — only
# use these where you cannot reach the GitHub CDN directly.)
if [[ -n "$ver" ]]; then
    ASSET_BASE="https://github.com/$REPO/releases/download/$ver/$ASSET"
else
    ASSET_BASE="https://github.com/$REPO/releases/latest/download/$ASSET"
fi
# Primary mirror: the asset re-published (gzip-compressed) on the `dist` branch and
# served from raw.githubusercontent.com, which is reachable even where the release CDN
# (objects.githubusercontent.com) is blocked. We gunzip it after download below.
RAW_MIRROR="https://raw.githubusercontent.com/$REPO/dist/$ASSET.gz"
MIRRORS=(
    "$RAW_MIRROR"
    "$ASSET_BASE"
    "https://ghfast.top/$ASSET_BASE"
    "https://ghproxy.net/$ASSET_BASE"
    "https://github.moeyy.xyz/$ASSET_BASE"
)
# Operator override: point at ANY reachable URL for the binary (self-hosted, a
# region-specific proxy, …). Takes precedence over the built-in list.
if [[ -n "${VPN_UI_BINARY_URL:-}" ]]; then
    MIRRORS=( "$VPN_UI_BINARY_URL" )
fi

# Millisecond clock for the transfer rates below. GNU date has %3N; a date
# without it (busybox) falls back to whole seconds, which only coarsens the rate.
now_ms() {
    local t
    t="$(date +%s%3N 2>/dev/null || true)"
    [[ "$t" =~ ^[0-9]{13,}$ ]] || t="$(date +%s)000"
    printf '%s' "$t"
}

# Best-effort Content-Length, so the progress line can show a percentage and an
# ETA. GitHub redirects a release asset to its CDN, so follow the redirects and
# keep the LAST length seen. A miss here is not fatal: the line simply drops the
# percentage and the ETA and reports bytes plus rate.
# Discarding the length when the probe itself failed (pipefail carries the -f /
# --spider status out of the pipeline) is what stops a 404 page's own
# Content-Length from being presented as the asset's size.
remote_size() {
    local url="$1" len=""
    if [[ "$DL" == "curl" ]]; then
        len="$(curl -fsIL --max-time 20 "$url" 2>/dev/null \
               | grep -iE '^[[:space:]]*content-length:' | tail -n1 | tr -cd '0-9')" || len=""
    else
        len="$(wget --spider -S --tries=1 --timeout=20 "$url" 2>&1 \
               | grep -iE '^[[:space:]]*content-length:' | tail -n1 | tr -cd '0-9')" || len=""
    fi
    [[ "$len" =~ ^[0-9]+$ ]] && printf '%s' "$len"
    return 0
}

# One redraw of the live line. DL_LINE_LEN keeps the previous VISIBLE width so a
# line that shrinks (the ETA counting down) is padded over instead of leaving a
# tail behind; padding with blanks rather than an erase-to-end-of-line escape
# keeps this honest for anyone who sets NO_COLOR.
DL_BAR_FULL='####################'
DL_BAR_EMPTY='--------------------'
DL_LINE_LEN=0
DL_COLS=80
progress_line() {
    local bytes="$1" total="$2" speed="$3"
    local pct=0 pct_txt="" size_txt rate_txt eta_txt="" bar="" barlen=0 pad="" len
    size_txt="$(fmt_bytes "$bytes")"
    rate_txt="$(fmt_bytes "$speed")/s"
    if (( total > 0 )); then
        pct=$(( bytes * 100 / total ))
        (( pct > 100 )) && pct=100
        pct_txt="$(printf '%3d%%  ' "$pct")"
        size_txt="$size_txt / $(fmt_bytes "$total")"
        if (( speed > 0 && bytes < total )); then
            eta_txt="   eta $(fmt_time "$(( (total - bytes) / speed ))")"
        fi
    fi
    size_txt="$size_txt   "

    # The bar is the first thing to go on a narrow terminal: the numbers matter
    # more than the picture, and a wrapped line would break the \r redraw.
    len=$(( 5 + ${#pct_txt} + ${#size_txt} + ${#rate_txt} + ${#eta_txt} ))
    if (( total > 0 && DL_COLS - len >= 23 )); then
        bar="[${TEAL}${DL_BAR_FULL:0:$(( pct * 20 / 100 ))}${R}${D}${DL_BAR_EMPTY:0:$(( 20 - pct * 20 / 100 ))}${R}] "
        barlen=23
    fi
    len=$(( len + barlen ))
    (( DL_LINE_LEN > len )) && pad="$(printf '%*s' "$(( DL_LINE_LEN - len ))" '')"
    DL_LINE_LEN=$len
    printf '\r  %s->%s %s%s%s%s%s%s%s%s' \
        "$BLUE" "$R" "$bar" "$pct_txt" "$size_txt" "$GREEN" "$rate_txt" "$R" "$eta_txt" "$pad"
}

# Download $1 to $2 behind a progress line we render ourselves. curl and wget are
# both run quietly and the line is drawn from the partial file's size, the one
# signal the two tools share: that is what keeps the two paths looking identical,
# and it is the only way to show a rate on the wget path, whose --show-progress
# bar never printed one. Returns the transfer's REAL exit status (from wait, not
# from the backgrounding), so a failed download still reaches die.
fetch_asset() {
    local url="$1" out="$2"
    local total tick=0.2 rc=0 rated=0 live=0
    local start now bytes=0 last_ms last_b=0 speed=0 elapsed
    [[ -t 1 ]] && live=1     # a piped install (curl ... | sudo bash) gets no \r redraws

    # Terminal width once per download: recomputing it per redraw would fork five
    # times a second for a number that almost never changes.
    if (( live )); then DL_COLS="$(tput cols 2>/dev/null || echo 80)"; fi
    [[ "$DL_COLS" =~ ^[0-9]+$ ]] || DL_COLS=80
    # Fractional sleeps are a coreutils extension. Where they are missing, redraw
    # once a second instead of spinning on a failing sleep.
    sleep 0.01 2>/dev/null || tick=1

    total="$(remote_size "$url")"
    [[ "$total" =~ ^[0-9]+$ ]] || total=0
    # With no live line, the size is the only hint the log gives about how long
    # the silence is going to last.
    if (( ! live && total > 0 )); then act "size:   $(fmt_bytes "$total")"; fi

    # Quiet, but NOT mute: -sS / -nv drop the built-in progress bars (we draw the
    # line) while keeping each tool's own diagnosis, which is parked in DL_ERR and
    # replayed only if the transfer fails.
    DL_ERR="$(mktemp)"
    if [[ "$DL" == "curl" ]]; then
        curl -fL --retry 3 -sS -o "$out" "$url" 2>"$DL_ERR" &
    else
        wget --tries=3 -nv -O "$out" "$url" 2>"$DL_ERR" &
    fi
    DL_PID=$!

    start="$(now_ms)"; last_ms="$start"
    while kill -0 "$DL_PID" 2>/dev/null; do
        sleep "$tick"
        bytes="$(stat -c %s "$out" 2>/dev/null || echo 0)"
        now="$(now_ms)"
        if (( bytes < last_b )); then
            # A --retry restart truncates the file. Re-seed the window rather
            # than report a negative rate.
            last_b="$bytes"; last_ms="$now"; speed=0
        elif (( now - last_ms >= 800 )); then
            # Rate over the last ~second, not over the whole transfer: that is
            # what makes a stall visible instead of averaging it away.
            speed=$(( (bytes - last_b) * 1000 / (now - last_ms) ))
            last_b="$bytes"; last_ms="$now"; rated=1
        elif (( ! rated && now > start )); then
            speed=$(( bytes * 1000 / (now - start) ))
        fi
        if (( live )); then progress_line "$bytes" "$total" "$speed"; fi
    done
    wait "$DL_PID" || rc=$?
    DL_PID=""

    bytes="$(stat -c %s "$out" 2>/dev/null || echo 0)"
    elapsed=$(( $(now_ms) - start ))
    (( elapsed < 1 )) && elapsed=1
    DL_BYTES="$bytes"
    DL_SECS=$(( (elapsed + 500) / 1000 ))
    DL_RATE=$(( bytes * 1000 / elapsed ))

    if (( live )); then
        if (( rc == 0 )); then
            # Settle the line at 100% with the average rate, then free the row.
            progress_line "$bytes" "$total" "$DL_RATE"
            printf '\n'
        elif (( DL_LINE_LEN > 0 )); then
            printf '\r%*s\r' "$DL_LINE_LEN" ''   # wipe a half-drawn line before die
        fi
    fi
    # Quiet mode swallowed curl's/wget's own diagnosis ("HTTP 404" and friends),
    # which is exactly what an operator needs here, so replay it before we fail.
    if (( rc != 0 )) && [[ -s "$DL_ERR" ]]; then warn "$(tail -n1 "$DL_ERR")"; fi
    rm -f "$DL_ERR"; DL_ERR=""
    return "$rc"
}

install -d -m 0755 "$DEST_DIR"
# --- disk pre-flight (fail fast instead of a cryptic curl 23 / "No space left") --
# The binary (~123MB) is streamed/decompressed straight into $DEST_DIR, so only it
# needs ~150MB free there; no staging filesystem is involved. Before giving up, we
# auto-free ONLY safe, self-inflicted junk: our own leftovers + apt cache +
# orphaned apt packages + journal.
_free_kb() { df -Pk "$1" 2>/dev/null | awk 'NR==2{print $4}'; }   # KiB free
_dest_free="$(( $(_free_kb "$DEST_DIR") * 1024 ))"
[[ "$_dest_free" =~ ^-?[0-9]+$ ]] || _dest_free=0
if (( _dest_free < 150*1024*1024 )); then
    act "low disk: $DEST_DIR has $(fmt_bytes "$_dest_free") free, need ~150MB"
    rm -f /tmp/vpn-ui-amd64.* "$DEST_DIR"/vpn-ui-amd64.* "$DEST_DIR"/vpn-ui-amd64.download 2>/dev/null
    if command -v apt-get >/dev/null 2>&1; then
        apt-get clean 2>/dev/null || true
        apt-get -y autoremove --purge >/dev/null 2>&1 || true
    fi
    if command -v journalctl >/dev/null 2>&1; then journalctl --vacuum-size=20M >/dev/null 2>&1 || true; fi
    _dest_free="$(( $(_free_kb "$DEST_DIR") * 1024 ))"
    if (( _dest_free < 150*1024*1024 )); then
        die "disk still too full after auto-cleanup: $DEST_DIR has $(fmt_bytes "$_dest_free") free, need ~150MB. Free ~200MB on the server and retry (see: df -h)."
    fi
    ok "freed space: $DEST_DIR now has $(fmt_bytes "$_dest_free") free"
fi
tmp="$DEST_DIR/vpn-ui-amd64.download"
rm -f "$tmp"
DL_PID=""; DL_ERR=""
# One teardown for everything the download owns: the partial file, the captured
# stderr, and the transfer itself. Wired to INT/TERM as well as EXIT because a
# background job in a non-interactive shell ignores the Ctrl-C that reaches us,
# so without this it would keep downloading after the script is gone.
dl_cleanup() {
    if [[ -n "$DL_PID" ]] && kill -0 "$DL_PID" 2>/dev/null; then
        kill "$DL_PID" 2>/dev/null || true
        wait "$DL_PID" 2>/dev/null || true
    fi
    [[ -n "$DL_ERR" ]] && rm -f "$DL_ERR"
    rm -f "$tmp"
    return 0
}
trap 'dl_cleanup' EXIT
trap 'dl_cleanup; exit 130' INT
trap 'dl_cleanup; exit 143' TERM

# Build the panel from source ONLY when explicitly asked (BUILD_FROM_SOURCE=1).
# The default downloads the prebuilt release binary: a ~70MB transfer that needs
# just curl/wget (already chosen above). The source path recompiles the Xray core
# and the panel with a full toolchain (git, gcc, Go, and Docker unless
# SKIP_BACKEND=1), so it takes many minutes and depends on github.com being
# reachable for the clone — it exists only for platforms/commits without a
# prebuilt asset.
BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-0}"
case "$BUILD_FROM_SOURCE" in
    1|true|yes|on) BUILD_FROM_SOURCE=1 ;;
    *)             BUILD_FROM_SOURCE=0 ;;
esac

if [[ "$BUILD_FROM_SOURCE" == "1" ]]; then
    msg "Building from source (BUILD_FROM_SOURCE=1)"
    if ! command -v git >/dev/null 2>&1; then
        act "installing git..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y git >/dev/null 2>&1
        fi
    fi
    if ! command -v gcc >/dev/null 2>&1; then
        act "installing gcc for CGO (SQLite)..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -y -qq gcc >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y gcc >/dev/null 2>&1
        fi
    fi
    if ! command -v go >/dev/null 2>&1 || [[ "$(go version 2>/dev/null)" < "go version go1.22" ]]; then
        act "installing Go 1.26..."
        GO_VER="1.26.5"
        GO_ARCH="$(uname -m)"
        case "$GO_ARCH" in
            x86_64)  GO_ARCH="amd64" ;;
            aarch64) GO_ARCH="arm64" ;;
            armv7l)  GO_ARCH="armv6l" ;;
        esac
        curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz" | tar -C /usr/local -xzf - >/dev/null 2>&1 \
            || die "failed to download Go ${GO_VER}."
        export PATH="/usr/local/go/bin:$PATH"
    fi
    if ! command -v docker >/dev/null 2>&1; then
        act "installing Docker..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y -qq ca-certificates curl gnupg >/dev/null 2>&1
            install -m 0755 -d /etc/apt/keyrings
            if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/tmp/docker_gpg_err; then
                warn "Docker GPG key failed — will build without Docker (daemons from system packages)"
            else
                chmod a+r /etc/apt/keyrings/docker.gpg
                UBUNTU_CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $UBUNTU_CODENAME stable" > /etc/apt/sources.list.d/docker.list
                if ! apt-get update -qq 2>/tmp/docker_apt_err; then
                    warn "Docker apt repo failed — will build without Docker"
                elif ! apt-get install -y -qq docker-ce docker-ce-cli containerd.io 2>/tmp/docker_install_err; then
                    warn "Docker package install failed — will build without Docker"
                fi
            fi
            systemctl enable --now docker >/dev/null 2>&1 || true
        elif command -v dnf >/dev/null 2>&1; then
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>&1
            dnf install -y docker-ce docker-ce-cli containerd.io >/dev/null 2>&1 || warn "Docker install failed — will build without Docker"
            systemctl enable --now docker >/dev/null 2>&1 || true
        fi
    fi
    if command -v docker >/dev/null 2>&1; then
        act "Docker version: $(docker --version 2>/dev/null | head -1)"
    else
        warn "Docker not available — backend daemon bundle will be skipped"
    fi
    GO_VER="$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1)"
    act "Go version: ${GO_VER:-unknown}"
    BUILD_DIR="$(mktemp -d)"
    trap 'dl_cleanup; rm -rf "$BUILD_DIR"' EXIT
    act "cloning $REPO..."
    # Errors are shown, not swallowed: a clone that dies on the wire reads like
    # "connection reset", not "git clone failed." --shallow-submodules keeps the
    # submodule clones shallow too (they would otherwise be FULL clones, which is
    # most of the transfer on a flaky link).
    if ! clone_out="$(git clone --depth 1 --recurse-submodules --shallow-submodules "https://github.com/$REPO.git" "$BUILD_DIR/src" 2>&1)"; then
        printf '%s\n' "$clone_out" | sed 's/^/    /' >&2
        die "git clone failed."
    fi
    act "building vpn-ui-amd64 (this may take several minutes)..."
    # Add temporary swap if memory is tight (Go compiler needs ~2GB). Track
    # whether WE created it so the teardown below only removes our own file.
    swapped=0
    if [[ ! -f /swapfile ]] && command -v fallocate >/dev/null 2>&1; then
        TOTAL_MEM="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
        if (( TOTAL_MEM < 3000000 )); then
            act "low memory, adding temporary swap..."
            SWAP_SIZE="$(( (3000000 - TOTAL_MEM) / 1024 + 512 ))M"
            fallocate -l "$SWAP_SIZE" /swapfile 2>/dev/null && chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile 2>/dev/null && swapped=1 || true
        fi
    fi
    # Use all available CPU cores for faster build, unless memory is tight
    NPROC="$(nproc 2>/dev/null || echo 1)"
    TOTAL_MEM="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    if (( TOTAL_MEM < 2000000 )); then
        act "low memory (${TOTAL_MEM}kB), building single-threaded with swap..."
        NPROC=1
    else
        act "building with ${NPROC} cores..."
    fi
    # Reuse a previously built Xray core + geo files instead of recompiling them
    # on every run. The clone lands in a fresh temp dir, so "inside the source
    # tree" can never cache across runs (the old check looked there and therefore
    # NEVER hit — every install rebuilt the core). Keep the artifacts under
    # $DEST_DIR and key the cache on the pinned Xray-core commit, the same stamp
    # build/core/build.sh writes: a bumped submodule misses and rebuilds itself.
    export SKIP_CORE=0
    export SKIP_SUBMODULES=0
    export SKIP_BACKEND="${SKIP_BACKEND:-1}"
    CORE_CACHE="$DEST_DIR/.core-cache/corebundle/core"
    CACHE_ARCH="$(go env GOARCH 2>/dev/null || echo amd64)"
    xray_commit="$(git -C "$BUILD_DIR/src/third_party/Xray-core" rev-parse HEAD 2>/dev/null || true)"
    if [[ -n "$xray_commit" && -f "$CORE_CACHE/$CACHE_ARCH/xray" \
          && "$(cat "$CORE_CACHE/$CACHE_ARCH/.xray.commit" 2>/dev/null || true)" == "$xray_commit" ]]; then
        install -d -m 0755 "$BUILD_DIR/src/corebundle/core"
        cp -a "$CORE_CACHE/." "$BUILD_DIR/src/corebundle/core/"
        export SKIP_CORE=1
        export SKIP_SUBMODULES=1
        act "Xray core cache hit @ ${xray_commit:0:12} — skipping rebuild"
    else
        act "no cached Xray core for ${xray_commit:0:12} — it will be compiled"
    fi
    if [[ "$SKIP_BACKEND" == "1" ]]; then
        act "skipping backend daemon bundle (set SKIP_BACKEND=0 to include)"
    fi
    (cd "$BUILD_DIR/src" && GOGC=100 GOMAXPROCS="$NPROC" bash build.sh) \
        || die "build failed."
    # Cache the freshly built core + geo files for the next run. Under the
    # default download install this dir is simply never touched.
    if [[ -d "$BUILD_DIR/src/corebundle/core" && -f "$BUILD_DIR/src/corebundle/core/$CACHE_ARCH/xray" ]]; then
        install -d -m 0755 "$CORE_CACHE"
        cp -a "$BUILD_DIR/src/corebundle/core/." "$CORE_CACHE/"
        act "cached Xray core @ ${xray_commit:0:12} for future builds"
    fi
    # Remove the temporary swap (only if this run created it)
    if (( swapped )); then
        swapoff /swapfile 2>/dev/null && rm -f /swapfile 2>/dev/null || true
    fi
    if [[ -f "$BUILD_DIR/src/build/out/vpn-ui-amd64" ]]; then
        cp "$BUILD_DIR/src/build/out/vpn-ui-amd64" "$tmp"
    else
        die "build succeeded but output binary not found."
    fi
    rm -rf "$BUILD_DIR"
else
    # Default: fetch the prebuilt release binary (the fast path — no toolchain,
    # no clone, no compile). Try each mirror in order; fetch_asset renders the
    # progress line and returns the real transfer status.
    rc=1
    for url in "${MIRRORS[@]}"; do
        if [[ "$url" == *.gz && -x "$(command -v gzip 2>/dev/null)" ]]; then
            # dist-branch mirror is gzip (GitHub caps repo files at 100MB). Stream it
            # through gzip -dc straight into the destination so ONLY the decompressed
            # binary ever sits on disk — peak need ~1x the binary size, not ~3x.
            act "downloading from: $url (streaming, decompressing)"
            if curl -fL --retry 3 -sS "$url" 2>"$DL_ERR" | gzip -dc > "$tmp" 2>/dev/null; then
                rc=0; break
            fi
            [[ -s "$DL_ERR" ]] && warn "$(tail -n1 "$DL_ERR")"
            rm -f "$tmp" 2>/dev/null
        else
            act "downloading from: $url"
            if fetch_asset "$url" "$tmp"; then rc=0; break; fi
        fi
        warn "mirror failed, trying next"
    done
    (( rc == 0 )) || die "download failed (all mirrors)."
    DL_BYTES="$(stat -c %s "$tmp" 2>/dev/null || echo 0)"
    ok "downloaded $(fmt_bytes "$DL_BYTES")"
fi
# Back to the plain tmp-file cleanup for the rest of the run: nothing below this
# point owns a background job, so the download's signal handling ends here.
trap - INT TERM

# Sanity: non-empty and a real Linux ELF binary (not an HTML 404 page).
[[ -s "$tmp" ]] || die "downloaded file is empty."
if command -v file >/dev/null 2>&1; then
    file -b "$tmp" | grep -qi 'ELF' || die "downloaded file is not an ELF binary (got: $(file -b "$tmp"))."
else
    [[ "$(head -c4 "$tmp")" == $'\x7fELF' ]] || die "downloaded file is not an ELF binary."
fi

# Install the binary (stop the unit first if we're upgrading in place)
if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
    act "stopping running ${UNIT} for replacement"
    systemctl stop "$UNIT" || true
fi
# Also reap a panel launched OUTSIDE systemd (a bare ./vpn-ui): the stop above only
# touches the unit, so a hand-launched panel would keep the web + Xray ports bound and
# collide with the unit we (re)start below. Its orphaned Xray/daemons are then cleared
# by the fresh panel's own startup reap. Done before the new unit starts, so safe.
if command -v pkill >/dev/null 2>&1; then
    pkill -x vpn-ui 2>/dev/null || true
    pkill -x "$(basename "$DEST")" 2>/dev/null || true
fi

# Safety net: on update, snapshot the DB (timestamped + tagged with the outgoing
# version) before the new binary can touch or migrate it. The service is already
# stopped above, so copy the SQLite WAL/SHM sidecars alongside it for a consistent
# set. Abort if the copy fails — never replace the binary without a good backup.
if [[ "$MODE" == "update" && -f "$DB" ]]; then
    install -d -m 0755 "$BACKUP_DIR"
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="$BACKUP_DIR/vpn-ui_${OLD_VER:-unknown}_${ts}.db"
    cp -p "$DB" "$backup" || die "DB backup failed ($DB -> $backup) — aborting before replacing the binary."
    for side in wal shm; do
        [[ -f "$DB-$side" ]] && cp -p "$DB-$side" "$backup-$side" || true
    done
    ok "backed up DB -> $backup"
fi

chmod +x "$tmp"
# Fail loudly (not with a cryptic "No space left on device") if $DEST_DIR can't hold
# the binary. df reports 1K blocks; convert to bytes and compare against the downloaded size.
if command -v df >/dev/null 2>&1; then
    _have="$(df -Pk "$DEST_DIR" 2>/dev/null | awk 'NR==2{print $4*1024}')"
    if [[ "$_have" =~ ^[0-9]+$ && "$_have" -lt "$DL_BYTES" ]]; then
        die "not enough free space in $DEST_DIR (have $(fmt_bytes "$_have"), need ~$(fmt_bytes "$DL_BYTES")). Free disk space and retry."
    fi
fi
mv -f "$tmp" "$DEST"
trap - EXIT
ok "installed -> $DEST"

# Install/refresh the management menu on BOTH paths (fresh install and update), so
# `vpn-ui` always matches the binary that ships it. Must come before the TLS step
# below, which sources the menu for obtain_letsencrypt_cert.
msg "Installing the ${MENU} management menu"
# VPNUI_BIN is what the menu (and the sourced SSL function) resolve the panel
# binary from, so a non-default DEST_DIR carries through instead of falling back to
# the compiled-in /opt/vpn-ui default.
export VPNUI_BIN="$DEST"
if "$DEST" install-menu >/dev/null 2>&1 && [[ -r "$MENU" ]]; then
    ok "management menu -> ${MENU}  (run: ${TEAL}vpn-ui${R})"
    # Bring in obtain_letsencrypt_cert: the single implementation, shared rather
    # than copied. vpn-ui.sh does nothing at top level when sourced (its menu is
    # behind a sourced/executed guard), so this only defines functions.
    # shellcheck source=vpn-ui.sh
    source "$MENU"
else
    warn "could not install ${MENU}, so the 'vpn-ui' menu is unavailable on this host."
    # Keep the TLS branch below honest instead of letting an undefined function
    # abort the whole deploy: real SSL simply isn't on offer without the menu.
    obtain_letsencrypt_cert() { warn "real SSL needs ${MENU}, which failed to install. Skipping."; return 1; }
fi

# Configure + install/refresh the systemd unit. Fresh installs get randomized
# credentials (--random); updates DO NOT, so the operator's existing port, login
# and web path survive the upgrade.
if [[ "$MODE" == "install" ]]; then
    # Optional migration: import an existing 3x-ui (or vpn-ui) backup database before
    # the panel is configured, so an operator moving over keeps their inbounds,
    # clients, traffic and admin logins. The import preserves THIS install's own
    # port/path/TLS/secret, so only the operator's data comes across. Honour a preset
    # IMPORT_DB for non-interactive installs; otherwise ask on the controlling
    # terminal. A piped install with no IMPORT_DB set skips it and starts fresh.
    imported=""
    import_path="${IMPORT_DB:-}"
    if [[ -z "$import_path" ]]; then
        {
            printf '%s::%s %sExisting 3x-ui data%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
            printf '    Import inbounds, clients and traffic from a 3x-ui backup database?\n'
            printf '    Enter the path to the .db file, or leave blank to start fresh.\n'
            printf '  path: '
        } > /dev/tty
        read -r import_path < /dev/tty || import_path=""
    fi
    if [[ -n "$import_path" ]]; then
        if [[ -r "$import_path" ]]; then
            msg "Importing database from $import_path"
            if "$DEST" import --from "$import_path"; then
                imported="1"
                ok "Imported existing data. You will log in with that panel's credentials."
            else
                warn "Import failed, continuing with a fresh database."
            fi
        else
            warn "Cannot read '$import_path', continuing with a fresh database."
        fi
    fi

    # Panel transport: HTTP (default) or self-signed HTTPS. Honour PANEL_TLS when
    # preset (selfsign/https -> TLS; http -> plain); otherwise ask on the
    # controlling terminal. A piped, non-interactive install with no PANEL_TLS set
    # falls back to HTTP so `curl ... | sudo bash` never hangs on a prompt.
    tls_choice="http"
    case "${PANEL_TLS:-}" in
        letsencrypt|le|acme|real)        tls_choice="letsencrypt" ;;
        selfsign|https|self-signed|yes)  tls_choice="selfsign" ;;
        http|plain|0|no)                 tls_choice="http" ;;
        "")
            # A preset DEPLOY_DOMAIN or DEPLOY_CF_TOKEN implies a non-interactive
            # real-cert request; the sourced SSL function picks the challenge.
            if [[ -n "$DOMAIN" || -n "${DEPLOY_CF_TOKEN:-}" ]]; then
                tls_choice="letsencrypt"
            else
                {
                    printf '%s::%s %sPanel access mode%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
                    printf "    %s1)%s HTTPS  (real cert via Let's Encrypt: Cloudflare token, manual, or this server's IP)\n" "$GREEN" "$R"
                    printf '    %s2)%s HTTPS  (self-signed certificate)\n'                "$GREEN" "$R"
                    printf '    %s3)%s HTTP   (no TLS) %s[default]%s\n'                    "$GREEN" "$R" "$D" "$R"
                    printf '  choose [1/2/3]: '
                } > /dev/tty
                read -r _ans < /dev/tty || _ans=""
                case "$_ans" in
                    1) tls_choice="letsencrypt" ;;
                    2) tls_choice="selfsign" ;;
                esac
            fi
            ;;
        *) warn "unrecognized PANEL_TLS='${PANEL_TLS}' — defaulting to HTTP." ;;
    esac

    # Enable the chosen cert BEFORE --random so the randomized run sees the TLS
    # setting and prints an https:// URL. A failed Let's Encrypt attempt falls back
    # to plain HTTP rather than aborting the whole install.
    if [[ "$tls_choice" == "selfsign" ]]; then
        msg "Generating self-signed TLS certificate (HTTPS)"
        "$DEST" cert -selfsign
    elif [[ "$tls_choice" == "letsencrypt" ]]; then
        obtain_letsencrypt_cert || tls_choice="http"
    fi

    # Panel login / access: randomize everything (default) or enter custom values.
    # Ask on the controlling terminal; a piped, non-interactive install (curl ... |
    # sudo bash) has no tty and falls back to --random, so it never hangs on the
    # prompt nor installs empty credentials. The binary applies either choice with
    # the same work-safe stop/apply/restart envelope (--random / --user...--path).
    cred_mode="random"
    if [[ "$imported" == "1" ]]; then
        cred_mode="keep"
    else
        {
            printf '%s::%s %sPanel login / access%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
            printf '    %s1)%s Randomize  (port, username, password, web path) %s[default]%s\n' "$GREEN" "$R" "$D" "$R"
            printf '    %s2)%s Custom     (enter each value yourself)\n' "$GREEN" "$R"
            printf '  choose [1/2]: '
        } > /dev/tty
        read -r _cans < /dev/tty || _cans=""
        [[ "$_cans" == "2" ]] && cred_mode="custom"
    fi

    if [[ "$cred_mode" == "keep" ]]; then
        msg "Installing systemd unit (keeping the imported panel's login)"
        "$DEST" --systemd
    elif [[ "$cred_mode" == "custom" ]]; then
        msg "Enter panel login / access details (leave a field blank to keep the default)"
        printf '  %susername%s: ' "$BLUE" "$R" > /dev/tty; read -r  C_USER < /dev/tty || C_USER=""
        printf '  %spassword%s: ' "$BLUE" "$R" > /dev/tty; read -rs C_PASS < /dev/tty || C_PASS=""; printf '\n' > /dev/tty
        printf '  %sport%s: '     "$BLUE" "$R" > /dev/tty; read -r  C_PORT < /dev/tty || C_PORT=""
        printf '  %sweb path%s: ' "$BLUE" "$R" > /dev/tty; read -r  C_PATH < /dev/tty || C_PATH=""
        msg "Applying custom login / access + installing systemd unit"
        "$DEST" --user "$C_USER" --pass "$C_PASS" --port "$C_PORT" --path "$C_PATH" --systemd
    else
        msg "Configuring credentials + installing systemd unit"
        warn "--random sets a fresh port, username, password and web path — note them below."
        "$DEST" --random --systemd
    fi
else
    # Update: only touch TLS when explicitly requested (PANEL_TLS=letsencrypt, or a
    # DEPLOY_DOMAIN / DEPLOY_CF_TOKEN is set), so routine binary updates never change
    # the transport.
    if [[ "${PANEL_TLS:-}" =~ ^(letsencrypt|le|acme|real)$ || -n "$DOMAIN" || -n "${DEPLOY_CF_TOKEN:-}" ]]; then
        obtain_letsencrypt_cert || true
    fi
    msg "Refreshing systemd unit (existing credentials preserved)"
    "$DEST" --systemd
fi

msg "Starting ${UNIT}"
systemctl restart "$UNIT"
sleep 1
if systemctl is-active --quiet "$UNIT"; then
    ok "${UNIT} is running"
else
    die "${UNIT} failed to start — inspect with: journalctl -u ${UNIT} -e"
fi

# Done
hr
msg "Deploy complete"
if [[ "$MODE" == "install" ]]; then
    if [[ "${cred_mode:-random}" == "keep" ]]; then
        act "sign in with the username / password from the panel you imported"
    elif [[ "${cred_mode:-random}" == "custom" ]]; then
        act "your custom login (port / user / password / web path) was applied — see above"
    else
        act "the randomized login (port / user / password / web path) is printed above"
    fi
    if [[ "${tls_choice:-http}" == "letsencrypt" ]]; then
        act "panel serves ${GREEN}HTTPS${R} with a real cert for ${TEAL}${DOMAIN}${WILDCARD_SAN:+ + ${WILDCARD_SAN}}${R}, no browser warning"
        act "auto-renew runs via acme.sh (cron); SSTP can reuse ${TEAL}$CERT_DIR/fullchain.pem${R} + ${TEAL}$CERT_DIR/privkey.pem${R}"
    elif [[ "${tls_choice:-http}" == "selfsign" ]]; then
        act "panel serves ${GREEN}HTTPS${R} with a self-signed cert — the browser warns once; accept it to continue"
    fi
else
    act "updated to ${GREEN}${ver:-latest}${R} — your existing port / login / web path are unchanged"
    # `[[ … ]] && act …` would return 1 when there was no backup, and under set -e
    # that ends the script right here, swallowing the status/logs lines below on
    # any update that found no DB to snapshot.
    if [[ -n "${backup:-}" ]]; then
        act "DB backup: ${TEAL}${backup}${R}"
    fi
fi
if [[ -x "$MENU" ]]; then
    act "manage:  ${TEAL}vpn-ui${R}  (update, login, start/stop, Xray, SSL)"
fi
act "status:  ${TEAL}systemctl status ${UNIT}${R}"
act "logs:    ${TEAL}journalctl -u ${UNIT} -f${R}"
hr
