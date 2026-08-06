#!/usr/bin/env bash
#
# build/core/build.sh — Build the pinned Xray core + fetch the geo data files
# that get embedded into the panel binary (go:embed) and extracted at runtime by
# the `corebundle` package.
#
# The panel ships a SPECIFIC patched Xray-core fork (Sir-MmD/Xray-core) whose
# Shadowsocks per-user `method` fallback the product depends on. This script
# produces that exact core, statically linked (CGO_ENABLED=0) so it runs on any
# Linux distro, and drops it, plus every geo file the routing editor can name,
# where the go:embed picks them up.
#
# Output layout (consumed by corebundle's //go:embed all:core):
#   corebundle/core/<goarch>/xray
#   corebundle/core/geoip.dat   geosite.dat            (base pair)
#   corebundle/core/geo{ip,site}_{IR,RU}.dat           (unless GEO_LEAN=1)
#
# Usage:
#   build/core/build.sh [goarch...]        # default: amd64
#
# Source of truth is the pinned submodule third_party/Xray-core (@ a fixed
# commit). It's used automatically when present; the clone path below is only a
# fallback for checkouts where the submodule wasn't initialised.
#
# Env:
#   XRAY_SRC   path to a local Xray-core checkout (overrides the submodule)
#   XRAY_REPO  fork git URL for the fallback clone (default: Sir-MmD/Xray-core)
#   XRAY_REF   git ref for the fallback clone       (default: default branch)
#   GEO_ONLY=1 only refresh geo files, skip the core build
#   GEO_LEAN=1 embed ONLY geoip.dat + geosite.dat, dropping the ~118MB of country
#              files geo{ip,site}_{IR,RU}.dat. The panel then downloads whichever
#              one a routing rule needs, the first time it needs it.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_ROOT="$REPO_ROOT/corebundle/core"

# shellcheck source=../lib/log.sh
source "$REPO_ROOT/build/lib/log.sh" 2>/dev/null || { step(){ echo "==> $*"; }; ok(){ echo "  - $*"; }; info(){ echo "  $*"; }; warn(){ echo "  ! $*" >&2; }; err(){ echo "  x $*" >&2; }; hr(){ :; }; }

XRAY_REPO="${XRAY_REPO:-https://github.com/Sir-MmD/Xray-core}"
XRAY_REF="${XRAY_REF:-}"
ARCHES=("${@:-amd64}")

mkdir -p "$OUT_ROOT"

# --- base geo files (architecture-independent) ---------------------------------
# Same source the dashboard's "Update geofiles" uses (Loyalsoldier/v2ray-rules-dat),
# so the bundled fallback matches what a later dashboard update would fetch.
# Download one geo file ONLY when it changed. `-z <cached>` sends a conditional
# request (If-Modified-Since the cached file's mtime); the server answers 304 and
# no body when it's current, so we keep the cache and skip the ~14MB transfer. A
# fetch failure keeps the existing copy (geo is a runtime-updatable fallback).
# GEO_FORCE=1 always re-downloads.
_geo_one() {
    local url="$1" out="$2" tmp rc=0
    if [[ "${GEO_FORCE:-0}" != "1" && -s "$out" ]]; then
        tmp="$(mktemp)"
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 -z "$out" -o "$tmp" "$url" || rc=$?
        if [[ $rc -eq 0 && -s "$tmp" ]]; then
            mv "$tmp" "$out"; ok "$(basename "$out"): updated"
        elif [[ $rc -eq 0 ]]; then
            rm -f "$tmp"; info "$(basename "$out"): up to date (304) — skipped"
        else
            rm -f "$tmp"; warn "$(basename "$out"): download failed (rc=$rc) — keeping cached copy"; return 0
        fi
    else
        curl -fL --retry 3 --connect-timeout 15 --max-time 120 -o "$out" "$url" || {
            if [[ -s "$out" ]]; then
                warn "$(basename "$out"): download failed but file exists — keeping"; return 0
            fi
            return 1
        }
        ok "$(basename "$out"): fetched"
    fi
}

# Every geo data file the panel's routing editor can name, and the complete set
# `corebundle` embeds. It is exactly the six the Basic Routing lists reference:
# `geoip:`/`geosite:` shorthands resolve to the Loyalsoldier pair, and the
# Iran/Russia entries are explicit `ext:geoip_IR.dat:ir` style references
# (web/html/xray.html settingsData). Keep this list in sync with
# `builtinGeofiles` in web/service/geofile.go, which is what the panel downloads
# from at runtime.
#
# All six are fetched and embedded by DEFAULT. The four country files add ~118MB
# (geosite_RU.dat alone is ~74MB) on top of the ~28MB base pair, which is a
# deliberate trade: the servers this panel runs on are frequently the ones that
# cannot reach GitHub at runtime, and a geo file the core cannot open is a fatal
# config parse error that takes every inbound down, not a degraded rule.
# GEO_LEAN=1 keeps only the base pair for a smaller binary; the panel then
# downloads a country file the first time a rule needs it (web/service/geofile.go).
GEO_BASE_FILES=(
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat|geoip.dat"
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat|geosite.dat"
)
GEO_COUNTRY_FILES=(
    "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat|geoip_IR.dat"
    "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat|geosite_IR.dat"
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat|geoip_RU.dat"
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat|geosite_RU.dat"
)

_geo_batch() {
    local entry url name
    for entry in "$@"; do
        url="${entry%%|*}"
        name="${entry#*|}"
        _geo_one "$url" "$OUT_ROOT/$name"
        _geo_stamp "$url" "$OUT_ROOT/$name"
    done
}

# Set the local file's mtime to the upstream Last-Modified, rather than leaving it
# at "whenever curl happened to write it".
#
# This is what makes the panel's own updater honest. The panel asks upstream
# `If-Modified-Since: <local mtime>`, and geo files reach a user pre-extracted from
# the binary, where the mtime would otherwise be the INSTALL time. Data built in
# March and installed in June would then look newer than every release in between,
# so the server answers 304, the panel reports "updated successfully", and the
# stale data stays. It never self-corrects either: GitHub's 304 carries an ETag but
# no Last-Modified, so there is nothing for the panel to re-stamp from.
_geo_stamp() {
    local url="$1" out="$2" lm
    [[ -e "$out" ]] || return 0
    lm="$(curl -fsSIL --retry 2 --connect-timeout 10 --max-time 15 "$url" 2>/dev/null | grep -i '^last-modified:' | tail -1 | sed 's/^[Ll]ast-[Mm]odified:[[:space:]]*//' | tr -d '\r' || true)"
    if [[ -z "$lm" ]]; then
        info "$(basename "$out"): skipping stamp (upstream unreachable)"
        return 0
    fi
    if touch -d "$lm" "$out" 2>/dev/null; then
        ok "$(basename "$out"): dated $lm"
    else
        warn "$(basename "$out"): could not parse Last-Modified '$lm'; leaving mtime as-is"
    fi
}

# The embed drops file mtimes, so record them beside the data. corebundle reads
# this back and re-applies each date to the file it extracts, which is the whole
# point of _geo_stamp above.
write_geo_manifest() {
    local f name manifest="$OUT_ROOT/geo.stamp"
    : > "$manifest"
    for f in "$OUT_ROOT"/*.dat; do
        [[ -e "$f" ]] || continue
        name="$(basename "$f")"
        printf '%s\t%s\n' "$name" "$(stat -c %Y "$f")" >> "$manifest"
    done
    info "geo.stamp: $(wc -l < "$manifest") entries"
}

fetch_geo() {
    local entry name stale=()
    step "Checking geo files (conditional; GEO_FORCE=1 to force a refresh)"
    _geo_batch "${GEO_BASE_FILES[@]}"

    if [[ "${GEO_LEAN:-0}" == "1" ]]; then
        # Left behind by an earlier full build. They would still be embedded, so
        # remove them rather than let GEO_LEAN=1 quietly produce a ~118MB-fat binary.
        for entry in "${GEO_COUNTRY_FILES[@]}"; do
            name="${entry#*|}"
            if [[ -e "$OUT_ROOT/$name" ]]; then
                rm -f "$OUT_ROOT/$name"
                stale+=("$name")
            fi
        done
        if (( ${#stale[@]} )); then
            warn "GEO_LEAN=1: removed country geo files from a previous build: ${stale[*]}"
        fi
        info "GEO_LEAN=1: country geo files are NOT embedded; the panel downloads them on demand"
    else
        _geo_batch "${GEO_COUNTRY_FILES[@]}"
    fi

    # `|| true` on both: this script runs under `set -o pipefail`, so if the glob
    # matches nothing (a first run whose downloads all failed) the ls exits non-zero,
    # the pipeline inherits it, and the build dies here instead of at the real
    # failure. Same trap the submodule-status check documents above.
    write_geo_manifest
    info "geo: $(du -ch "$OUT_ROOT"/*.dat 2>/dev/null | tail -1 | awk '{print $1}' || true) across $(ls -1 "$OUT_ROOT"/*.dat 2>/dev/null | wc -l || true) file(s)"
    { ls -lh "$OUT_ROOT"/*.dat 2>/dev/null || true; } | awk '{print "    " $5, $9}'
}

# --- the pinned core -----------------------------------------------------------
prepare_src() {
    if [[ -n "${XRAY_SRC:-}" ]]; then
        echo "$XRAY_SRC"
        return
    fi
    # Prefer the pinned submodule checkout (third_party/Xray-core @ <sha>) — this
    # is the reproducible source of truth. Bump it with a normal submodule update.
    if [[ -f "$REPO_ROOT/third_party/Xray-core/go.mod" ]]; then
        echo "$REPO_ROOT/third_party/Xray-core"
        return
    fi
    # Fallback: submodule not initialised. Clone into a PERSISTENT cache (default
    # outside the repo so it survives fresh checkouts too) so we clone ONCE, then
    # only `git fetch` to pick up updates on later runs — never re-clone every
    # build. Override the location with XRAY_CACHE.
    local cache="${XRAY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/vpn-ui-build/Xray-core}"
    if [[ -d "$cache/.git" ]]; then
        info "reusing cached Xray-core clone ($cache); fetching updates" >&2
        git -C "$cache" remote set-url origin "$XRAY_REPO" >/dev/null 2>&1 || true
        if [[ -n "$XRAY_REF" ]]; then
            git -C "$cache" fetch --depth 1 origin "$XRAY_REF" >&2 2>&1 &&
                git -C "$cache" checkout -q FETCH_HEAD >&2 2>&1 || true
        else
            git -C "$cache" fetch --depth 1 origin >&2 2>&1 &&
                git -C "$cache" checkout -q FETCH_HEAD >&2 2>&1 || true
        fi
    else
        mkdir -p "$(dirname "$cache")"
        step "cloning Xray-core into cache $cache (first time only)" >&2
        if [[ -n "$XRAY_REF" ]]; then
            git clone --depth 1 --branch "$XRAY_REF" "$XRAY_REPO" "$cache" >&2
        else
            git clone --depth 1 "$XRAY_REPO" "$cache" >&2
        fi
    fi
    echo "$cache"
}

build_core() {
    local src
    src="$(prepare_src)"
    # The commit the source is at. If the cached xray was built from this same
    # commit, there is nothing to rebuild — skip the (slow) go build. Bump the
    # submodule/ref to trigger a rebuild, or set CORE_FORCE=1.
    local srccommit
    srccommit="$(git -C "$src" rev-parse HEAD 2>/dev/null || echo unknown)"
    info "pinned Xray core source: $src @ ${srccommit:0:12}"
    for goarch in "${ARCHES[@]}"; do
        local outdir="$OUT_ROOT/$goarch"
        mkdir -p "$outdir"
        local marker="$outdir/.xray.commit"
        if [[ "${CORE_FORCE:-0}" != "1" && -x "$outdir/xray" && "$srccommit" != "unknown" \
              && "$(cat "$marker" 2>/dev/null)" == "$srccommit" ]]; then
            ok "core ($goarch) already built from ${srccommit:0:12} — skipping (CORE_FORCE=1 to rebuild)"
            continue
        fi
        step "go build xray ($goarch, CGO_ENABLED=0, static)"
        ( cd "$src" && \
          CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
          go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -v -o "$outdir/xray" ./main )
        chmod 0755 "$outdir/xray"
        echo "$srccommit" > "$marker"
        file "$outdir/xray" || true
        ok "core: $(ls -lh "$outdir/xray" | awk '{print $5, $9}')"
    done
}

fetch_geo
if [[ "${GEO_ONLY:-0}" != "1" ]]; then
    build_core
fi
step "Done. Embed contents:"
ls -lhR "$OUT_ROOT"
