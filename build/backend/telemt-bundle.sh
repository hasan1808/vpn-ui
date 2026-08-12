#!/bin/sh
#
# build/backend/telemt-bundle.sh: build a static musl telemt (MTProto Proxy)
# from the PINNED third_party/telemt submodule.
#
# Runs INSIDE a rust:alpine (musl) container with the submodule mounted at /src.
# This mirrors build/core/build.sh (the patched Xray-core): the fork
# github.com/Sir-MmD/telemt pins upstream telemt 3.4.23 and carries our patch on
# top, so WHAT is built is recorded as a submodule commit in git rather than as a
# tarball URL plus a pile of local .patch files that could silently stop applying.
#
# The fork's patch (see its commit message) adds [access.user_modes]: per-ACCOUNT
# connection modes. vpn-ui exposes modes per client, which upstream's process-wide
# [general.modes] cannot express: without it the panel's per-client mode toggles
# would gate the LINKS we hand out but not the proxy itself.
#
# Why this is the SIMPLEST bundle in the tree:
#   - No plugins. Unlike accel-ppp/strongSwan/pppd (which dlopen their features and
#     need a relocatable tree + musl loader wrapper), telemt is one binary. It goes
#     in backend.go's flat `Daemons` manifest, needs no *BinPath branch in
#     procmgr.go's daemonBin(), and needs no tgz staleness gate.
#   - No runtime data files. Direct-to-DC mode carries a built-in DC address table,
#     so there is no proxy-secret / proxy-multi.conf to fetch at startup.
#   - No kernel module, no nftables, no capabilities beyond binding the listen port.
#
# Dep strategy (musl-static): rust:alpine's host triple IS x86_64-unknown-linux-musl
# and defaults to crt-static for musl, but RUSTFLAGS sets it explicitly so the recipe
# does not depend on that default. telemt's TLS is rustls/ring (pure Rust + asm), NOT
# OpenSSL: so no openssl-dev, no *-static archives, nothing to source-build.
# cmake/perl exist only because ring's build script probes for a C toolchain.
#
# Output: /out/telemt (verified statically linked). Consumed by backend.go's
# Daemons list via {Name:"telemt"}.
set -eu

ARCH="${ARCH:-x86_64}"

echo "== telemt-bundle: arch=$ARCH (from pinned third_party/telemt) =="

# --- toolchain -----------------------------------------------------------------
apk add --no-cache build-base musl-dev pkgconf cmake perl file >/dev/null

echo "== toolchain =="
rustc --version
rustc -vV | grep host

# --- source (the pinned submodule, mounted read-only at /src) -------------------
if [ ! -f /src/Cargo.toml ]; then
    echo "FATAL: /src is not a telemt checkout: is third_party/telemt initialised?" >&2
    echo "       Run: git submodule update --init --recursive" >&2
    exit 1
fi
# Copy out of the read-only mount so cargo can write target/ without dirtying the
# submodule working tree.
cp -a /src /build
cd /build
rm -rf target

echo "== source =="
grep -m1 '^version' Cargo.toml
# The patches are the whole reason we build a fork rather than upstream, and EVERY
# one of them fails silently at runtime: telemt ignores config it does not know, so a
# binary missing a patch starts happily, serves traffic, and just quietly does not
# enforce the thing the panel asked for. So verify each one and refuse to produce a
# binary rather than ship one that lies.
#
# Check them INDIVIDUALLY, not as "is the fork checked out". This is not paranoia:
# `build.sh` runs `git submodule update` whenever the submodule sits at a commit the
# parent does not record, which silently rewinds the working tree to the recorded
# pin. A guard on one patch let a build through that had a LATER patch rewound away.
patch_present() {   # <name> <needle> <file>
    if ! grep -q "$2" "$3"; then
        echo "FATAL: third_party/telemt lacks the $1 patch (no '$2' in $3)." >&2
        echo "       The submodule is not at the expected Sir-MmD/telemt commit." >&2
        echo "       If you just bumped it, commit third_party/telemt in the parent:" >&2
        echo "       an uncommitted bump is REVERTED by build.sh's submodule sync." >&2
        exit 1
    fi
    echo "  $1 patch: present"
}
patch_present "[access.user_modes] (per-account modes)" "user_modes" src/config/types.rs
patch_present "upstreams.socks_user_from_account (per-client routing)" \
    "socks_user_from_account" src/config/types.rs
patch_present "[general.modes] hot-reload (live mode toggles)" \
    "cfg.general.modes = new.general.modes" src/config/hot_reload.rs

# --- build (fully static) ------------------------------------------------------
# --locked pins the whole dep graph to the committed Cargo.lock, so this recipe is
# reproducible and cannot silently pull a newer transitive crate.
export CARGO_HOME=/tmp/cargo
export RUSTFLAGS="-C target-feature=+crt-static"
# GCC 14+ turns implicit-function-declaration/implicit-int/int-conversion into hard
# errors; ring's C build script (via the `cc` crate, which honours $CFLAGS) would fail.
export CFLAGS="-Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion"

TRIPLE="${ARCH}-unknown-linux-musl"
echo "== building for $TRIPLE (this takes ~4 min) =="
cargo build --release --locked --target "$TRIPLE"

mkdir -p /out
cp "target/${TRIPLE}/release/telemt" /out/telemt
strip /out/telemt 2>/dev/null || true

echo "== telemt built =="
file /out/telemt
# Fail loudly rather than shipping a binary that needs a host loader: the panel
# go:embeds this and extracts it onto arbitrary distros, so a dynamic link would
# only surface as a runtime "no such file or directory" on a user's box.
if ! file /out/telemt | grep -q "static"; then
    echo "FATAL: /out/telemt is not statically linked" >&2
    exit 1
fi
ldd /out/telemt 2>&1 || echo "  (ldd: not a dynamic executable: good)"
/out/telemt --version 2>&1 | head -2 || true
ls -lh /out/telemt
