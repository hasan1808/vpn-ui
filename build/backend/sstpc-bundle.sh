#!/bin/sh
#
# build/backend/sstpc-bundle.sh: build the static musl SSTP CLIENT (sstpc) plus
# the pppd plugin an SSTP handshake cannot complete without.
#
# Runs INSIDE an Alpine (musl) container. accel-ppp gives us the SSTP SERVER
# (build/backend/accel-ppp-bundle.sh) and has no client mode at all, so dialing
# OUT to somebody else's SSTP server needs a second, unrelated project:
# sstp-client (https://gitlab.com/sstp-project/sstp-client). Alpine packages
# neither, so this is a source build like ocserv.
#
# TWO outputs, and the second is the one that is easy to miss:
#   /out/sstpc-bundle.tgz     the client as a relocatable musl tree + launcher
#   /out/sstp-pppd-plugin.so  loaded by pppd, NOT by sstpc
#
# sstpc terminates the TLS/SSTP layer and hands the PPP session to pppd. The
# protocol then demands a "crypto binding": proof that the peer which just
# authenticated over PPP owns the TLS channel too, derived from the MPPE master
# keys that only pppd ever sees. pppd passes them out through this plugin, so
# without it sstpc cannot answer the server's Call-Connected challenge, and any
# server that verifies the binding (Windows RRAS does, and so does accel-ppp,
# which is what our own SSTP core runs) drops the call right after a successful
# login. That makes the .so exactly as load-bearing as the binary.
#
# ONE build, and NOT a static one. This used to relink sstpc with -all-static in a
# second phase, and that binary could never work: see the tree section below, where
# the reason and the measurement are. The plugin still comes out of the ordinary
# build, which is what libtool needs to emit it as a real shared object at all
# (-all-static on a library target means "static library, please", and a .a cannot
# be dlopen'd).
#
# Output: the tree as /out/sstpc-bundle.tgz (consumed by backend/sstpc.go, extracted
# to the fixed PREFIX) plus the flat /out/sstp-pppd-plugin.so, which stays flat
# because pppd dlopens it by an absolute path this panel passes in and it is linked
# to carry no dependency of its own.
#
# HOST LIBC CONSTRAINT: the plugin is musl-linked, so only a musl pppd can load
# it. That is the BUNDLED pppd (backend.PppdBundled), never a distro one, so the
# SSTP-client dial path has to invoke the bundled pppd by absolute path rather
# than going through backend.UsingBundledPppd (which defers to a host pppd when
# one exists).
set -eu

PREFIX=/usr/libexec/vpn-ui-sstpc          # must equal backend.SstpcBundleRoot
ARCH="${ARCH:-x86_64}"
LOADER="ld-musl-${ARCH}.so.1"
# Assembled at its REAL deploy path inside the disposable build container, because the
# launcher hard-codes $PREFIX and the relocation self-check below only resolves when
# the tree actually lives there. Same approach as strongswan-bundle.sh.
DEST="$PREFIX"
SSTP_VER="${SSTP_VER:-1.0.20}"

echo "== sstpc-bundle: arch=$ARCH sstp-client=$SSTP_VER prefix=$PREFIX =="
rm -rf "$DEST"

# --- toolchain + deps ----------------------------------------------------------
# ppp-dev is what makes the plugin possible: it ships pppd's headers AND pppd.pc,
# which is where sstp-client reads the plugin ABI version from. ppp itself is
# here for the load self-check at the bottom.
apk add --no-cache \
    build-base linux-headers pkgconf wget file \
    autoconf automake libtool \
    openssl-dev openssl-libs-static \
    libevent-dev libevent-static \
    ppp ppp-dev >/dev/null

# The plugin is an ABI contract with ONE pppd version: pppd refuses a plugin
# built against another. The pppd that will load it is the one
# build/backend/pppd-bundle.sh harvests from this same Alpine release, so the
# versions agree by construction. Read it back anyway and print it, so a future
# Alpine bump that moves only one of the two is visible in the build log.
PPP_VER="$(pkgconf --modversion pppd 2>/dev/null || ls /usr/lib/pppd | head -1)"
[ -n "$PPP_VER" ] || { echo "FATAL: cannot determine the Alpine ppp version (no pppd.pc, no /usr/lib/pppd)" >&2; exit 1; }
[ -d "/usr/lib/pppd/$PPP_VER" ] || { echo "FATAL: /usr/lib/pppd/$PPP_VER missing: ppp-dev and ppp disagree on the version" >&2; exit 1; }
echo "== building against ppp $PPP_VER (must match pppd-bundle.sh) =="

# Download with retries + backoff (same hardening as the other recipes; the
# bare `wget -q` dies silently with exit 4 on a transient network blip).
dl_retry() {
    local d="$1"; shift
    for url in "$@"; do
        for n in 1 2 3 4 5; do
            echo "  dl[try $n] $url"
            if wget -t 1 -T 60 -q -O "$d" "$url" 2>/tmp/dl.err; then
                echo "  ok: $url -> $d ($(wc -c < "$d") bytes)"
                return 0
            fi
            sleep "$n"
        done
    done
    echo "FATAL: download failed: $d" >&2
    exit 1
}

# --- source --------------------------------------------------------------------
# The project moved off SourceForge; GitLab is the only place 1.0.20 exists, and
# a GitLab archive is a git snapshot with no ./configure, hence autogen.sh.
cd /tmp
dl_retry sstp-client.tar.gz \
    "https://gitlab.com/sstp-project/sstp-client/-/archive/${SSTP_VER}/sstp-client-${SSTP_VER}.tar.gz"
tar xf sstp-client.tar.gz
cd "sstp-client-${SSTP_VER}"
./autogen.sh >/dev/null 2>&1

# --with-pic is not cosmetic: it makes the static libsstp_api archive PIC, which
# is what lets the plugin absorb it below instead of pulling in a second .so.
./configure \
    --prefix=/usr \
    --enable-ppp-plugin \
    --with-pic \
    --with-pppd-plugin-dir="/usr/lib/pppd/$PPP_VER" \
    --with-runtime-dir=/var/run/sstpc >/tmp/sstp-conf.log 2>&1 \
    || { echo "FATAL: sstp-client configure failed" >&2; tail -30 /tmp/sstp-conf.log >&2; exit 1; }
echo "== sstp-client ./configure summary =="
sed -n '/sstp-client version/,$p' /tmp/sstp-conf.log | head -20

# MPPE-Keys is the plugin capability the crypto binding is built on. configure
# turns it off silently when the headers do not expose the key accessors, which
# would produce a plugin that loads and then never answers. Refuse that build.
grep -q "MPPE-Keys.*yes" /tmp/sstp-conf.log \
    || { echo "FATAL: configure disabled MPPE key export: the SSTP crypto binding cannot be computed" >&2; exit 1; }

# --- phase 1: normal build (gives us the plugin as a real .so) ------------------
make -j"$(nproc)" >/tmp/sstp-make.log 2>&1 \
    || { echo "FATAL: sstp-client build failed" >&2; tail -40 /tmp/sstp-make.log >&2; exit 1; }

# --- the relocatable tree ------------------------------------------------------
# sstpc is DYNAMIC and travels with its libraries, for one reason: OpenSSL 3 keeps
# MD4 in the `legacy` PROVIDER, which is a dlopen'd module, and sstpc needs MD4.
# It hashes the password to the NT hash and derives the MPPE keys itself
# (sstp_chap_hash_pass -> sstp_chap_mppe_get, called on SSTP_PPP_AUTH) to answer the
# server's crypto binding. A fully static musl binary cannot dlopen anything at all,
# so the static build this used to produce failed on EVERY host before it opened a
# socket:
#
#     Could not load legacy crypto provider
#     Could not initialize secure socket layer
#     **Error: Could not initialize the client, (-1)
#
# and it did so identically whatever the operator configured, because nothing about
# the configuration was involved. The old self-check could not see it: `sstpc --help`
# exits before client init, so it passed on a binary that could never connect. The
# check at the bottom now DIALS, which is where this fails.
#
# Same shape as pppd/accel-ppp/strongSwan, and the same launcher trick: entry point is
# a shell wrapper that runs the musl loader with --library-path, so the tree works on
# a glibc host, and exports OPENSSL_MODULES so the legacy provider is found.
mkdir -p "$DEST/sbin" "$DEST/lib" "$DEST/lib/ossl-modules"

# `make install`, not `cp src/sstpc`. sstpc links against the project's own
# libsstp_api, so while it is UNINSTALLED libtool leaves a shell WRAPPER at src/sstpc
# (the real ELF hides in src/.libs) whose job is to point the loader at the build
# tree. Copying that wrapper produced a bundle whose "binary" was a shell script, and
# the launcher's musl loader answered "Not a valid dynamic program". Installing makes
# libtool relink the program against the installed library and put a real ELF at
# /usr/sbin/sstpc, which is also what makes the ldd walk below resolve libsstp_api.
# Installing into the container's own /usr is safe: the container is disposable, and
# the tree we ship is assembled at $PREFIX.
make install >/tmp/sstp-install.log 2>&1 \
    || { echo "FATAL: sstp-client install failed" >&2; tail -30 /tmp/sstp-install.log >&2; exit 1; }
[ -f /usr/sbin/sstpc ] || { echo "FATAL: /usr/sbin/sstpc missing after install" >&2; exit 1; }
cp /usr/sbin/sstpc "$DEST/sbin/sstpc.bin"
strip "$DEST/sbin/sstpc.bin" 2>/dev/null || true
file "$DEST/sbin/sstpc.bin" | grep -q "ELF" \
    || { echo "FATAL: $DEST/sbin/sstpc.bin is not an ELF (libtool wrapper again?)" >&2; file "$DEST/sbin/sstpc.bin" >&2; exit 1; }

# The provider itself. It is dlopen'd on demand, so ldd never names it and the
# collect() below would miss it.
[ -f /usr/lib/ossl-modules/legacy.so ] \
    || { echo "FATAL: /usr/lib/ossl-modules/legacy.so missing: sstpc could not compute the NT hash" >&2; exit 1; }
cp /usr/lib/ossl-modules/legacy.so "$DEST/lib/ossl-modules/legacy.so"

cp "/lib/$LOADER" "$DEST/lib/$LOADER"
ln -sf "$LOADER" "$DEST/lib/libc.musl-${ARCH}.so.1"

collect() {
    for f in "$@"; do
        [ -f "$f" ] || continue
        ldd "$f" 2>/dev/null | awk '/=>/ {print $3}' | while read -r lib; do
            [ -f "$lib" ] || continue
            base=$(basename "$lib")
            [ -e "$DEST/lib/$base" ] && continue
            cp -L "$lib" "$DEST/lib/$base"
        done
    done
}
collect "$DEST/sbin/sstpc.bin" "$DEST/lib/ossl-modules/legacy.so"
collect "$DEST"/lib/*.so*      # deps-of-deps (libssl -> libcrypto, etc.)

cat > "$DEST/sbin/sstpc" <<EOF
#!/bin/sh
# vpn-ui bundled sstpc launcher — do not edit (generated by sstpc-bundle.sh).
B=$PREFIX
export LD_LIBRARY_PATH="\$B/lib:\${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="\${OPENSSL_MODULES:-\$B/lib/ossl-modules}"
exec "\$B/lib/$LOADER" --library-path "\$B/lib" "\$B/sbin/sstpc.bin" "\$@"
EOF
chmod 0755 "$DEST/sbin/sstpc"

mkdir -p /out

# --- the plugin, relinked to depend on nothing but libc ------------------------
# As libtool builds it the plugin has a NEEDED entry on libsstp_api-0.so, the
# project's own shared lib. A dlopen'd object whose dependency is not on the
# loading process's library path just fails to load, and pppd's is not ours to
# set, so fold the (PIC) archive in and ship one file. The object name is
# libtool's mangling of the source file, so glob it rather than spelling it out.
PLUGIN_OBJ="$(ls src/pppd-plugin/.libs/*sstp-plugin.o 2>/dev/null | head -1)"
[ -n "$PLUGIN_OBJ" ] || { echo "FATAL: plugin object not found under src/pppd-plugin/.libs" >&2; exit 1; }
[ -f src/libsstp-api/.libs/libsstp_api.a ] || { echo "FATAL: PIC libsstp_api.a not built (did --with-pic take effect?)" >&2; exit 1; }
gcc -shared -o /out/sstp-pppd-plugin.so "$PLUGIN_OBJ" src/libsstp-api/.libs/libsstp_api.a
strip /out/sstp-pppd-plugin.so 2>/dev/null || true

# --- self-checks ---------------------------------------------------------------
echo "== sstpc built =="
file "$DEST/sbin/sstpc.bin"

# Relocation: the launcher must run the binary through the bundled musl loader.
echo "== sstpc relocation self-test =="
ver="$("$DEST/sbin/sstpc" --version 2>&1 || true)"
echo "$ver" | head -2
echo "$ver" | grep -q "sstp-client version" \
    || { echo "FATAL: bundled sstpc did not run via the musl-loader wrapper: $ver" >&2; exit 1; }

# THE check, and the one whose absence shipped a client that could not start. Running
# --help (or --version above) is NOT enough: both return before sstpc initialises
# OpenSSL, so the broken static build passed them for as long as it existed. Dial
# instead. 127.0.0.1:1 refuses instantly, so the run reaches client init, gets far
# enough to fail at the connection, and says so; a client that cannot initialise its
# crypto says something else entirely, which is exactly what is being tested for.
echo "== sstpc dial self-test (must reach the connect, not die in init) =="
out="$("$DEST/sbin/sstpc" --nolaunchpppd --log-stderr 127.0.0.1:1 2>&1 || true)"
echo "$out" | head -5
case "$out" in
    *"legacy crypto provider"*)
        echo "FATAL: sstpc cannot load OpenSSL's legacy provider, so it could never compute the" >&2
        echo "       NT hash the SSTP crypto binding needs. Either the tree is not carrying" >&2
        echo "       lib/ossl-modules/legacy.so, or the launcher is not exporting OPENSSL_MODULES." >&2
        exit 1 ;;
    *"Could not initialize"*)
        echo "FATAL: sstpc failed during client initialisation: $out" >&2
        exit 1 ;;
esac

echo "== sstp-pppd-plugin.so dependencies =="
readelf -d /out/sstp-pppd-plugin.so | grep NEEDED || true
if readelf -d /out/sstp-pppd-plugin.so | grep -q "libsstp"; then
    echo "FATAL: the plugin still needs libsstp_api-0.so: it would fail to dlopen outside the build tree" >&2
    exit 1
fi

# The real proof: pppd itself accepts it. Plugins are loaded during option
# parsing, so this prints "loaded" well before pppd gives up on the bogus device.
# A version-mismatched or symbol-short plugin dies right here instead.
echo "== pppd $PPP_VER load test =="
if pppd plugin /out/sstp-pppd-plugin.so nodetach noauth /dev/null 2>&1 | grep -q "loaded"; then
    echo "== OK: pppd $PPP_VER loads sstp-pppd-plugin.so =="
else
    echo "FATAL: pppd refused the plugin: it is built against the wrong ppp ABI" >&2
    pppd plugin /out/sstp-pppd-plugin.so nodetach noauth /dev/null 2>&1 | head -10 >&2
    exit 1
fi

# --- package -------------------------------------------------------------------
# Tarred at its real path so ExtractSstpcBundle (untar to /) recreates the prefix.
tar czf /out/sstpc-bundle.tgz -C / "${PREFIX#/}"
echo "== sstpc-bundle.tgz built (sstp-client $SSTP_VER, wrapper launcher, no patchelf) =="
tar tzf /out/sstpc-bundle.tgz | wc -l | awk '{print "== entries: "$1}'
ls -lh /out/sstpc-bundle.tgz /out/sstp-pppd-plugin.so
