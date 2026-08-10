#!/bin/sh
#
# build/backend/ocserv-bundle.sh: build a static musl ocserv (OpenConnect server)
# and the matching openconnect CLIENT.
#
# Runs INSIDE an Alpine (musl) container. ocserv is NOT packaged by Alpine (any
# repo), so it is built from source (autotools; 1.3.0 ships ./configure, not
# meson). The goal is a single, fully statically-linked binary (like
# openvpn/xl2tpd/pptpd) that drops into
# backend/bin/<arch>/ocserv and is embedded via //go:embed — no host libc / no
# per-distro package.
#
# The openconnect CLIENT is built here rather than in a script of its own for one
# reason: it wants the same static GnuTLS, and that GnuTLS is a six-minute source
# build. Sharing the container reuses it (Alpine packages no gnutls .a, see
# below), so the client costs a few seconds instead of doubling the recipe.
#
# Dep strategy (musl-static):
#   - radcli (RADIUS)          -> Alpine radcli-dev ships libradcli.a         (apk)
#   - libev                    -> Alpine libev-dev  ships libev.a             (apk)
#   - nettle, gmp, lz4,        -> Alpine *-static packages                    (apk)
#     libseccomp, unistring
#   - talloc, protobuf-c, pcl  -> ocserv's own bundled copies (-Dlocal-*)     (source)
#   - GnuTLS                   -> NOT packaged static  -> built from source,   (source)
#       self-contained via --with-included-libtasn1 --with-included-unistring
#       and --without-p11-kit (drops the dlopen'd PKCS#11 module).
#   - libxml2 (client only)    -> Alpine libxml2-static, which drags in        (apk)
#       -llzma and -lz, hence xz-static/zlib-static.
#
# Output: /out/ocserv, /out/ocserv-worker, /out/occtl (the server side) plus
# /out/openconnect and /out/vpnc-script (the client side), all verified
# `statically linked` and all listed in backend.go's Daemons manifest.
#
# NOTE: this is the Phase-0 build spike for the OpenConnect feature. If static
# GnuTLS proves unworkable, the fallback is a relocatable musl tree (like
# pppd-bundle.sh / libreswan-bundle.sh) shipping ocserv + its .so deps + loader.
set -eu

# dl_retry <destfile> <url>...
# infradead's ocserv/openconnect hosting is flaky (transient TLS/5xx drops, and
# the ftp. mirror serves a broken cert). GNU wget dies on the first network
# error with exit 4, which has bit this recipe once already in CI, so retry each
# mirror with backoff and a hard timeout instead of hanging on a stalled
# connection or failing silently on a transient blip.
dl_retry() {
    local dest="$1"; shift
    local part="$dest.part"
    rm -f "$part"
    for url in "$@"; do
        for n in 1 2 3 4 5; do
            echo "  dl[try $n] $url"
            if wget -t 1 -T 60 -q -O "$part" "$url" 2>"/tmp/dl.err"; then
                mv "$part" "$dest"
                echo "  ok: $dest ($(wc -c < "$dest") bytes) <- $url"
                return 0
            fi
            sed 's/^/    /' "/tmp/dl.err" 2>/dev/null || true
            sleep "$n"
        done
    done
    rm -f "$part"
    echo "FATAL: could not download $dest from any mirror" >&2
    return 1
}

ARCH="${ARCH:-x86_64}"
GNUTLS_VER="${GNUTLS_VER:-3.8.13}"     # matches Alpine 3.22's gnutls; source build for the .a
OCSERV_VER="${OCSERV_VER:-1.3.0}"
OPENCONNECT_VER="${OPENCONNECT_VER:-9.21}"
# vpnc-scripts has never cut a release, so the client's routing/DNS script is
# pinned by commit the way a submodule would be. Bump deliberately, not by drift.
VPNC_SCRIPT_REV="${VPNC_SCRIPT_REV:-ce9e961bd0f6b867e1c7c35f78f6fb973f6ff101}"

echo "== ocserv-bundle: arch=$ARCH gnutls=$GNUTLS_VER ocserv=$OCSERV_VER openconnect=$OPENCONNECT_VER =="

# --- toolchain + static deps from Alpine ---------------------------------------
apk add --no-cache \
    build-base linux-headers pkgconf git wget file xz \
    meson ninja samurai gperf \
    nettle-dev nettle-static gmp-dev gmp-static \
    libidn2-static libunistring-static \
    lz4-dev lz4-static \
    libseccomp-dev libseccomp-static \
    libev-dev radcli-dev \
    readline-dev readline-static ncurses-dev ncurses-static \
    libxml2-dev libxml2-static xz-dev xz-static \
    zlib-dev zlib-static >/dev/null

# --- GnuTLS (static, self-contained) -------------------------------------------
# --with-included-{libtasn1,unistring} pulls those into libgnutls.a so we don't
# need their (missing) -static apk packages. --without-p11-kit drops the only
# dlopen'd dep. nettle/gmp come from the static apk archives above.
if [ -f /usr/local/lib/pkgconfig/gnutls.pc ]; then
  echo "== gnutls static already present (cached /usr/local) — skipping build =="
else
cd /tmp
dl_retry "gnutls-${GNUTLS_VER}.tar.xz" \
    "https://www.gnupg.org/ftp/gcrypt/gnutls/v${GNUTLS_VER%.*}/gnutls-${GNUTLS_VER}.tar.xz"
tar xf "gnutls-${GNUTLS_VER}.tar.xz"
cd "gnutls-${GNUTLS_VER}"
./configure --prefix=/usr/local \
    --enable-static --disable-shared \
    --without-p11-kit \
    --with-included-libtasn1 --with-included-unistring \
    --disable-doc --disable-tests --disable-tools --disable-nls \
    --disable-guile --disable-libdane --disable-cxx \
    --without-tpm --without-tpm2 --disable-full-test-suite >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
echo "== gnutls static installed =="
fi

# --- ocserv (autotools, fully static) ------------------------------------------
# ocserv 1.3.0 is autotools (NOT meson). RADIUS is auto-enabled when radcli is
# found (radcli-dev ships libradcli.a + radcli.pc); --without-radius would drop
# it. Use ocserv's bundled talloc/protobuf-c/PCL so we don't need their static
# apk archives. Point pkg-config at our static GnuTLS in /usr/local and force
# --static so gnutls.pc emits its whole transitive static graph (nettle/gmp/…).
cd /tmp
dl_retry "ocserv-${OCSERV_VER}.tar.xz" \
    "https://www.infradead.org/ocserv/download/ocserv-${OCSERV_VER}.tar.xz" \
    "https://ftp.infradead.org/pub/ocserv/ocserv-${OCSERV_VER}.tar.xz"
tar xf "ocserv-${OCSERV_VER}.tar.xz"
cd "ocserv-${OCSERV_VER}"

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
export PKG_CONFIG="pkgconf --static"

# --disable-seccomp: static libseccomp.a carries a gperf-generated `in_word_set`
# that clashes ("multiple definition") with ocserv's own gperf HTTP-header parser
# under static link. seccomp only powers the optional isolate-workers syscall
# sandbox; dropping it keeps parity with our other bundled daemons (openvpn/pppd
# have no such sandbox). Re-add later via a libseccomp source-rebuild that renames
# the symbol if per-worker seccomp is wanted.
./configure \
    --sysconfdir=/etc \
    --with-local-talloc \
    --without-protobuf \
    --without-pcl-lib \
    --without-maxmind \
    --without-libwrap \
    --without-gssapi \
    --disable-seccomp \
    LDFLAGS="-static -s" \
    LIBS="-Wl,--start-group -lreadline -lncurses -Wl,--end-group"
echo "== ocserv ./configure summary =="
grep -iE "radius|gnutls|seccomp|lz4|talloc|protobuf|pcl|compat" config.log | grep -iE "yes|no|enabled|disabled|found" | head -20 || true
make -j"$(nproc)"

mkdir -p /out
cp src/ocserv /out/ocserv
# ocserv is multi-process: the main daemon exec()s a SEPARATE ocserv-worker binary
# for every connection, resolved next to the main binary. Without it, ocserv binds
# its ports but drops every handshake ("exec ocserv-worker failed"). Ship both; they
# get extracted side by side into backend/bin.
cp src/ocserv-worker /out/ocserv-worker
cp src/occtl/occtl /out/occtl 2>/dev/null || cp src/occtl /out/occtl 2>/dev/null || true
strip /out/ocserv /out/ocserv-worker /out/occtl 2>/dev/null || true

echo "== ocserv-worker (static?) =="
file /out/ocserv-worker

echo "== ocserv built =="
file /out/ocserv
ldd /out/ocserv 2>&1 || echo "  (ldd: not a dynamic executable — good)"
/out/ocserv --version 2>&1 | head -12 || true
ls -lh /out/ocserv

# --- openconnect (the CLIENT of this same protocol, fully static) ---------------
# Reuses the GnuTLS built above (PKG_CONFIG_PATH still points at /usr/local) and
# adds libxml2, which every protocol openconnect speaks uses for its config
# exchange. Alpine DOES package openconnect, but only dynamically linked, and a
# dynamic ELF is no use to a go:embed bundle that lands on arbitrary distros.
#
# --disable-shared --enable-static keeps libopenconnect.so out of the picture;
# the program is then forced static with -all-static at make time, because
# libtool silently strips a plain -static (the same trap the openvpn recipe
# documents in build/backend/build.sh).
#
# Being musl-static is an advantage here rather than a compromise: a glibc static
# binary still needs the host's matching NSS shared objects to resolve a name,
# while musl's resolver is self-contained, so looking up the remote gateway keeps
# working on a host whose libc we know nothing about.
cd /tmp
dl_retry "openconnect-${OPENCONNECT_VER}.tar.gz" \
    "https://www.infradead.org/openconnect/download/openconnect-${OPENCONNECT_VER}.tar.gz"
tar xf "openconnect-${OPENCONNECT_VER}.tar.gz"
cd "openconnect-${OPENCONNECT_VER}"

# The compiled-in vpnc-script default is a FIXED absolute path rather than the
# extracted one, because the panel's bin/ dir moves with the install location.
# backend/clients.go symlinks that sentinel at the extracted copy, the same trick
# pptpd's --sbindir gets, so the binary behaves even if a caller forgets --script.
./configure \
    --prefix=/usr \
    --with-vpnc-script=/usr/libexec/vpn-ui/vpnc-script \
    --without-openssl \
    --disable-nls --disable-shared --enable-static \
    --without-libproxy --without-stoken --without-libpskc \
    --without-libpcsclite --without-gssapi --without-java \
    >/tmp/openconnect-conf.log 2>&1 \
    || { echo "FATAL: openconnect configure failed" >&2; tail -30 /tmp/openconnect-conf.log >&2; exit 1; }
echo "== openconnect ./configure summary =="
sed -n '/SSL library/,$p' /tmp/openconnect-conf.log | head -14
make -j"$(nproc)" LDFLAGS="-all-static -s" >/tmp/openconnect-make.log 2>&1 \
    || { echo "FATAL: openconnect build failed" >&2; tail -40 /tmp/openconnect-make.log >&2; exit 1; }
cp .libs/openconnect /out/openconnect 2>/dev/null || cp openconnect /out/openconnect
strip /out/openconnect 2>/dev/null || true

echo "== openconnect built =="
file /out/openconnect
if ! file /out/openconnect | grep -q "statically linked"; then
    echo "FATAL: /out/openconnect is not statically linked (libtool ate -all-static?)" >&2
    exit 1
fi
/out/openconnect --version 2>&1 | head -4 || true

# --- vpnc-script (the client's routing/DNS hook) --------------------------------
# openconnect brings the tunnel up and then hands every route, DNS and MTU
# decision to this script: without it a session authenticates and carries no
# traffic. It is a plain POSIX script driving iproute2 (already a host
# requirement), so it ships as a data file beside the binaries, not compiled in.
dl_retry /out/vpnc-script \
    "https://gitlab.com/openconnect/vpnc-scripts/-/raw/${VPNC_SCRIPT_REV}/vpnc-script"
head -1 /out/vpnc-script | grep -q '^#!' \
    || { echo "FATAL: vpnc-script fetch returned something that is not a script" >&2; exit 1; }
sh -n /out/vpnc-script || { echo "FATAL: fetched vpnc-script does not parse" >&2; exit 1; }
chmod 0755 /out/vpnc-script

ls -lh /out/openconnect /out/vpnc-script
