#!/usr/bin/env bash
#
# build/backend/build.sh — Build portable, statically-linked VPN daemon binaries
# that get embedded into the vpn-ui binary (go:embed) and extracted at runtime.
#
# "Daemon" is the historical name; the bundle also carries the CLIENT helpers
# (pptp, openconnect, sstpc) the panel dials OUT with, built by the same recipes
# as the servers they pair with.
#
# The daemons are built against musl (Alpine) and statically linked, so the
# resulting binaries run on any Linux distro/glibc version without depending on
# the host's package manager. This is what lets the panel "bake in" the backend
# instead of installing xl2tpd/libreswan/openvpn per-distro.
#
# Output layout (consumed by the `backend` Go package's //go:embed):
#   backend/bin/<goarch>/<daemon>
#
# Usage:
#   build/backend/build.sh [goarch...]     # default: amd64
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_ROOT="$REPO_ROOT/backend/bin"

# shellcheck source=../lib/log.sh
source "$REPO_ROOT/build/lib/log.sh" 2>/dev/null || { step(){ echo "==> $*"; }; ok(){ echo "  - $*"; }; info(){ echo "  $*"; }; warn(){ echo "  ! $*" >&2; }; err(){ echo "  x $*" >&2; }; hr(){ :; }; }

# goarch -> Alpine build platform (docker --platform)
declare -A PLATFORM=(
    [amd64]="linux/amd64"
    [arm64]="linux/arm64"
)

ARCHES=("${@:-amd64}")

build_arch() {
    local goarch="$1"
    local platform="${PLATFORM[$goarch]:-}"
    if [[ -z "$platform" ]]; then
        # Not an error: the Go embed simply has no bundle for this arch, so the
        # daemons fall back to the host package manager there. Keeps CI green for
        # arches we don't (yet) build daemons for (armv7, s390x, …).
        warn "No daemon bundle for '$goarch' (unsupported) — skipping"
        return 0
    fi
    local outdir="$OUT_ROOT/$goarch"
    mkdir -p "$outdir"

    step "Building daemons for $goarch ($platform)"
    # DOCKER_NET lets the caller pick host networking when the default bridge is
    # firewalled (common with firewalld on the build host).
    docker run --rm ${DOCKER_NET:-} --platform "$platform" -v "$outdir:/out" alpine:3.20 sh -euxc '
        apk add --no-cache build-base linux-headers pkgconf git wget file \
            openssl-dev openssl-libs-static libcap-ng-dev libcap-ng-static \
            lzo-dev lz4-dev lz4-static

        # Download with retries + backoff: swupdate.openvpn.org drops/rate-limits
        # automated fetches (it 403s the stock BusyBox wget User-Agent when it
        # has flagged the IP, so dl_retry sends a browser-like -U), and
        # sourceforge reconnects; the bare `wget -q` that used to sit here dies
        # silently with exit 4 on the first blip - which is how CI has failed
        # mid-recipe more than once.
        dl_retry() {
            local d="$1"; shift
            for url in "$@"; do
                for n in 1 2 3 4 5; do
                    echo "  dl[try $n] $url"
                    if wget -t 1 -T 60 -q -U "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" -O "$d" "$url" 2>/tmp/dl.err; then
                        echo "  ok: $url -> $d ($(wc -c < "$d") bytes)"
                        return 0
                    fi
                    sleep "$n"
                done
            done
            echo "FATAL: download failed: $d" >&2
            exit 1
        }

        # --- xl2tpd (static) ---
        git clone --depth 1 https://github.com/xelerance/xl2tpd /src/xl2tpd
        cd /src/xl2tpd
        # Only the main daemon + control tool are needed (pfc requires libpcap).
        make -j"$(nproc)" xl2tpd xl2tpd-control LDFLAGS="-static" 'CC=gcc -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion'
        cp xl2tpd xl2tpd-control /out/
        strip /out/xl2tpd /out/xl2tpd-control || true

        # --- openvpn (static) ---
        cd /tmp
        OVPN_VER=2.6.12
        dl_retry "openvpn-${OVPN_VER}.tar.gz" \
            "https://swupdate.openvpn.org/community/releases/openvpn-${OVPN_VER}.tar.gz"
        tar xf "openvpn-${OVPN_VER}.tar.gz"
        cd "openvpn-${OVPN_VER}"
        # No plugins/dco, but lzo AND lz4 are in: a provider profile that says
        # `comp-lzo` or `compress lz4` cannot be dialled at all by a binary built
        # without them, and plenty of them still do. Costs ~24KB.
        # Keep management (panel uses the mgmt socket). Force static archives for
        # the deps configure would otherwise take dynamically: pkg-config reports
        # the SHARED lzo/lz4, and -all-static then has nothing to link.
        # libtool strips a plain -static, so pass -all-static at make.
        ./configure --enable-lzo --enable-lz4 --disable-plugins --disable-dco --disable-unit-tests \
            OPENSSL_LIBS="-l:libssl.a -l:libcrypto.a" \
            LIBCAPNG_CFLAGS=" " LIBCAPNG_LIBS="-l:libcap-ng.a" \
            LZO_CFLAGS=" " LZO_LIBS="-l:liblzo2.a" \
            LZ4_CFLAGS=" " LZ4_LIBS="-l:liblz4.a"
        make -j"$(nproc)" LDFLAGS="-all-static -s" 'CC=gcc -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion'
        cp src/openvpn/openvpn /out/openvpn

        # --- pptpd (static) ---
        # pptpd execs pptpctrl at the compile-time SBINDIR path (no PATH lookup),
        # so pin it to a fixed sentinel that provisioning symlinks to the bundle.
        # Sourceforge 403s automated egress (rate-limits the IP after a few hits),
        # so the Ubuntu archive of the identical upstream tarball is the fallback.
        cd /tmp
        dl_retry pptpd.tar.gz \
            "https://downloads.sourceforge.net/project/poptop/pptpd/pptpd-1.4.0/pptpd-1.4.0.tar.gz" \
            "https://archive.ubuntu.com/ubuntu/pool/main/p/pptpd/pptpd_1.4.0.orig.tar.gz"
        tar xf pptpd.tar.gz
        cd pptpd-1.4.0
        ./configure --sbindir=/usr/libexec/vpn-ui
        make pptpd pptpctrl LDFLAGS="-static" 'CC=gcc -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion'
        cp pptpd pptpctrl /out/
        strip /out/pptpd /out/pptpctrl || true

        # --- pptp, the CLIENT half (static) ---
        # pptpd serves PPTP; this is the other direction, the pty helper pppd
        # drives to DIAL a remote PPTP server. Different upstream project
        # (pptpclient), no shared code, no library deps beyond libc, so it rides
        # along in this run instead of earning a container of its own.
        # PPPD_BINARY is compiled in as /usr/sbin/pppd, which is exactly where
        # backend.LinkSystemPppd points the bundled pppd, so the default is
        # already right; the panel drives the --nolaunchpppd form anyway, where
        # pppd is the parent and that path is never consulted.
        cd /tmp
        PPTP_VER=1.10.0
        dl_retry pptp.tar.gz \
            "https://downloads.sourceforge.net/project/pptpclient/pptp/pptp-${PPTP_VER}/pptp-${PPTP_VER}.tar.gz" \
            "https://deb.debian.org/debian/pool/main/p/pptp-linux/pptp-linux_${PPTP_VER}.orig.tar.gz"
        tar xf pptp.tar.gz
        cd "pptp-${PPTP_VER}"
        make -j"$(nproc)" pptp LDFLAGS="-static" 'CC=gcc -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion'
        cp pptp /out/pptp
        strip /out/pptp || true

        # configure DOWNGRADES a missing lzo/lz4 to a warning and builds anyway, so
        # the only proof the libraries made it in is the version banner the panel
        # itself probes (ovpnOutCompressionSupport in web/service/vpnout_openvpn.go).
        # --version exits non-zero by design, hence the `|| true`.
        ovpn_ver="$(/out/openvpn --version 2>&1 || true)"
        for feat in "[LZO]" "[LZ4]"; do
            case "$ovpn_ver" in
                *"$feat"*) ;;
                *) echo "ERROR: openvpn built without $feat" >&2; exit 1 ;;
            esac
        done

        # Confirm all outputs are static
        for b in /out/xl2tpd /out/xl2tpd-control /out/openvpn /out/pptpd /out/pptpctrl /out/pptp; do
            if ! file "$b" | grep -q "statically linked"; then
                echo "WARNING: $b is not statically linked" >&2
            fi
        done
    '

    # pppd relocatable bundle. pppd dlopens plugins + OpenSSL providers, so it
    # can't be one static binary — build/backend/pppd-bundle.sh assembles a
    # loader-relocated tree from Alpine's musl ppp/openssl packages. Separate
    # Alpine run so the (distro-package based) recipe stays self-contained.
    local muslarch
    case "$goarch" in
        amd64) muslarch=x86_64 ;;
        arm64) muslarch=aarch64 ;;
        *) muslarch="$goarch" ;;
    esac
    # Alpine 3.22 ships ppp 2.5.2. Do NOT drop below 3.21: ppp 2.5.0 (Alpine 3.20)
    # has a missing-braces bug in rc_read_config that makes the RADIUS plugin fail
    # to read ANY config file ("RADIUS: Can't read config file") — fixed in 2.5.1.
    step "Building pppd bundle for $goarch"
    docker run --rm ${DOCKER_NET:-} --platform "$platform" \
        -e ARCH="$muslarch" \
        -v "$outdir:/out" \
        -v "$REPO_ROOT/build/backend/pppd-bundle.sh:/pppd-bundle.sh:ro" \
        alpine:3.22 sh -e /pppd-bundle.sh

    # libreswan (IPsec) built with USE_DH2=true — the ALL_ALGS build that offers the
    # MODP1024 (DH2) group legacy L2TP/IPsec clients (Windows 7, old MikroTik) need,
    # which no distro package ships. Like pppd it can't be one static binary (NSS
    # dlopens freebl), so it ships as a relocatable musl tree. Slow to compile, so
    # it's cached with the rest of the bundle.
    step "Building libreswan (ALL_ALGS) bundle for $goarch"
    docker run --rm ${DOCKER_NET:-} --platform "$platform" \
        -e ARCH="$muslarch" \
        -v "$outdir:/out" \
        -v "$REPO_ROOT/build/backend/libreswan-bundle.sh:/libreswan-bundle.sh:ro" \
        alpine:3.22 sh -e /libreswan-bundle.sh

    # ocserv (OpenConnect server) — built from source (not packaged by Alpine) as a
    # single static musl binary WITH RADIUS (radcli) + AnyConnect compat. GnuTLS is
    # source-built static inside the recipe (the only dep Alpine ships no *-static
    # for). Emits /out/ocserv + /out/occtl. Separate Alpine 3.22 run so the recipe
    # stays self-contained, like pppd/libreswan above.
    # The same run also emits the CLIENT (/out/openconnect + /out/vpnc-script): it
    # needs that identical static GnuTLS, and rebuilding GnuTLS in a container of
    # its own would add ~6 minutes to every bundle build for no gain.
    step "Building ocserv (OpenConnect) server + client static binaries for $goarch"
    docker run --rm ${DOCKER_NET:-} --platform "$platform" \
        -e ARCH="$muslarch" \
        -v "$outdir:/out" \
        -v "$REPO_ROOT/build/backend/ocserv-bundle.sh:/ocserv-bundle.sh:ro" \
        alpine:3.22 sh -e /ocserv-bundle.sh

    # accel-ppp (SSTP server) — HARVESTED from Alpine's musl accel-ppp package into
    # a relocatable tree. accel-pppd dlopens its features as modules (libsstp.so,
    # libradius.so, libauth_mschap_v2.so, …) via libtriton, so it can't be one
    # static binary — same reason as pppd. Ships accel-pppd + accel-cmd +
    # /usr/lib/accel-ppp/*.so modules + RADIUS dictionaries + ldd deps + musl loader
    # as /out/accel-ppp-bundle.tgz, consumed by backend/accel.go. Separate Alpine
    # 3.22 run so the (distro-package based) recipe stays self-contained, like
    # pppd/libreswan above. (accel-ppp is Alpine community — has the SSTP module.)
    step "Building accel-ppp (SSTP) bundle for $goarch"
    docker run --rm ${DOCKER_NET:-} --platform "$platform" \
        -e ARCH="$muslarch" \
        -v "$outdir:/out" \
        -v "$REPO_ROOT/build/backend/accel-ppp-bundle.sh:/accel-ppp-bundle.sh:ro" \
        alpine:3.22 sh -e /accel-ppp-bundle.sh

    # sstpc (SSTP client): the other direction from accel-ppp above, which serves
    # SSTP and has no client mode at all, so this is a different upstream project
    # (sstp-client). Built from source on Alpine 3.22 because the pppd PLUGIN it
    # emits alongside the binary is an ABI contract with one exact ppp version,
    # and 3.22's ppp 2.5.2 is what pppd-bundle.sh harvests. Emits /out/sstpc-bundle.tgz
    # (a relocatable musl tree: sstpc needs MD4 from OpenSSL 3's dlopen'd legacy
    # provider, which a fully static binary cannot load) plus the flat
    # /out/sstp-pppd-plugin.so, which pppd loads by absolute path.
    step "Building sstpc (SSTP client) bundle for $goarch"
    docker run --rm ${DOCKER_NET:-} --platform "$platform" \
        -e ARCH="$muslarch" \
        -v "$outdir:/out" \
        -v "$REPO_ROOT/build/backend/sstpc-bundle.sh:/sstpc-bundle.sh:ro" \
        alpine:3.22 sh -e /sstpc-bundle.sh

    # strongswan (IKEv2 server) — HARVESTED from Alpine's musl strongswan package into
    # a relocatable tree. charon dlopens its features as plugins (libstrongswan-eap-radius.so,
    # -eap-mschapv2, -eap-tls, -kernel-netlink, -vici, -x509, …), so it can't be one
    # static binary — same reason as accel-ppp/pppd. Ships charon + swanctl + pki +
    # /usr/lib/ipsec/plugins/*.so + ldd deps + musl loader as /out/strongswan-bundle.tgz,
    # consumed by backend/strongswan.go. Separate Alpine 3.22 run so the recipe stays
    # self-contained, like the bundles above.
    step "Building strongswan (IKEv2) bundle for $goarch"
    docker run --rm ${DOCKER_NET:-} --platform "$platform" \
        -e ARCH="$muslarch" \
        -v "$outdir:/out" \
        -v "$REPO_ROOT/build/backend/strongswan-bundle.sh:/strongswan-bundle.sh:ro" \
        alpine:3.22 sh -e /strongswan-bundle.sh

    # telemt (MTProto Proxy), built from the PINNED third_party/telemt submodule
    # (the Sir-MmD fork: upstream 3.4.23 + our [access.user_modes] patch), exactly
    # like build/core/build.sh does for the patched Xray-core. The SIMPLEST bundle
    # here: no plugins to dlopen (so no relocatable tree like accel-ppp/strongSwan),
    # no OpenSSL (rustls/ring is pure Rust), no runtime data files in direct mode.
    # Emits /out/telemt. Uses rust:alpine rather than alpine:3.22 because it needs a
    # Rust toolchain whose host triple is already *-unknown-linux-musl.
    if [[ ! -f "$REPO_ROOT/third_party/telemt/Cargo.toml" ]]; then
        echo "third_party/telemt is not initialised: run: git submodule update --init --recursive" >&2
        exit 1
    fi
    step "Building telemt (MTProto Proxy) static binary for $goarch"
    docker run --rm ${DOCKER_NET:-} --platform "$platform" \
        -e ARCH="$muslarch" \
        -v "$outdir:/out" \
        -v "$REPO_ROOT/build/backend/telemt-bundle.sh:/telemt-bundle.sh:ro" \
        -v "$REPO_ROOT/third_party/telemt:/src:ro" \
        rust:alpine sh -e /telemt-bundle.sh

    ok "Done: $(ls -lh "$outdir")"
}

for a in "${ARCHES[@]}"; do
    build_arch "$a"
done
