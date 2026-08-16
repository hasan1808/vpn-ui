#!/usr/bin/env bash
# MmD
#
# vpn-ui management menu: the `vpn-ui` command.
#
# Installed to /usr/bin/vpn-ui by `vpn-ui-amd64 install-menu`, which deploy.sh runs
# on every fresh install and update. The script is EMBEDDED in the binary it
# drives, so the two are always the same release: upstream installs its menu by
# curling raw.githubusercontent at `main`, which pins the default branch's tip even
# on a box running a tagged release, and leaves the menu's numbering describing a
# binary that isn't there.
#
# The script never scrapes the binary's human output (upstream's
# `x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}'` breaks the day
# someone rewords a line). Anything it only displays, the binary prints; anything
# it branches on comes from `vpn-ui-amd64 info --get <field>`, whose field names
# are a stable contract (see panelInfo in main.go). No jq required.
#
# It is also SOURCEABLE: deploy.sh sources this file purely to reuse
# obtain_letsencrypt_cert, so there is exactly ONE acme.sh implementation rather
# than two copies drifting apart. Everything below is a definition; the only code
# that runs is behind the sourced/executed guard at the very bottom. Keep it that
# way, or `source` will re-exec deploy.sh through sudo and drop it into a menu.
set -euo pipefail

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

# The panel binary this menu drives. VPNUI_BIN overrides it for a non-default
# install; deploy.sh exports it so the menu follows deploy.sh's own DEST.
BIN="${VPNUI_BIN:-/opt/vpn-ui/vpn-ui-amd64}"
# Every value below is preserved when already set, because deploy.sh sources this
# file with its own: sourcing must add the shared function, never quietly redefine
# the caller's configuration.
CERT_DIR="${CERT_DIR:-$(dirname "$BIN")/cert}"
DOMAIN="${DOMAIN:-${DEPLOY_DOMAIN:-}}"
EMAIL="${EMAIL:-${DEPLOY_EMAIL:-}}"
# How the ACME challenge is answered: "cloudflare" (DNS-01 through the Cloudflare
# API), "manual" (standalone HTTP-01, the original flow) or "ip" (standalone
# HTTP-01 for the server's bare public address). Chosen per run.
SSL_METHOD="${SSL_METHOD:-}"
# The Cloudflare API token, when that path is taken. It is a SECRET: this script
# never prints it and never writes it to disk. It IS exported, for acme.sh, which
# saves it in $HOME/.acme.sh/account.conf (0600, inside a 0700 directory) because an
# unattended renewal two months from now has to re-create the TXT record with nobody
# at the keyboard. Presetting DEPLOY_CF_TOKEN chooses the Cloudflare path.
CF_Token="${CF_Token:-${DEPLOY_CF_TOKEN:-}}"
# Second name on a wildcard certificate ("*.example.com"); empty for a single host.
WILDCARD_SAN="${WILDCARD_SAN:-}"
# "1" issues a wildcard without asking (Cloudflare path only).
DEPLOY_WILDCARD="${DEPLOY_WILDCARD:-}"
# Derived by ssl_ip_target, not an operator knob: "1" when the certificate's
# identifier is an IPv6 literal, which decides whether acme.sh's standalone server
# is forced onto v4 or v6. Declared here only so set -u never sees it unset.
SSL_IPV6="${SSL_IPV6:-}"

# --------------------------------------------------------------------------- #
#  Panel facts (never parsed out of prose)
# --------------------------------------------------------------------------- #

# Read one field of `vpn-ui-amd64 info --json` by name; prints the raw value.
# Tolerant of failure (empty output) so a caller under `set -e` can branch on it.
info_get() { "$BIN" info --get "$1" 2>/dev/null || true; }

# The panel's systemd unit. NEVER hardcode "vpn-ui": the name is operator
# configurable (settings key systemdServiceName, SystemdService.GetServiceName),
# and acting on the wrong unit is worse than not acting at all.
# Prints the unit name, or warns and returns non-zero. It deliberately does NOT
# die(): a die() inside the $(...) its callers use would only exit that subshell,
# leaving the caller to act on an EMPTY unit name (systemctl start "") while set -e
# decides the script's fate. Callers guard with `|| return 0` and stay in the menu.
panel_unit() {
    local u; u="$(info_get systemdUnit)"
    if [[ -z "$u" ]]; then
        warn "could not read the systemd unit name from '$BIN info'. Is the panel installed?"
        return 1
    fi
    printf '%s' "$u"
}

# True when a panel is alive but NOT under systemd.
#
# This is the production box's actual state: the panel is started by hand
# (setsid ./vpn-ui-amd64 &) with the unit inactive-but-enabled. systemd then
# reports the unit inactive while the panel is up and serving, so `systemctl stop`
# would exit 0 having stopped nothing, and `systemctl start` would launch a SECOND
# panel that collides on the web port and every inbound. The control socket is the
# only witness that cannot be fooled: only a live panel answers it.
panel_runs_unmanaged() {
    [[ "$(info_get systemdActive)" != "true" && "$(info_get panelRunning)" == "true" ]]
}

# Explain the unmanaged-panel state once, in the operator's words.
say_unmanaged() {
    warn "the unit '$1' is NOT active, yet a panel IS running (its control socket answers)."
    act  "it was started outside systemd (e.g. ${TEAL}setsid ./vpn-ui-amd64 &${R}), so systemd cannot manage it."
}

# --------------------------------------------------------------------------- #
#  Item 17: Get SSL  (shared with deploy.sh: one implementation, no copies)
# --------------------------------------------------------------------------- #

# Is there a terminal to prompt on? Every prompt below is guarded by this, because
# the same function serves the menu and a fully unattended deploy, and the unattended
# one must never block on a question nobody can answer.
#
# It OPENS /dev/tty rather than testing it with -r. /dev/tty is a 0666 character
# device, so -r passes even in a process with no controlling terminal at all (cron,
# systemd, setsid), and the prompt then dies on ENXIO instead of falling through to
# the preset. Opening it is the only honest test. Note that stdin being a pipe is NOT
# the same question: `curl ... | sudo bash` over SSH still has a terminal, and asking
# there is exactly what these prompts are for.
have_tty() { { : < /dev/tty; } 2>/dev/null; }

# Read the Cloudflare API token and verify it before anything is built on top of it.
#
# The permission list is the point of the prompt: a token that can edit DNS but
# cannot READ zones works right up until acme.sh looks the zone up, and the failure
# then reads like a DNS problem rather than a missing checkbox. Verifying against
# Cloudflare here also catches the mistyped and the expired token in one second
# instead of five minutes into an issuance.
ssl_cf_token() {
    if [[ -z "$CF_Token" ]]; then
        have_tty || {
            warn "no Cloudflare token (set DEPLOY_CF_TOKEN=...), skipping real SSL."
            return 1
        }
        {
            printf '%s::%s %sCloudflare API token%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
            printf '    Create one at %shttps://dash.cloudflare.com/profile/api-tokens%s\n' "$TEAL" "$R"
            printf '    (Create Token -> Custom token) with EXACTLY these permissions:\n'
            printf '      %sZone : Zone : Read%s\n' "$GREEN" "$R"
            printf '      %sZone : DNS  : Edit%s\n' "$GREEN" "$R"
            printf '    Zone Resources: All zones, or just the zone you are issuing for.\n'
            printf '    The token is used to write a temporary TXT record for the challenge.\n'
            printf '  %stoken%s (input hidden): ' "$BLUE" "$R"
        } > /dev/tty
        read -rs CF_Token < /dev/tty || CF_Token=""
        printf '\n' > /dev/tty
    fi
    [[ -n "$CF_Token" ]] || { warn "no Cloudflare token entered, skipping real SSL."; return 1; }
    export CF_Token

    msg "Verifying the token with Cloudflare"
    # The binary makes the API call: no jq on a minimal box, and a token passed in
    # the environment stays out of /proc/<pid>/cmdline, which is world-readable.
    # Cloudflare's own refusal ("Invalid API Token") is printed on its stderr.
    local verdict=""
    if ! verdict="$("$BIN" cf verify)"; then
        warn "Cloudflare did not accept that token. Check the two permissions above, and that it has not expired."
        CF_Token=""
        return 1
    fi
    ok "$verdict"
}

# Choose which domain the certificate is for: pick a zone the token can see, then
# a single host or a wildcard. Sets DOMAIN (the certificate's main name) and
# WILDCARD_SAN. A preset DOMAIN wins: an operator who already named the host is not
# asked to pick it out of a list.
ssl_cf_domain() {
    local wildcard=""
    case "$DEPLOY_WILDCARD" in yes|true|1) wildcard="1" ;; esac

    if [[ -n "$DOMAIN" ]]; then
        act "using the preset domain ${TEAL}${DOMAIN}${R}"
        if [[ -n "$wildcard" ]]; then
            WILDCARD_SAN="*.${DOMAIN}"
        fi
        return 0
    fi
    have_tty || { warn "no domain (set DEPLOY_DOMAIN=...), skipping real SSL."; return 1; }

    msg "Reading the domains this token can see"
    local zones=""
    if ! zones="$("$BIN" cf zones)"; then
        warn "could not list the token's domains. It needs 'Zone : Zone : Read' on at least one zone."
        return 1
    fi

    local -a names=() states=()
    local zname zstate
    while IFS=$'\t' read -r zname zstate; do
        [[ -n "$zname" ]] || continue
        names+=("$zname")
        states+=("$zstate")
    done <<< "$zones"
    (( ${#names[@]} > 0 )) || { warn "that token can see no domains."; return 1; }

    local idx=0
    if (( ${#names[@]} == 1 )); then
        act "one domain on this token: ${TEAL}${names[0]}${R}"
    else
        local i
        {
            printf '%s::%s %sDomains on this Cloudflare token%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
            for i in "${!names[@]}"; do
                if [[ "${states[$i]}" == "active" ]]; then
                    printf '    %s%d)%s %s\n' "$GREEN" "$(( i + 1 ))" "$R" "${names[$i]}"
                else
                    printf '    %s%d)%s %s %s(%s)%s\n' "$GREEN" "$(( i + 1 ))" "$R" "${names[$i]}" \
                        "$D" "${states[$i]}" "$R"
                fi
            done
            printf '  choose [1-%d]: ' "${#names[@]}"
        } > /dev/tty
        local pick=""
        read -r pick < /dev/tty || pick=""
        if ! [[ "$pick" =~ ^[0-9]+$ ]] || (( pick < 1 || pick > ${#names[@]} )); then
            warn "'${pick}' is not one of the listed domains, skipping real SSL."
            return 1
        fi
        idx=$(( pick - 1 ))
    fi
    DOMAIN="${names[$idx]}"
    # A zone Cloudflare has not activated yet is not answering DNS for that name, so
    # the challenge could never validate. Say so now rather than after the timeout.
    if [[ "${states[$idx]}" != "active" ]]; then
        warn "Cloudflare reports ${DOMAIN} as '${states[$idx]}', not active: its nameservers are not delegated to Cloudflare yet, so the DNS challenge will fail."
    fi

    # Scope. A wildcard is DNS-01 only (Let's Encrypt does not validate *.example.com
    # over HTTP), which is why the option lives on this path and not the manual one.
    if [[ -z "$wildcard" ]]; then
        {
            printf '%s::%s %sCertificate for %s%s\n' "$B$BLUE" "$R" "$WHITE" "$DOMAIN" "$R"
            printf '    %s1)%s Subdomain  (e.g. panel.%s) %s[default]%s\n' "$GREEN" "$R" "$DOMAIN" "$D" "$R"
            printf '    %s2)%s Wildcard   (*.%s, and %s itself)\n' "$GREEN" "$R" "$DOMAIN" "$DOMAIN"
            printf '  choose [1/2]: '
        } > /dev/tty
        local scope=""
        read -r scope < /dev/tty || scope=""
        if [[ "$scope" == "2" ]]; then
            wildcard="1"
        fi
    fi

    if [[ -n "$wildcard" ]]; then
        # The apex goes FIRST because acme.sh names the certificate directory after
        # the first -d: leading with the wildcard would put a glob character in every
        # path, and --install-cert would have to be passed "*.example.com" too.
        WILDCARD_SAN="*.${DOMAIN}"
        act "certificate will cover ${TEAL}${DOMAIN}${R} and ${TEAL}*.${DOMAIN}${R}"
        return 0
    fi

    printf '  %ssubdomain%s (the label before .%s, blank for %s itself): ' \
        "$BLUE" "$R" "$DOMAIN" "$DOMAIN" > /dev/tty
    local label=""
    read -r label < /dev/tty || label=""
    [[ -n "$label" ]] || return 0
    if ! [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
        warn "'${label}' is not a valid host name, skipping real SSL."
        return 1
    fi
    # Accept the full host as readily as the bare label: "panel" and
    # "panel.example.com" are the same request typed two ways.
    case "$label" in
        "$DOMAIN"|*".$DOMAIN") DOMAIN="$label" ;;
        *)                     DOMAIN="${label}.${DOMAIN}" ;;
    esac
    act "certificate will cover ${TEAL}${DOMAIN}${R}"
}

# Is $1 an IP literal Let's Encrypt would actually issue a certificate for?
#
# A pure predicate: no I/O, no globals, so it can be called from the method chooser
# before anything has been decided. The private ranges are rejected HERE rather than
# left to the CA because Let's Encrypt allows only 5 failed validations per hour per
# address, and spending one of them on 192.168.x.x buys nothing.
#
# Documentation ranges (203.0.113.0/24, 2001:db8::/32) are deliberately NOT rejected:
# they are what every example in the docs uses, and an operator testing the flow
# against one should get the CA's answer, not ours.
ssl_ip_valid() {
    local ip="${1:-}"
    case "$ip" in
        *:*) ssl_ip_valid_v6 "$ip" ;;
        *)   ssl_ip_valid_v4 "$ip" ;;
    esac
}

ssl_ip_valid_v4() {
    local a b c d
    # The octet pattern forbids a leading zero deliberately. The string is handed to
    # acme.sh verbatim, so "08.8.8.8" would go to the CA exactly as typed and be
    # refused as malformed; normalising it to 8.8.8.8 here would issue a certificate
    # for an address the operator did not name. 10# then keeps the arithmetic below
    # in base 10 rather than reading a zero-led octet as octal.
    [[ "$1" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
    a=$(( 10#${BASH_REMATCH[1]} )); b=$(( 10#${BASH_REMATCH[2]} ))
    c=$(( 10#${BASH_REMATCH[3]} )); d=$(( 10#${BASH_REMATCH[4]} ))
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
    # 0/8 this-network, 10/8 + 172.16/12 + 192.168/16 private, 127/8 loopback,
    # 169.254/16 link-local, 100.64/10 carrier NAT, 224/4 and up multicast/reserved.
    if (( a == 0 || a == 10 || a == 127 || a >= 224 )) \
    || (( a == 100 && b >= 64  && b <= 127 )) \
    || (( a == 169 && b == 254 )) \
    || (( a == 172 && b >= 16  && b <= 31  )) \
    || (( a == 192 && b == 168 )); then
        return 1
    fi
    return 0
}

ssl_ip_valid_v6() {
    local ip="$1" colons first
    # Hex and colons only. This rejects a zone id ("fe80::1%eth0") and the
    # ::ffff:1.2.3.4 mapped form, which is an IPv4 address in v6 clothing and not
    # something the CA will accept as a v6 identifier.
    [[ "$ip" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    [[ "$ip" == *":::"* ]] && return 1
    # No group longer than four hex digits, and the colon count a real address has:
    # exactly 7 written out, 2 to 7 once "::" has collapsed a run of zeroes. Cheaper
    # and less fragile than expanding the address, and the CA is the final authority
    # on syntax anyway; our job is only to catch the obviously wrong.
    [[ "$ip" =~ [0-9A-Fa-f]{5} ]] && return 1
    colons="${ip//[^:]/}"
    if [[ "$ip" == *"::"* ]]; then
        (( ${#colons} >= 2 && ${#colons} <= 7 )) || return 1
    else
        (( ${#colons} == 7 )) || return 1
    fi
    # 2000::/3 is the only global unicast space IANA has assigned, so every address a
    # server is reachable at from the internet starts there. Testing for that instead
    # of listing loopback, link-local, unique-local and multicast separately is one
    # comparison instead of four, and errs towards making the operator look again.
    [[ "$ip" == ::* ]] && return 1
    first="${ip%%:*}"
    (( 16#$first >= 0x2000 && 16#$first <= 0x3fff )) || return 1
    return 0
}

# Everything about a certificate for a bare IP that an operator otherwise discovers
# days later. Printed on stdout rather than /dev/tty on purpose: an unattended
# DEPLOY_DOMAIN=<ip> install then leaves the same record in its log.
ssl_ip_caveats() {
    msg "A certificate for a bare IP is not the same deal as one for a domain"
    warn "Let's Encrypt issues IP certificates for 160 hours (under 7 days), so this renews every few days instead of quarterly. The panel picks a renewal up without restarting, so nobody is disconnected, but TCP :80 has to be free and reachable from the internet EVERY time. An IP identifier cannot use DNS-01, so there is no escape hatch if it is not."
    act "Let's Encrypt connects to the address itself, so this cannot work behind NAT or a CDN."
    act "Rate limit: 5 certificates per 7 days for that address, no override. Re-running this to debug will lock you out for days."
    act "Browsers do trust it (a real IP SAN), but only for that exact address, never for a hostname. If the IP changes the certificate is dead."
}

# Choose the address the certificate is for. Sets DOMAIN to the literal, clears
# WILDCARD_SAN (an IP certificate has exactly one identifier) and records whether it
# is IPv6.
#
# DOMAIN is reused rather than given a sibling variable on purpose: acme.sh names the
# certificate directory after the first -d, so the fullchain check and --install-cert
# further down already address this certificate correctly with no change at all.
ssl_ip_target() {
    WILDCARD_SAN=""
    SSL_IPV6=""
    ssl_ip_caveats

    local ip="$DOMAIN"
    if [[ -z "$ip" ]]; then
        local detected; detected="$(info_get ip)"
        # GetServerIPv4 reports the literal string N/A when every lookup service
        # failed, and it only ever resolves IPv4, so an IPv6-only host types its own.
        [[ "$detected" == "N/A" ]] && detected=""
        if have_tty; then
            printf '  %sIP address%s%s: ' "$BLUE" "$R" "${detected:+ [$detected]}" > /dev/tty
            read -r ip < /dev/tty || ip=""
            [[ -n "$ip" ]] || ip="$detected"
        else
            ip="$detected"
        fi
    fi

    [[ -n "$ip" ]] || { warn "no IP address (set DEPLOY_DOMAIN=<public IP>), skipping real SSL."; return 1; }
    if ! ssl_ip_valid "$ip"; then
        warn "'${ip}' is not a public IP address. Let's Encrypt issues only for a routable address, so a private, loopback, link-local or carrier-NAT one is refused. Skipping real SSL."
        return 1
    fi

    DOMAIN="$ip"
    [[ "$ip" == *:* ]] && SSL_IPV6="1"
    act "certificate will cover the address ${TEAL}${DOMAIN}${R}"
    return 0
}

# Put acme.sh's Cloudflare hook on disk, given the acme.sh being used. acme.sh 3.1.4
# does NOT fetch a missing dnsapi plugin: without dns_cf.sh it prints "Cannot find
# DNS API hook" and asks the operator to add the TXT record by hand, which is no
# automation at all. A fresh --install copies the bundled hook in from the scratch
# directory; this covers the other case, an acme.sh that was already on the box
# before vpn-ui.
ssl_ensure_dns_cf_hook() {
    # $HOME/.acme.sh is acme.sh's LE_WORKING_DIR, which its _findHook searches;
    # prefer it over the script's own directory, which for a distro-packaged client
    # is /usr/bin and not somewhere plugins belong.
    local acme_home="$HOME/.acme.sh"
    [[ -d "$acme_home" ]] || acme_home="$(dirname "$1")"
    [[ -s "$acme_home/dnsapi/dns_cf.sh" ]] && return 0

    local hookdir; hookdir="$(mktemp -d)"
    if "$BIN" install-acme "$hookdir/acme.sh" >/dev/null 2>&1 && [[ -s "$hookdir/dnsapi/dns_cf.sh" ]]; then
        install -d -m 0755 "$acme_home/dnsapi"
        install -m 0755 "$hookdir/dnsapi/dns_cf.sh" "$acme_home/dnsapi/dns_cf.sh"
    fi
    rm -rf "$hookdir"

    [[ -s "$acme_home/dnsapi/dns_cf.sh" ]] || {
        warn "acme.sh's Cloudflare DNS hook is missing and could not be installed, skipping real SSL."
        return 1
    }
}

# The address to register the acme.sh account under, or NOTHING.
#
# "admin@$DOMAIN" is a reasonable placeholder for a domain and a broken one for an
# IP: admin@203.0.113.5 is not a valid mailbox, and whether Boulder still syntax
# checks the contact field is not something worth gambling an issuance on. An
# account with no address is perfectly legal; it only forgoes expiry reminders,
# which are useless here anyway (see the caveats: this cert outlives its own
# reminder window by about a day).
ssl_account_email() {
    if [[ -n "$EMAIL" ]]; then
        printf '%s' "$EMAIL"
    elif [[ "$SSL_METHOD" != "ip" ]]; then
        printf '%s' "admin@$DOMAIN"
    fi
}

# Install acme.sh from the copy BUNDLED in the panel binary, into $HOME/.acme.sh.
# Returns non-zero when it did not land.
#
# This is the offline path: `curl https://get.acme.sh | sh` fails on a box with no or
# blocked egress to get.acme.sh, which is exactly why real SSL was silently skipped.
# The binary writes the pinned client into a scratch dir; running it there as
# `--install` sets up $HOME/.acme.sh (account.conf, renew cron, shell alias) with NO
# network fetch. Only `--issue` needs the net, and that reaches Let's Encrypt, not
# get.acme.sh. `--install` must run from the dir holding the file literally named
# acme.sh: it does `cp acme.sh ...`.
# --force: install even when no cron daemon is present (EnsureAcmeDeps could not add
# one) so a locked-down host still gets its certificate; without it the pre-check
# fails and issuance is skipped entirely.
ssl_install_bundled_acme() {
    local -a args=(--install --force)
    local acct; acct="$(ssl_account_email)"
    if [[ -n "$acct" ]]; then
        args+=(-m "$acct")
    fi

    local acmedir; acmedir="$(mktemp -d)"
    if "$BIN" install-acme "$acmedir/acme.sh" >/dev/null 2>&1 && [[ -s "$acmedir/acme.sh" ]]; then
        ( cd "$acmedir" && sh ./acme.sh "${args[@]}" ) >/dev/null 2>&1 || true
    fi
    rm -rf "$acmedir"
    [[ -x "$HOME/.acme.sh/acme.sh" ]]
}

# Does the acme.sh at $1 understand --cert-profile? It arrived in acme.sh 3.x, and an
# IP certificate cannot be issued without it.
#
# The help text is captured rather than piped into grep: `grep -q` stops reading at
# the first match, acme.sh then dies of SIGPIPE, and under `set -o pipefail` that
# turns a successful probe into a failed one.
ssl_acme_has_profile() {
    local help; help="$("$1" --help 2>&1 || true)"
    [[ "$help" == *"--cert-profile"* ]]
}

# Obtain a REAL certificate (Let's Encrypt via acme.sh) and point the panel's HTTPS
# at it. Two ways to prove control of the domain:
#
#   cloudflare: DNS-01 through the Cloudflare API. Needs an API token, nothing else.
#               The domain does not have to resolve here and :80 stays free, and it
#               is the only way to get a wildcard certificate.
#   manual:     standalone HTTP-01, the original flow. Needs a public DNS A record
#               for $DOMAIN pointing at this host and TCP :80 free during issuance.
#
# The same cert files can be reused for SSTP so stock Windows trusts it. Best-effort:
# on any failure it warns and leaves the panel's current TLS untouched (returns
# non-zero). Callers guard with `|| ...` so set -e is suspended inside; unguarded
# failures won't abort deploy.
obtain_letsencrypt_cert() {
    # The challenge is chosen FIRST because it decides what has to be asked for: a
    # token and a zone, or a domain that already points at this box. Presets win, so
    # an unattended DEPLOY_DOMAIN install behaves exactly as it always has.
    case "$SSL_METHOD" in
        cloudflare|manual|ip) ;;
        *)
            if [[ -n "$CF_Token" ]]; then
                SSL_METHOD="cloudflare"
            elif [[ -n "$DOMAIN" ]] && ssl_ip_valid "$DOMAIN"; then
                # DEPLOY_DOMAIN=<public IP> is already an unambiguous request for a
                # certificate naming that address, so deploy.sh reaches the IP path
                # with no new switch and no change of its own.
                SSL_METHOD="ip"
            elif [[ -n "$DOMAIN" ]] || ! have_tty; then
                SSL_METHOD="manual"
            else
                {
                    printf '%s::%s %sDomain validation%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
                    printf '    %s1)%s Cloudflare API token  (DNS-01: automatic, no port needed, allows a wildcard)\n' "$GREEN" "$R"
                    printf '    %s2)%s Manual                (HTTP-01: the domain must already point here, TCP :80 free) %s[default]%s\n' "$GREEN" "$R" "$D" "$R"
                    printf "    %s3)%s No domain, use the IP (HTTP-01 for this server's address: 6-day cert, so\n" "$GREEN" "$R"
                    printf '                              TCP :80 must stay reachable for renewal every few days)\n'
                    printf '  choose [1/2/3]: '
                } > /dev/tty
                local how=""
                read -r how < /dev/tty || how=""
                case "$how" in
                    1) SSL_METHOD="cloudflare" ;;
                    3) SSL_METHOD="ip" ;;
                    *) SSL_METHOD="manual" ;;
                esac
            fi
            ;;
    esac

    if [[ "$SSL_METHOD" == "cloudflare" ]]; then
        ssl_cf_token  || return 1
        ssl_cf_domain || return 1
    elif [[ "$SSL_METHOD" == "ip" ]]; then
        ssl_ip_target || return 1
    elif [[ -z "$DOMAIN" ]] && have_tty; then
        printf '  %sdomain%s (DNS A record must point here): ' "$BLUE" "$R" > /dev/tty
        read -r DOMAIN < /dev/tty || DOMAIN=""
    fi
    [[ -n "$DOMAIN" ]] || { warn "no domain (set DEPLOY_DOMAIN=...), skipping real SSL."; return 1; }
    if [[ -z "$EMAIL" ]] && have_tty; then
        printf "  %semail%s (Let's Encrypt account, optional): " "$BLUE" "$R" > /dev/tty
        read -r EMAIL < /dev/tty || EMAIL=""
    fi

    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || \
        { warn "need curl or wget for acme.sh, skipping real SSL."; return 1; }

    # acme.sh standalone binds :80. Warn (don't fail) if it's already taken. The
    # DNS-01 path never touches the port, so the warning would only mislead there.
    if [[ "$SSL_METHOD" == "manual" || "$SSL_METHOD" == "ip" ]] && command -v ss >/dev/null 2>&1 && \
       ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ':80$'; then
        warn "TCP :80 is in use, acme.sh standalone may fail to bind it."
    fi

    # Ensure acme.sh's host prerequisites BEFORE touching it. Its `--install`
    # pre-check HARD-FAILS on a box with no cron daemon (minimal Fedora ships no
    # cronie), so the client never installs and real SSL silently drops to HTTP with
    # "acme.sh not found after install" — even though the box had internet. It also
    # needs socat or python for the standalone HTTP-01 server. The panel binary
    # installs both cross-distro (see EnsureAcmeDeps). No-op when already present;
    # best-effort, since --install --force below still issues without cron (only
    # auto-renew is lost). Guarded so a failure never aborts under the caller's set -e.
    if [[ "$SSL_METHOD" == "cloudflare" ]]; then
        msg "Ensuring acme.sh dependencies (cron, for unattended renewal)"
    else
        msg "Ensuring acme.sh dependencies (cron + standalone server)"
    fi
    "$BIN" acme-deps 2>&1 | sed 's/^/  /' || true

    local ACME="$HOME/.acme.sh/acme.sh"
    if ! [[ -x "$ACME" ]]; then
        if command -v acme.sh >/dev/null 2>&1; then
            ACME="$(command -v acme.sh)"
        else
            msg "Installing bundled acme.sh"
            ssl_install_bundled_acme || true
            ACME="$HOME/.acme.sh/acme.sh"

            # Network fallback ONLY if the bundled install did not land (older binary
            # without `install-acme`, or a broken $HOME). Best-effort; issuance still
            # needs curl/wget, so requiring one here costs nothing extra.
            if ! [[ -x "$ACME" ]]; then
                msg "Bundled acme.sh unavailable, falling back to get.acme.sh"
                # Unquoted on purpose: with no account address the whole argument has
                # to vanish, not become an empty positional the installer then parses.
                local acct; acct="$(ssl_account_email)"
                if command -v curl >/dev/null 2>&1; then
                    curl -fsSL https://get.acme.sh | sh -s ${acct:+email="$acct"} >/dev/null 2>&1 || true
                elif command -v wget >/dev/null 2>&1; then
                    wget -qO- https://get.acme.sh | sh -s ${acct:+email="$acct"} >/dev/null 2>&1 || true
                fi
                ACME="$HOME/.acme.sh/acme.sh"
            fi
        fi
    fi
    [[ -x "$ACME" ]] || { warn "acme.sh not found after install, skipping real SSL."; return 1; }

    # An acme.sh that was already on this box wins the resolution above, and a
    # distro-packaged 2.x has no --cert-profile: the IP issuance would then die on an
    # unrecognised option, which reads like anything but "your client is too old".
    # Replace it with the 3.1.4 pinned inside the panel binary.
    if [[ "$SSL_METHOD" == "ip" ]] && ! ssl_acme_has_profile "$ACME"; then
        msg "This box's acme.sh predates IP certificates, installing the bundled one"
        ssl_install_bundled_acme || true
        ACME="$HOME/.acme.sh/acme.sh"
        if ! [[ -x "$ACME" ]] || ! ssl_acme_has_profile "$ACME"; then
            warn "acme.sh here does not support --cert-profile (needs 3.x), which a certificate for an IP requires. Skipping real SSL."
            return 1
        fi
    fi

    "$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

    # One issuance, two challenges. $DOMAIN is always the FIRST -d, which is the name
    # acme.sh calls the certificate: everything below (the fullchain check, the
    # --install-cert) addresses the certificate by it, wildcard or not.
    local -a issue_args=(--issue -d "$DOMAIN")
    local challenge="standalone HTTP-01"
    if [[ "$SSL_METHOD" == "cloudflare" ]]; then
        ssl_ensure_dns_cf_hook "$ACME" || return 1
        if [[ -n "$WILDCARD_SAN" ]]; then
            issue_args+=(-d "$WILDCARD_SAN")
        fi
        issue_args+=(--dns dns_cf)
        challenge="Cloudflare DNS-01"
    elif [[ "$SSL_METHOD" == "ip" ]]; then
        # Every one of these is load-bearing:
        #   --server letsencrypt   acme.sh's compiled-in default CA is ZeroSSL, which
        #                          cannot do IP identifiers over ACME at all. Passing
        #                          it HERE (not only to --set-default-ca) is also what
        #                          writes the CA into the per-domain conf, so the
        #                          unattended renewal goes to the right place.
        #   --cert-profile         shortlived is the ONLY Let's Encrypt profile whose
        #                          permitted identifiers include `ip`. Without it the
        #                          order is refused outright.
        #   --standalone           an IP identifier cannot use DNS-01 (nothing to put a
        #                          TXT record on) and tls-alpn-01 wants TCP 443, which
        #                          is not where this panel listens.
        #   --days 3               acme.sh's renewal arithmetic assumes 90 days; a
        #                          160-hour certificate has to be told otherwise.
        issue_args+=(--standalone --server letsencrypt --cert-profile shortlived --days 3)
        # Not cosmetic. acme.sh's standalone server is a bare `socat TCP-LISTEN`
        # unless forced, which comes up IPv6-only, and Let's Encrypt's IPv4 fetch
        # then gets connection-refused with nothing in the log to explain it.
        if [[ -n "$SSL_IPV6" ]]; then
            issue_args+=(--listen-v6)
        else
            issue_args+=(--listen-v4)
        fi
        challenge="standalone HTTP-01 (IP, shortlived)"
    else
        issue_args+=(--standalone)
    fi

    msg "Issuing Let's Encrypt certificate for ${DOMAIN}${WILDCARD_SAN:+ + $WILDCARD_SAN} (${challenge})"
    # RSA-2048 for the widest client trust (legacy Windows SSTP included).
    if ! "$ACME" "${issue_args[@]}" --keylength 2048; then
        # acme returns non-zero for two very different reasons and only one is fatal:
        #   - an existing cert is still valid ("skip") -> a real chain IS on disk, proceed;
        #   - issuance FAILED, e.g. the HTTP-01 check timed out because Let's Encrypt
        #     could not fetch the token over :80 (the domain doesn't point at THIS box,
        #     or :80 is firewalled/behind NAT) -> NO chain on disk, bail.
        # Gate on the actual fullchain, NOT the domain directory: acme.sh creates the
        # directory (with the domain key) even when validation fails, so its presence
        # proves nothing. Checking the dir let a failed issuance march into
        # --install-cert, which then died on a missing fullchain.cer and left a partial
        # key in $CERT_DIR.
        if [[ ! -s "$HOME/.acme.sh/${DOMAIN}/fullchain.cer" && ! -s "$HOME/.acme.sh/${DOMAIN}_ecc/fullchain.cer" ]]; then
            warn "acme.sh could not issue a certificate for ${DOMAIN}."
            if [[ "$SSL_METHOD" == "cloudflare" ]]; then
                warn "Let's Encrypt validated over DNS: the token needs 'Zone : DNS : Edit' on ${DOMAIN} (not only on another zone), and the zone must be active in Cloudflare, meaning its nameservers are delegated there. The panel's TLS was left unchanged."
            elif [[ "$SSL_METHOD" == "ip" ]]; then
                # The manual-path advice below ("must resolve to THIS server's public
                # IP") is actively misleading here: nothing resolves, and the address
                # being wrong is a different mistake from the port being unreachable.
                warn "Let's Encrypt validates by connecting to ${DOMAIN} itself on TCP :80, so that has to be this machine's own public address (not a NAT or CDN front) and the port has to be reachable from the internet. The panel's TLS was left unchanged."
                act  "Let's Encrypt allows 5 failed validations per hour for one address, so fix the cause before retrying rather than re-running this to see."
            else
                warn "Let's Encrypt validates over HTTP: ${DOMAIN} must resolve to THIS server's public IP and TCP :80 must be reachable from the internet (not firewalled, not behind a proxy/CDN for a different host). The panel's TLS was left unchanged."
            fi
            return 1
        fi
    fi

    install -d -m 0755 "$CERT_DIR"
    msg "Installing certificate + auto-renew hook"
    # Deliberately NOT a restart. The panel re-reads these two files per TLS
    # handshake (web/network/cert_reloader.go), so a renewal is picked up in place.
    # Restarting would take Xray and every VPN daemon the panel parents down with it,
    # which on a 160-hour IP certificate would mean disconnecting every user every few
    # days. acme.sh still wants a reloadcmd and `true` is the honest way to say there
    # is nothing to do. Safe to hardcode because this script is EMBEDDED in the binary
    # it drives (see the header), so a menu offering this can never be paired with a
    # panel that lacks the reloader.
    "$ACME" --install-cert -d "$DOMAIN" \
        --key-file       "$CERT_DIR/privkey.pem" \
        --fullchain-file "$CERT_DIR/fullchain.pem" \
        --reloadcmd      "true" \
        || { warn "acme.sh install-cert failed, skipping real SSL."; return 1; }

    # Point the panel's web server (and subscription server) at the real cert.
    "$BIN" cert -webCert "$CERT_DIR/fullchain.pem" -webCertKey "$CERT_DIR/privkey.pem" >/dev/null 2>&1 \
        || { warn "applying cert to panel failed."; return 1; }
    ok "real certificate installed for ${DOMAIN}${WILDCARD_SAN:+ + $WILDCARD_SAN}"
    return 0
}

# --------------------------------------------------------------------------- #
#  Menu items
# --------------------------------------------------------------------------- #

# 1) Update. The binary owns the whole flow (version check, DB backup, swap,
#    restart), including refreshing THIS script from the release it installs.
item_update() { "$BIN" update || warn "update did not complete."; }

# 2) Un-Install. The binary prompts for confirmation and removes /usr/bin/vpn-ui
#    (this file) among everything else, so there is no menu to return to.
item_uninstall() {
    "$BIN" --uninstall || { warn "uninstall did not complete."; return 0; }
    exit 0
}

# 3-6) Change username / password / port / web path. All four go through the
#      binary's work-safe switches, which stop the unit, apply, and start it again
#      (a live panel holds the DB open and would keep serving the old values).
item_username() {
    local v; printf '  %snew username%s: ' "$BLUE" "$R"; read -r v || return 0
    [[ -n "$v" ]] || { warn "no username entered, nothing changed."; return 0; }
    "$BIN" --user "$v" || warn "changing the username failed."
}

item_password() {
    local v; printf '  %snew password%s: ' "$BLUE" "$R"; read -rs v || return 0; printf '\n'
    [[ -n "$v" ]] || { warn "no password entered, nothing changed."; return 0; }
    "$BIN" --pass "$v" || warn "changing the password failed."
}

item_port() {
    local v; printf '  %snew port%s [1-65535]: ' "$BLUE" "$R"; read -r v || return 0
    [[ -n "$v" ]] || { warn "no port entered, nothing changed."; return 0; }
    if ! [[ "$v" =~ ^[0-9]+$ ]] || (( v < 1 || v > 65535 )); then
        warn "'$v' is not a valid port, nothing changed."
        return 0
    fi
    "$BIN" --port "$v" || warn "changing the port failed."
}

item_webpath() {
    local v; printf '  %snew web path%s: ' "$BLUE" "$R"; read -r v || return 0
    [[ -n "$v" ]] || { warn "no path entered, nothing changed."; return 0; }
    "$BIN" --path "$v" || warn "changing the web path failed."
}

# 7) Reset Login. Randomizes port, username, password AND web path, so the old
#    URL stops working too. Worth a confirmation.
item_random() {
    warn "this randomizes the port, username, password and web path. The current login stops working."
    local a; printf "  type %s'yes'%s to proceed: " "$WHITE" "$R"; read -r a || return 0
    [[ "$a" == "yes" ]] || { act "aborted, nothing changed."; return 0; }
    "$BIN" --random || warn "randomizing the login failed."
}

# 8) View current login info.
item_info() { "$BIN" info || warn "could not read the panel settings."; }

# 9-11) systemd start / stop / restart.
item_start() {
    local unit; unit="$(panel_unit)" || return 0
    if panel_runs_unmanaged; then
        say_unmanaged "$unit"
        warn "starting the unit now would run a SECOND panel that collides on the web port and every inbound."
        act  "stop the running one first, then start the unit."
        local a; printf '  start %s anyway? [y/N]: ' "$unit"; read -r a || return 0
        [[ "$a" == "y" || "$a" == "Y" ]] || { act "aborted."; return 0; }
    fi
    msg "Starting ${unit}"
    systemctl start "$unit" || { warn "systemctl start ${unit} failed. Inspect: journalctl -u ${unit} -e"; return 0; }
    ok "${unit}: $(systemctl is-active "$unit" 2>/dev/null || true)"
}

item_stop() {
    local unit; unit="$(panel_unit)" || return 0
    # Report the truth rather than a systemctl exit code: stopping an inactive unit
    # succeeds, which would look like "panel stopped" while it keeps serving.
    if panel_runs_unmanaged; then
        say_unmanaged "$unit"
        warn "'systemctl stop ${unit}' would report success and stop NOTHING. Not running it."
        act  "stop it by PID instead, e.g.:  ${TEAL}pkill -x $(basename "$BIN")${R}"
        act  "(never ${TEAL}pkill -f${R} a daemon name over SSH: the pattern matches your own shell)"
        return 0
    fi
    if [[ "$(info_get systemdActive)" != "true" ]]; then
        act "${unit} is already stopped, and no panel answers the control socket."
        return 0
    fi
    msg "Stopping ${unit}"
    systemctl stop "$unit" || { warn "systemctl stop ${unit} failed."; return 0; }
    ok "${unit}: $(systemctl is-active "$unit" 2>/dev/null || true)"
}

item_restart() {
    local unit; unit="$(panel_unit)" || return 0
    if panel_runs_unmanaged; then
        say_unmanaged "$unit"
        warn "'systemctl restart ${unit}' would not touch it, and would start a SECOND panel beside it."
        act  "stop the running one first, then restart the unit."
        return 0
    fi
    msg "Restarting ${unit}"
    systemctl restart "$unit" || { warn "systemctl restart ${unit} failed. Inspect: journalctl -u ${unit} -e"; return 0; }
    ok "${unit}: $(systemctl is-active "$unit" 2>/dev/null || true)"
}

# 12-14, 16) Xray + cores. These MUST go through the running panel: Xray and the
# VPN daemons are its child processes, tracked by in-process state, so a separate
# process acting on its own would report a running Xray as stopped and "restart" it
# into a second copy fighting for port 62790. `ctl` talks to the live panel and
# refuses (non-zero) when there is none. It never acts locally.
item_xray_start()   { "$BIN" ctl xray.start        || true; }
item_xray_stop()    { "$BIN" ctl xray.stop         || true; }
item_xray_restart() { "$BIN" ctl xray.restart      || true; }
item_cores_restart() {
    msg "Restarting all cores (this restarts every configured protocol, so it takes a moment)"
    "$BIN" ctl cores.restart-all || true
    "$BIN" ctl cores.status      || true
}

# 15) Xray Logs. The access log is a real file, so no socket is needed, but it is
# the file named by the Xray config's `log.access`, which is what the panel's own
# Xray Logs page reads (ServerService.GetXrayLogs -> xray.GetAccessLogPath). The
# binary reports the resolved path so the menu and the dashboard always show the
# same file; an empty value means Xray's access log is off (the shipped default is
# literally "none"), in which case the dashboard's log page is empty too.
item_xray_logs() {
    local log archive
    log="$(info_get xrayAccessLog)"
    archive="$(info_get xrayAccessLogArchive)"
    if [[ -z "$log" ]]; then
        warn "Xray's access log is disabled (log.access is \"none\" in the Xray config)."
        act  "enable it in the panel: Xray Settings -> Log -> access log path, then restart Xray."
        if [[ -n "$archive" && -s "$archive" ]]; then
            act "showing the archived access log instead: ${TEAL}${archive}${R}"
            log="$archive"
        else
            return 0
        fi
    elif [[ ! -f "$log" ]]; then
        warn "the configured access log ${TEAL}${log}${R} does not exist yet. Has Xray logged any traffic?"
        return 0
    fi
    msg "Tailing ${log}   (Ctrl-C returns to the menu)"
    hr
    # Ctrl-C must return to the menu, not kill it: with an INT trap installed bash
    # runs the (no-op) handler instead of dying alongside the tail it is waiting on.
    trap ':' INT
    tail -n 200 -f "$log" || true
    trap - INT
}

# 17) Get SSL.
item_ssl() {
    obtain_letsencrypt_cert || warn "the panel's TLS settings were left exactly as they were."
}

# --------------------------------------------------------------------------- #
#  Menu
# --------------------------------------------------------------------------- #

show_menu() {
    local unit state panel
    unit="$(info_get systemdUnit)";   [[ -n "$unit"  ]] || unit="?"
    state="$(info_get systemdState)"; [[ -n "$state" ]] || state="?"
    panel="stopped"
    [[ "$(info_get panelRunning)" == "true" ]] && panel="running"

    printf '\n'
    hr
    printf '%s[%sPRO-UI%s]%s management   %sv%s%s\n' \
        "$B$TEAL" "$GREEN" "$TEAL" "$R" "$D" "$(info_get version)" "$R"
    printf '  %spanel%s %s   %sunit%s %s (%s)\n' "$D" "$R" "$panel" "$D" "$R" "$unit" "$state"
    hr
    printf '    %s1)%s  Update                 %s10)%s Stop      (systemd)\n'   "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s2)%s  Un-Install             %s11)%s Restart   (systemd)\n'   "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s3)%s  Change Username        %s12)%s Start Xray\n'            "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s4)%s  Change Password        %s13)%s Stop Xray\n'             "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s5)%s  Change Port            %s14)%s Restart Xray\n'          "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s6)%s  Change Web-Path        %s15)%s Xray Logs\n'             "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s7)%s  Reset Login (random)   %s16)%s Restart All Cores\n'     "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s8)%s  View login info        %s17)%s Get SSL (domain / server IP)\n' "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s9)%s  Start     (systemd)    %s0)%s  Exit\n'                  "$GREEN" "$R" "$GREEN" "$R"
    hr
}

pause() {
    printf '\n'
    read -r -p "  press Enter to return to the menu... " _ || true
}

menu_loop() {
    local choice
    while true; do
        show_menu
        printf '  choose [0-17]: '
        # EOF (a piped stdin) must leave, not spin forever on an empty read.
        read -r choice || { printf '\n'; return 0; }
        printf '\n'
        case "$choice" in
            1)  item_update ;;
            2)  item_uninstall ;;
            3)  item_username ;;
            4)  item_password ;;
            5)  item_port ;;
            6)  item_webpath ;;
            7)  item_random ;;
            8)  item_info ;;
            9)  item_start ;;
            10) item_stop ;;
            11) item_restart ;;
            12) item_xray_start ;;
            13) item_xray_stop ;;
            14) item_xray_restart ;;
            15) item_xray_logs ;;
            16) item_cores_restart ;;
            17) item_ssl ;;
            0)  return 0 ;;
            "") continue ;;
            *)  warn "invalid choice: '${choice}'" ;;
        esac
        pause
    done
}

usage() {
    cat <<EOF
usage: ${0##*/}            open the management menu
       ${0##*/} ssl        issue/install a Let's Encrypt certificate (non-interactive
                           with DEPLOY_DOMAIN=... DEPLOY_EMAIL=...)
       ${0##*/} --help     this message

environment:
  VPNUI_BIN         path to the panel binary (default: /opt/vpn-ui/vpn-ui-amd64)
  SSL_METHOD        how to answer the ACME challenge, skipping the question:
                    'cloudflare' (DNS-01, needs a token, allows a wildcard),
                    'manual' (standalone HTTP-01, needs :80 and a live A record) or
                    'ip' (standalone HTTP-01 naming this server's public address)
  DEPLOY_DOMAIN     domain to issue the certificate for (skips the prompt). A public
                    IP address here selects 'ip': the certificate then names the
                    address itself, needs no DNS at all, and lasts 160 hours, so the
                    panel restarts (dropping every VPN session) about every 3 days.
                    Private, loopback, link-local and carrier-NAT addresses are
                    refused, as is anything behind NAT or a CDN.
  DEPLOY_EMAIL      Let's Encrypt account email (optional)
  DEPLOY_CF_TOKEN   Cloudflare API token: validates over DNS-01 instead of HTTP-01.
                    Needs 'Zone : Zone : Read' + 'Zone : DNS : Edit'. Without a
                    DEPLOY_DOMAIN the token's domains are offered as a list.
  DEPLOY_WILDCARD   1 issues *.DOMAIN alongside DOMAIN (Cloudflare token only)
EOF
}

# Acquire root: re-exec through sudo when not already root, so `vpn-ui` just works
# for an operator with sudo. Everything this menu does (settings in the root-owned
# DB, systemctl, the root-only control socket) needs it. Mirrors deploy.sh.
require_root() {
    [[ $EUID -eq 0 ]] && return 0
    if [[ -f "$0" ]] && command -v sudo >/dev/null 2>&1; then
        exec sudo -- bash "$0" "$@"
    fi
    die "must run as root. Use: sudo ${0##*/}"
}

require_bin() {
    [[ -x "$BIN" ]] || die "panel binary not found at ${BIN}. Set VPNUI_BIN=/path/to/vpn-ui-amd64 if it lives elsewhere."
}

main() {
    case "${1:-}" in
        -h|--help|help) usage; return 0 ;;
        ssl)
            require_root "$@"
            require_bin
            obtain_letsencrypt_cert
            return $?
            ;;
        "") ;;
        *) die "unknown argument '${1}'. Run '${0##*/}' for the menu, or '${0##*/} --help'." ;;
    esac
    require_root "$@"
    require_bin
    menu_loop
}

# Executed vs sourced. deploy.sh sources this file for obtain_letsencrypt_cert
# alone and must not be re-exec'd through sudo nor land in an interactive menu.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
