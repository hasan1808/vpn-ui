# IKEv2 — research and implementation plan

Adding **IKEv2/IPsec** as a 7th VPN protocol. This document is the research record and
proposed implementation contract, produced from a 6-agent recon (codebase + web).
Mirrors the style of `openconnect-plan.md` / `sstp-plan.md`.

STATUS: RESEARCH ONLY — HOLD FOR REVIEW. Nothing built yet (user chose "hold at research").

## Decisions locked (2026-07-14)
1. **BlackBerry scope = BB10 and newer ONLY.** Legacy BlackBerry OS 7-and-below (IKEv1) is
   OUT of scope — no separate IKEv1 Cisco-compatible responder. The main IKEv2 plan already
   covers BB10 / PlayBook / Android-BlackBerrys. (Optional Phase 7 below = dropped.)
2. **Expose all three auth modes in v1:** (a) EAP-MSCHAPv2 + server cert [primary],
   (b) PSK, (c) mutual cert / EAP-TLS. See Part 5 for the real implications of (b) and (c) —
   they are NOT free additions and change the auth plumbing.
3. **Next step = hold at research.** Do not start Phase 0/1 until the user says go.

---

# Part 0 — Executive summary

- **Daemon = bundle strongSwan.** The libreswan we already bundle CANNOT do this feature:
  its server-side EAP is EAP-TLS-only (no EAP-MSCHAPv2), and its only username/password
  path is IKEv1-XAUTH, which modern native clients reject. The libreswan maintainer himself
  points users to strongSwan for IKEv2 user/pass. So the real choice is "bundle strongSwan"
  vs "no native IKEv2" — not "reuse libreswan".
- **Auth model = IKEv2 + server certificate + EAP-MSCHAPv2, backed by our in-binary RADIUS**
  (strongSwan `eap-radius` plugin → 127.0.0.1:1812/1813, exactly like ocserv/accel-ppp/pptp).
  This is the maximally-compatible, native-on-every-OS setup (Windows/macOS/iOS/Android/Linux).
- **Address base 6 = `10.6.0.0/16`** (next free /16; no nftables widening).
- **Biggest new cost: our RADIUS server must learn to speak EAP-MSCHAPv2** (EAP-Message
  state machine + return MS-MPPE MSK keys), which is more than the native MS-CHAPv2 it does
  today for PPP. The NT-hash crypto already exists; it needs re-wrapping in EAP framing.
- **BlackBerry (scope locked to BB10+):** IKEv2 + server-cert + EAP-MSCHAPv2 natively reaches
  **BlackBerry 10**, **PlayBook**, and the **Android BlackBerrys** (via the strongSwan app) —
  all covered by the primary auth mode. Legacy BlackBerry OS 7-and-below (IKEv1-only) is out
  of scope by decision.
- **Three auth modes requested for v1** (EAP-MSCHAPv2 / PSK / mutual-cert-EAP-TLS). Only
  EAP-MSCHAPv2 plugs cleanly into the existing per-account RADIUS model. **PSK bypasses
  RADIUS/EAP** (per-IKE-ID shared secrets + a non-RADIUS accounting path) and **EAP-TLS
  requires the panel to issue per-user client certs** (a mini-PKI like OpenVPN's). Recommend
  shipping EAP-MSCHAPv2 first, then PSK + EAP-TLS as fast-follow modes on the same daemon.

---

# Part 1 — Your first question: IKEv2 "modes" and the certificate

## The correction to the mental model
IKEv2 authentication is **directional and can be asymmetric**: the server authenticates to
the client, and the client authenticates to the server, and the two sides can use *different*
methods. The near-universal setup is asymmetric — **the server always proves itself with an
X.509 certificate**, and the **client proves itself with a username/password over
EAP-MSCHAPv2**. EAP runs only *after* the server has proven itself and an encrypted channel
exists, which is why EAP-MSCHAPv2 is safe here even though bare MSCHAPv2 is weak on the wire.

So your "two modes" intuition is almost right but mislocates the cert: **there is always a
server certificate**. The real question is *whose* cert and *whether the client already
trusts the issuer*.

## The real mode map (what to tell users)
- **Mode A — "server + user + pass, install nothing".** EAP-MSCHAPv2 where the server's cert
  is issued by a **publicly-trusted CA (e.g. Let's Encrypt)** on a real DNS hostname whose SAN
  matches the dialed host. The server still has a cert; the client just already trusts the
  issuer, so nothing is installed.
- **Mode B1 — "install a cert, still user + pass".** EAP-MSCHAPv2 with a **self-signed /
  private-CA** server cert. The client imports the **CA (a trust anchor)**, *not* a personal
  cert. This is the most common reason people "have to install a certificate."
- **Mode B2 — "install a personal client cert".** Full **mutual certificate / EAP-TLS**: each
  user gets their own X.509 cert + key that *is* their identity (passwordless, or 2FA on top).
  A different, stronger mode.
- **Modes you didn't mention:** **PSK** (one shared static secret — poor for many users; the
  Android strongSwan app refuses it) and **Certificate + EAP two-factor**.

There is **no secure IKEv2 mode with username/password and no server certificate at all.**
EAP-only auth (RFC 5998) can drop the server cert only for mutual, key-generating,
dictionary-resistant EAP methods (EAP-TLS/AKA/pwd) — and it explicitly excludes EAP-MSCHAPv2.

## Full method table
| Method | Password-based? | Client needs | Native OS support |
|---|---|---|---|
| PSK (mutual shared secret) | static secret | the PSK | Win native: no; Android app: no; macOS/iOS/Linux: yes |
| Certificate / pubkey (mutual X.509) | no | own client cert + key | Win/macOS/iOS/Android/Linux |
| **EAP-MSCHAPv2** | **yes** | user/pass; trust server cert | **Win/macOS/iOS/Android/Linux — the workhorse** |
| EAP-TLS | no (cert in EAP) | client cert + key | broad |
| EAP-PEAP | yes | user/pass; trust server cert | Windows native only |
| EAP-TTLS / EAP-GTC | yes / OTP | user/pass or token | thin (GTC = Android app only) |
| EAP-only (RFC 5998) | depends | mutual+keygen EAP only | niche; not EAP-MSCHAPv2 |

## Recommendation
**EAP-MSCHAPv2 + server X.509 cert + our RADIUS backend.** It matches our architecture (all
other protocols are server-authoritative RADIUS) and works out of the box on every native OS
client — no third-party app needed. Support both server-cert options in the panel (like SSTP):
self-signed by default (with the existing Windows warning modal + a CA download), and
"use a real cert" for the zero-install Let's-Encrypt experience.

---

# Part 2 — Your second question: BlackBerry

| Generation | Native VPN | IKE version | Auth | Reaches our IKEv2 server? |
|---|---|---|---|---|
| **Legacy BBOS 5/6/7/7.1** (Bold/Curve/Torch/9900) | Yes, but BES-gated | **IKEv1 only** | group-PSK + XAUTH (user/pass or SecurID), or cert | **NO** — needs a separate IKEv1 Cisco-compatible responder |
| **BlackBerry 10** (Z10/Q10/Passport/Classic) | Yes, native, self-service | **IKEv1 and IKEv2** | IKEv2: **EAP-MSCHAPv2** or cert (server cert required) | **YES** — IKEv2 + server cert + EAP-MSCHAPv2 |
| **PlayBook** (QNX) | Yes, native | IKEv1 and IKEv2 | same as BB10 | **YES in principle** — live-test |
| **Android BB** (Priv/KEYone/KEY2/Motion) | built-in = L2TP only (<Android 11) | strongSwan app: IKEv2 | app: EAP-MSCHAPv2 / cert (no PSK) | **YES via the strongSwan app** |

Key facts:
- **Legacy "BlackBerry OS" (the Java handsets, BBOS 7 and below) is IKEv1-only**, works by
  emulating Cisco/Check Point/Nortel concentrators, and is BES-activation-gated and long EOL.
  Serving it requires a *separate* IKEv1 config (aggressive mode + XAUTH-PSK, or main mode +
  cert) with the device set to a "Cisco Secure PIX / IOS Easy VPN" vendor type. It cannot use
  IKEv2 or L2TP at all.
- **BlackBerry 10 and PlayBook do IKEv2 natively**, and the reliable recipe is exactly ours:
  gateway authenticates with a **server certificate** (`leftauth=pubkey`), user authenticates
  with **EAP-MSCHAPv2**, CA imported on the device. **Do NOT use IKEv2-PSK for BlackBerry** —
  the PSK-gateway + EAP-MSCHAPv2 combo trips strongSwan bug #1182 (IKE_AUTH stalls), and the
  Android strongSwan app can't do PSK at all. Server cert is the reliable common denominator.

So: the recommended strongSwan IKEv2 + server-cert + EAP-MSCHAPv2 design covers every
BlackBerry from BB10 onward with no extra work. **The only question is whether legacy BBOS
(7 and below) is in scope** — if yes, that is a separate IKEv1 sub-feature (Part 5, decision 1).

---

# Part 3 — Why strongSwan, not the bundled libreswan

Verified against libreswan 5.3.1 (June 2026), the maintainer's own statements, and
strongSwan's official docs (agent 6, adversarially checked):

- **libreswan server-side EAP is EAP-TLS ONLY.** `leftautheap`/`rightautheap` accept only
  `none`/`tls` — there is no `mschapv2`. The maintainer confirmed this twice in 2025 and
  pointed users to strongSwan for IKEv2 username/password.
- **libreswan has no RADIUS-for-EAP path.** Its only user/pass mechanism is IKEv1
  XAUTH → PAM → pam_radius, which Windows 10 and modern Android reject.
- Our existing libreswan bundle is compiled `make base` with `USE_AUTHPAM=false` and no
  XAUTH/RADIUS/EAP flags. It exists solely to serve **L2TP over IKEv1 with PSK** (the
  `USE_DH2=true`/MODP1024 build for Win7/legacy clients — `conn l2tp-psk`, `authby=secret`).
  It is an IKEv1-ESP-transport role and cannot be extended into an IKEv2-EAP terminator.

strongSwan fits our architecture cleanly:
- `eap-radius` is a **method-agnostic EAP proxy** — the gateway forwards the whole EAP
  conversation to RADIUS (no `eap-mschapv2` plugin needed on the gateway). Point it at
  `127.0.0.1:1812/1813` exactly like ocserv/accel-ppp already do.
- `pools = radius` maps RADIUS **Framed-IP-Address** → the client's virtual IP — this is our
  per-account fixed-IP / User-Limit model, unchanged.
- MOBIKE on by default; accounting via `accounting = yes`; DNS push via the `attr` plugin;
  split/full tunnel via `local_ts`.
- It is the de-facto standard for this recipe (pfSense's "IKEv2 EAP-RADIUS" is strongSwan).

---

# Part 4 — Architecture fit and the two hidden costs

## 4.1 Address base
Registry to date: l2tp=10.0, pptp=10.1, openvpn-udp=10.2 / tcp-mirror=10.3, openconnect=10.4,
sstp=10.5. **IKEv2 = base 6 = `10.6.0.0/16`** (`vpnrange.go protocolBase`). Single contiguous
block, no mirror — clone the OpenConnect branch (`normalizeBlockRanges(base=6, mirror=-1)`).
Inside the existing VPN address space; no nft widening.

## 4.2 RADIUS integration — server-authoritative, like OpenConnect
- NAS-Identifier `ikev2` / `ikev2-<id>` added to `parseNASIdentifier` (radius.go:741,751).
- Login matched by id OR email (already generic).
- **Same-NAT device collapse:** eap-radius sends no usable `NAS-Port`, so IKEv2 hits the same
  issue as ocserv/sstp — add `ikev2` to the idempotent-redial exclusion (radius.go:982) and
  record the session at auth time (not Acct-driven), reusing the openconnect pattern.
- **Eviction:** new branch alongside `killOcservByIP`/`SstpService.KillClientIP` →
  `swanctl --terminate` (by IKE SA name / virtual IP). isIPActive (radius.go:707) needs an
  ikev2 case (virtual IPs live on charon, not as local addrs → `swanctl --list-sas`).

## 4.3 THE BIGGEST NEW COST — RADIUS must speak EAP-MSCHAPv2
This is the #1 risk and must be scoped honestly. `eap-radius` **tunnels the EAP conversation
to RADIUS inside EAP-Message attributes**. Our in-binary RADIUS today does **native RADIUS
MS-CHAPv2** (MS-CHAP-Challenge/MS-CHAP2-Response VSAs, for PPP) — that is a *different* thing
from **EAP-MSCHAPv2** (EAP-encapsulated, multi-round-trip with Access-Challenge).

To keep the server-authoritative-RADIUS architecture, our RADIUS server (web/service/radius.go)
must gain an **EAP-MSCHAPv2 state machine**:
1. EAP-Identity request/response,
2. EAP-MSCHAPv2 challenge (Access-Challenge) → verify NT-response,
3. EAP-Success, and **return the MSK in `MS-MPPE-Send-Key` / `MS-MPPE-Receive-Key`** in the
   final Access-Accept (strongSwan requires this for key-generating EAP methods).

Good news: the NT-hash / `rfc2759.GenerateNTResponse` crypto **already exists** in the
MS-CHAPv2 branch — it needs re-wrapping in EAP-Message framing + challenge/response state
(the `layeh.com/radius` lib supports EAP-Message). Estimate: this is the single largest chunk
of net-new code, and the part most worth a spike before committing to the full protocol wiring.

Fallback (NOT recommended): strongSwan's local `eap-mschapv2` plugin reading credentials from
a file we generate — but that pulls RADIUS out of the auth path and loses DB integration,
User-Limit, and Framed-IP pinning. Only consider if the EAP-in-RADIUS work proves prohibitive.

## 4.4 Second cost — UDP 500/4500 bind conflict with L2TP libreswan
Only one IKE daemon can bind UDP 500/4500 per IP (the ports are spec-fixed; clients dial them).
Our bundled pluto binds them for L2TP/IPsec when L2TP IPsec is enabled. charon cannot also bind
them on the same IP. Plan:
- Detect the conflict and **don't start charon if pluto holds 500/4500** on the same address
  (surface a clear panel warning: "IKEv2 and L2TP/IPsec can't both run on this IP").
- If the box has multiple IPs, bind them to different addresses.
- Long-term option (out of scope for v1): let strongSwan serve *both* the L2TP-IKEv1 transport
  and native IKEv2 — a larger change to the working L2TP path.

## 4.5 Kernel modules — genuinely new
Every existing VPN protocol needs only `ppp_generic` or `tun`. IKEv2/IPsec needs the **kernel
IPsec/XFRM stack**: `esp4`, `ah4`, `xfrm_user`, `af_key`, and AEAD/auth algs. These are NOT in
`vpnKernelModules` (core.go:21-29) today — add them + wire into the cross-distro kernel
provisioning (some cloud kernels ship them as modules, some builtin).

## 4.6 Certificate generator — new shape (RSA + SAN + CA)
Our ocserv/sstp self-signed generators are **ECDSA P-384, leaf-only, no SAN** — the WRONG
shape for IKEv2. Native clients require:
- **A SAN matching the exact dialed address.** FQDN → dNSName SAN. **Windows connect-by-IP
  needs the IP as a dNSName-type SAN (`DNS:1.2.3.4`), never an iPAddress SAN**, or the client
  throws error 13801. Apple requires a SAN match since iOS 13 / macOS 10.15 (CN alone fails).
- **`serverAuth` EKU** (Windows), `digitalSignature` key usage.
- **RSA (3072)** — manually-configured iOS profiles reject ECDSA server certs.
- A **CA→leaf chain** (client trusts the CA). `ikeIntermediate` EKU is optional/harmless.

Build a new IKEv2 cert generator that merges OpenVPN's CA+leaf builder (openvpn.go:917) with
the panel cert's SAN logic (panelcert.go:48-55), switched to RSA + serverAuth EKU. The cert/key/
CA must then be **imported into strongSwan's store** (`/etc/swanctl/x509*`, `x509ca`, `private`)
— a path that doesn't exist today.

## 4.7 Client onboarding — new export deliverable
Only OpenVPN currently delivers a client file (`.ovpn` with inline CA). IKEv2 needs a client
onboarding path: a **CA `.pem` download** (all platforms), and ideally profile exports —
`.mobileconfig` (iOS/macOS), `.sswan` (strongSwan Android). Windows/native connect-by-IP works
with just the CA import (no profile), but a profile is a big UX win. Model on the `downloadOvpn`
handler (inbound.go:790). Also: `send_cert=always` (Apple + the Android built-in CERTREQ bug).

---

# Part 5 — Decisions (RESOLVED 2026-07-14) and their implications

1. **Legacy BlackBerry OS scope — RESOLVED: BB10 and newer only.** No legacy-BBOS IKEv1
   sub-feature. Removes the optional Phase 7. Simplifies the plan: one daemon (strongSwan),
   IKEv2 only, no IKEv1 Cisco-emulation responder.

2. **Auth modes — RESOLVED: expose all three (EAP-MSCHAPv2, PSK, mutual-cert/EAP-TLS).**
   These are genuinely different auth plumbing, not three checkboxes on one path. Honest
   breakdown so this is understood before building:

   | Mode | Per-user identity | Uses our RADIUS? | Framed-IP / User-Limit | Panel must issue client certs? | Native BB10 |
   |---|---|---|---|---|---|
   | **EAP-MSCHAPv2** | yes (username) | yes (`eap-radius`) | yes, native | no | yes |
   | **Mutual cert / EAP-TLS** | yes (cert CN = account) | via `eap-radius` EAP-TLS proxy, or local+vici | yes if routed by CN | **YES — per-user CA+leaf, like OpenVPN** | yes |
   | **PSK** | only via **per-IKE-ID PSK secrets** (id = username, own secret) | **NO — PSK is not EAP/RADIUS** | needs a **non-RADIUS** path (charon pool + vici/updown accounting) | no | yes, but NOT with server-cert; see caveat |

   - **EAP-MSCHAPv2** is the clean fit and the only mode that reuses the whole existing
     per-account machinery unchanged. Ship it first.
   - **EAP-TLS** adds a real deliverable: a per-user **client**-cert issuer + revocation
     (clone OpenVPN's CA→leaf; export a `.p12`/profile per account). Identity = cert CN.
   - **PSK** is the awkward one. IKEv2 PSK does mutual auth with **no username and no EAP**,
     so it never touches our RADIUS. To keep per-account identity you must generate
     **per-IKE-ID PSKs** into strongSwan `secrets` and drive virtual-IP assignment +
     accounting through charon (vici/updown), a **separate code path** from `eap-radius`.
     A single shared PSK for a whole inbound loses per-user accounting/User-Limit entirely.
     Also note: PSK-gateway-auth + EAP for BlackBerry is the combo that trips strongSwan bug
     #1182 and the Android app can't do PSK at all — so "PSK mode" here means the classic
     shared-secret / per-ID-PSK IPsec tunnel, presented as an alternative connection type,
     with weaker per-user semantics than EAP-MSCHAPv2. This tradeoff is inherent to PSK.

   Net: implement in this order within the one `ikev2` protocol — **EAP-MSCHAPv2 (full
   RADIUS/User-Limit) -> EAP-TLS (client-cert issuer) -> PSK (per-ID secrets, charon-side
   accounting)** — with a per-inbound "auth mode" selector in the form.

3. **Spike-first recommendation stands.** The `eap-radius` -> EAP-MSCHAPv2-in-RADIUS spike
   (Part 4.3) is the biggest risk and should precede full wiring, mirroring how ocserv/sstp
   were de-risked. Deferred until the user says go (decision 3 = hold at research).

---

# Part 6 — Proposed phasing (after decisions)

- **Phase 0 — Build gate.** `build/backend/strongswan-bundle.sh` (alpine:3.22 `apk add
  strongswan`, harvest charon + `/usr/lib/ipsec/plugins/*.so` [eap-radius, eap-identity, attr,
  kernel-netlink, vici, x509, pem, pubkey, openssl] + deps + musl loader → tree bundle). New
  `backend/strongswan.go` (clone backend/accel.go). Wire into build.sh cache gate. Assert
  charon + eap-radius plugin present. This is the load-bearing feasibility check.
- **Phase 1 — EAP-MSCHAPv2 RADIUS spike** (de-risk 4.3). Prove real strongSwan eap-radius
  authenticates against our RADIUS with MSK return + Framed-IP virtual IP.
- **Phase 2 — Addressing + service (EAP-MSCHAPv2 mode).** protocolBase 6; new
  `web/service/ikev2.go` (server-auth RADIUS model, clone openconnect.go structure);
  swanctl.conf/strongswan.conf generation with a per-inbound **auth-mode selector**
  (default eap-mschapv2); procmgr child; kernel modules; server-cert generator (RSA+SAN+CA)
  + swanctl x509 import. Ships the primary mode end-to-end first.
- **Phase 3 — Go wiring.** The ~15 dispatch sites (radius.go, vpnrange.go, nftables.go
  [CollectAndResetTraffic 5->6 arity], xray.go, core.go, inbound.go, web.go, xray_traffic_job.go,
  controller/inbound.go) per the wiring checklist.
- **Phase 4 — Frontend.** `form/protocol/ikev2.html` (clone sstp.html) + cert modal (with the
  Windows self-signed warning) + client onboarding (CA/profile download) + dashboard/core status.
- **Phase 5 — E2E.** test_unit phase + strongSwan client; connect/dns/egress/user-limit/
  strategy/multi-user/multi-inbound/usage/termination/routing/cross-inbound. Author only
  (never auto-run incus per project rule).
- **Phase 6 — Live verify** on the test box (real Windows/iOS/Android + ideally a BB10).
- **Phase 7 — EAP-TLS mode** (mutual cert). Adds a per-user **client**-cert issuer + revocation
  (clone OpenVPN's CA->leaf), `.p12`/profile export per account, and the swanctl `remote
  { auth = eap-tls }` / CN->account routing. Same daemon, new auth-mode branch + UI option.
- **Phase 8 — PSK mode.** Per-IKE-ID PSK generation into strongSwan `secrets`, charon-side
  virtual-IP pool + vici/updown accounting (does NOT use eap-radius). Weaker per-user
  semantics by nature (see Part 5.2). Same daemon, new auth-mode branch + UI option.
- (Dropped) legacy-BBOS IKEv1 sub-feature — out of scope by decision 1.

---

# Reference: strongSwan config skeleton (from agent 6, verified against strongSwan test scenarios)

`/etc/swanctl/swanctl.conf` (per-inbound, generated):
```
connections {
   ikev2-<id> {
      version     = 2
      local_addrs = %any
      pools       = radius                 # per-user IP from RADIUS Framed-IP-Address
      local  { auth = pubkey; certs = server.pem; id = <host-in-SAN> }
      remote { auth = eap-radius; eap_id = %any }
      children { net { local_ts = 0.0.0.0/0; esp_proposals = aes256gcm16-sha256 } }
      send_certreq = no
      proposals = aes256-sha256-modp2048,aes256gcm16-prfsha256-ecp256
   }
}
```
`/etc/strongswan.conf`:
```
charon {
   plugins {
      eap-radius {
         accounting = yes
         accounting_interval = 300s
         servers { local { address = 127.0.0.1; secret = <radiusSecret>
                           auth_port = 1812; acct_port = 1813; nas_identifier = ikev2-<id> } }
      }
      attr { dns = <dns1>, <dns2> }
   }
}
```
Cert (build our own generator equivalent to): `pki --gen --type rsa --size 3072` + self-signed
CA + leaf `--san <host> --flag serverAuth` (RSA, SAN mandatory, serverAuth EKU).

---

# Build / test commands (once building)
- Quick compile: `CGO_ENABLED=1 go build -o /tmp/vpn-ui-ikev2 main.go`
- Unit: `CGO_ENABLED=1 go test ./web/... -count=1`
- Full bundled binary: `./build.sh` (rebuilds daemons incl. strongswan bundle)
- Daemon bundle alone (docker/podman): `build/backend/build.sh amd64`
