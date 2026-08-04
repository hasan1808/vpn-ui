# vpn-ui panel API reference

Request and response shapes for the panel's HTTP API, covering all 19 protocols (the 5
Xray-native ones inherited from upstream 3x-ui, the 3 native ones this fork adds, and the
11 VPN and relay protocols it adds beside them), plus the accounts / membership layer.

The source of truth for each protocol's settings shape is `web/service/protocoldefaults.go`
(the Go table, which is what the SERVER enforces) and `web/assets/js/model/inbound.js` (the
browser model it was ported from). If this document and those disagree, they are right.
Where the two disagree with each other, section 14 lists it.

Every `curl` example below is copy-pasteable against a panel with these two shell
variables set, and reflects the defaults the current code actually applies:

```sh
BASE='https://HOST:PORT/<basePath>'   # e.g. https://vpn.example.com:2083/aX9k2m
JAR=jar.txt
```

---

## 1. Base URL, auth and the two things that surprise everyone

### Base path

Every route lives under the panel's configured base path, which is randomised at install
time and settable from Panel Settings:

```
https://HOST:PORT/<basePath>/panel/api/inbounds/list
```

`<basePath>` already carries its leading and trailing slashes internally; in a URL it is one
path segment, e.g. `/aX9k2m/`. A request to `/panel/api/...` without it does not 404 with a
useful message, it simply does not match a route.

### Auth: a session cookie, not a token

There is no API key. Log in first and keep the cookie:

```sh
curl -sS -c "$JAR" -X POST "$BASE/login" \
  --data-urlencode 'username=admin' \
  --data-urlencode 'password=secret'
# with per-admin 2FA enabled, add: --data-urlencode 'twoFactorCode=123456'
```

Then send `-b "$JAR"` on every call. `GET $BASE/logout` clears it.

The cookie is named **`vpn-ui`**. It is a signed (not encrypted) gin-contrib cookie
session that holds **only the admin's numeric id**; the user row is re-read from the
database on every request, so a permission change or an account disable takes effect
immediately rather than lingering until the cookie expires. `MaxAge` comes from the
`sessionMaxAge` panel setting (minutes) and `HttpOnly` is set. A cookie written by a
pre-upgrade binary held a gob-encoded user row; it fails the type assertion and soft
logs the session out, which is one forced re-login and not a bug.

An account with 2FA that sent no code gets HTTP 200, `success:false`, and
`obj: {"twoFactorRequired": true}`. Resend with `twoFactorCode`.

**Unauthenticated API requests get `404`, not `401`.** `checkAPIAuth`
(`web/controller/api.go`) aborts with 404 to hide which endpoints exist. A 404 from
`/panel/api/...` therefore means "not logged in" at least as often as it means "wrong URL".

**But `/panel/...` and `/panel/api/...` fail differently, and one of the three
shapes looks like success.** They are sibling Gin groups with different auth
middleware, and the routes this document sends you to for core status and VPN
outbounds (`/panel/core/*`, `/panel/xray/*`) are on the `/panel` side. Measured
against a running panel:

| Request, while not logged in | Result |
|---|---|
| `/panel/api/...` (any headers) | `404`, empty body |
| `/panel/*` **with** `X-Requested-With: XMLHttpRequest` | `401` + the usual JSON envelope |
| `GET /panel/core/status` **without** that header, following redirects | **`200` and an HTML login page** |
| `POST /panel/xray/vpnoutbound/list` **without** that header, following redirects | **`404`**, from a path you never called |

The last two rows are the trap, and they are the same bug wearing two faces.
`checkLogin` (`web/controller/base.go`) answers a non-AJAX caller with a `307` to
the login page, and every HTTP client that follows redirects by default (curl
`-L`, Python `requests`, Go's `http.Client`, most of them) follows it.

A `307` **preserves the method**, so where you land depends on what you sent. A GET
lands on the login page and returns `200` with `text/html`: a script checking the
status code sees success, then fails to find its JSON or silently reads nothing. A
POST is re-POSTed to the base path, which has no POST route, so it returns `404`
from a URL that is not the one you asked for. That second shape is nastier than it
looks, because this document also tells you a `404` means "`/panel/api` and not
logged in" and here you have one from a `/panel` route instead.

**So always send `X-Requested-With: XMLHttpRequest`.** On `/panel/api` it changes
nothing; on `/panel` it converts a redirect-to-HTML into an honest `401`. Checking
`Content-Type` for JSON is the belt-and-braces version.

### Gotcha 1: bodies are form-urlencoded, not JSON

The panel's own frontend posts through axios with `Qs.stringify`, so **every POST body is
`application/x-www-form-urlencoded`**, and the Go side binds it with Gin's `ShouldBind` +
`form:` struct tags. A JSON body works only where a handler happens to bind both; do not
rely on it.

Anything structurally nested is passed as **a JSON string inside a form field**. For an
inbound that is `settings`, `streamSettings` and `sniffing`:

```sh
curl -b jar.txt -X POST 'https://HOST:PORT/<basePath>/panel/api/inbounds/add' \
  --data-urlencode 'remark=l2tp-main' \
  --data-urlencode 'enable=true' \
  --data-urlencode 'listen=' \
  --data-urlencode 'port=1701' \
  --data-urlencode 'protocol=l2tp' \
  --data-urlencode 'settings={"clients":[{"id":"alice","password":"s3cret","email":"alice@example.com","enable":true}]}' \
  --data-urlencode 'streamSettings={}' \
  --data-urlencode 'sniffing={}'
```

Repeated keys are how arrays arrive (`Qs` `arrayFormat: 'repeat'`), e.g.
`inboundIds=3&inboundIds=7`. An empty `inboundIds=` is the sentinel for "the group was
cleared", and means none ticked rather than id 0.

### Gotcha 2: a denial is HTTP 200 with `success:false`

Every handler answers through one envelope (`web/entity/entity.go`, `entity.Msg`):

```json
{ "success": true, "msg": "Inbound created successfully", "obj": { } }
```

A refusal, a validation failure, a permission denial and an ownership denial all come back
as **HTTP 200** with:

```json
{ "success": false, "msg": "somethingWentWrong (Invalid port (must be 1-65535): 70000)", "obj": null }
```

There is no 403. Client code that branches on the status code treats every rejection as a
success. **Assert on `body.success`**, and read `body.msg` for the reason. The only non-200
you will see from the API group is the 404 for an unauthenticated request.

`obj` is `null` for message-only replies, an object for creates and single reads, and an
array for list endpoints.

---

## 2. Endpoint index

All paths are relative to `/<basePath>/panel/api/inbounds`. `POST` unless noted.
The permission column is the bit `requirePerm` enforces; a super admin bypasses all of them,
and a reseller's mask is derived from their role rather than stored.

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/list` | accessInbounds | Every inbound the caller can see, with `clientStats` |
| GET | `/get/:id` | accessInbounds | One inbound |
| GET | `/getClientTraffics/:email` | accessInbounds | One account's traffic row |
| GET | `/getClientTrafficsById/:id` | accessInbounds | Same, keyed by client identity |
| GET | `/resellerBalance` | accessInbounds | Caller's reseller balance (answers "not a reseller" for others) |
| POST | `/add` | createInbound | Create an inbound |
| POST | `/update/:id` | editInbound | Update an inbound. Partial: omitted fields keep their stored value |
| POST | `/del/:id` | deleteInbound | Delete an inbound |
| POST | `/import` | createInbound | Create from an exported inbound object |
| POST | `/reorder` | editInbound | Display order only |
| POST | `/addClient` | createClient | Add an account (target inbound is a **body** field) |
| POST | `/updateClient/:clientId` | editClient | Edit an account |
| POST | `/:id/delClient/:clientId` | deleteClient | Delete by identity |
| POST | `/:id/delClientByEmail/:email` | deleteClient | Delete by email |
| POST | `/:id/copyClients` | createClient | Copy accounts to another inbound |
| POST | `/bulkPreview` | bulkOperation | Dry-run a bulk op |
| POST | `/bulkUpdateClients` | bulkOperation | Apply a bulk op |
| POST | `/:id/resetClientTraffic/:email` | editClient | Zero one account's counters |
| POST | `/resetAllClientTraffics/:id` | bulkOperation | Zero every account on an inbound |
| POST | `/resetAllTraffics` | bulkOperation | Zero every inbound's counters |
| POST | `/delDepletedClients/:id` | deleteClient | Drop accounts past quota/expiry |
| POST | `/updateClientTraffic/:email` | editClient | Set counters directly |
| POST | `/clientIps/:email` | accessInbounds | Source addresses seen for an account |
| POST | `/clearClientIps/:email` | editClient | Forget them |
| POST | `/onlines`, `/lastOnline` | accessInbounds | Liveness |

Protocol-specific, documented in section 9:

| Method | Path | Purpose |
|---|---|---|
| GET | `/:id/ovpn/:proto` | Download an `.ovpn` (`proto` = `udp` or `tcp`), raw file, not the envelope |
| GET | `/:id/wgc-configs?email=` | Render a wg-c account's per-device `.conf`s |
| GET | `/:id/awg-configs?email=` | Same for AmneziaWG |
| GET | `/:id/gre-configs?email=` | Render a GRE account's per-peer parameters |
| GET | `/:id/ssh-configs?email=` | Render an SSH account's endpoints and links |
| GET | `/:id/addressing` | Read one inbound's address pool, User Limit resolution and per-account tunnel addresses |
| GET | `/pools` | Read which `/24` of the VPN address space each inbound holds |
| POST | `/generate-openvpn-certs`, `/:id/generate-openvpn-certs` | Mint a CA + server cert + tls-crypt key |
| POST | `/generate-ocserv-cert`, `/:id/generate-ocserv-cert` | Mint an OpenConnect server cert |
| POST | `/generate-sstp-cert`, `/:id/generate-sstp-cert` | Mint an SSTP server cert |
| POST | `/generate-ikev2-cert`, `/:id/generate-ikev2-cert` | Mint an IKEv2 CA + server cert |
| POST | `/check-ikev2-cert` | Inspect an IKEv2 cert, returns its key type and any warning |

The id-less cert variants exist so material can be generated for an inbound that has not
been saved yet; the `:id` variants also persist it onto the inbound.

---

## 3. The inbound object

Top-level form fields on `/add` and `/update/:id` (`model.Inbound`, `form:` tags):

| Field | Type | Notes |
|---|---|---|
| `id` | int | `/update/:id` only, and must match the path |
| `remark` | string | Display label |
| `enable` | bool | `true` / `false` as strings |
| `listen` | string | Empty = all interfaces |
| `port` | int | 1-65535. GRE ignores it and the server picks one |
| `protocol` | string | See the table in section 5 |
| `settings` | JSON string | Per-protocol, sections 6 and 7 |
| `streamSettings` | JSON string | Xray transport. `{}` for every VPN/relay protocol |
| `sniffing` | JSON string | `{}` is fine |
| `total` | int64 | Inbound-wide traffic cap in bytes, 0 = unlimited |
| `expiryTime` | int64 | Unix ms, 0 = never |
| `trafficReset` | string | `never` (default) / `hourly` / `daily` / `weekly` / `monthly`. A cron job zeroes matching inbounds; an unrecognised value simply never matches one |
| `trafficMultiplierEnable` | bool | Weight usage past a threshold |
| `trafficMultiplierAfter` | int64 | Threshold in bytes on up+down |
| `trafficMultiplier` | float | Weight past the threshold. Defaults to 1 |
| `speedLimitEnable` | bool | Per-account rate limit, not a shared pool |
| `speedLimitSeparate` | bool | false = `speedLimitDown` caps both directions |
| `speedLimitDown`, `speedLimitUp` | int | KB/s, 0 = unlimited |
| `speedLimitAfter` | int64 | Threshold in bytes, 0 = immediate |
| `ipLimit` | int | Default cap on distinct source addresses per account, 0 = none |
| `ipLimitStrategy` | string | `reject` (default) or `accept` (evict oldest) |

`tag` is derived server-side from listen and port; do not send it.
`sortOrder` has no form tag on purpose, so an update cannot reset it.

**Partial updates are safe: an omitted field means "leave it alone".** `/update/:id` binds
the request onto the STORED row, so sending just `remark` and `settings` to rename an
inbound changes only those two. An explicitly sent value still wins, including a falsy one,
so `speedLimitEnable=false` does turn the limiter off.

This was not always true, and the difference matters if you are reading an older client.
Until `a59b0585` the handler bound onto an empty struct, and Gin leaves any field the
request did not mention at its zero value while `UpdateInbound` copies about twenty columns
onto the row regardless. A rename therefore also zeroed **twelve** fields: the traffic
multiplier and its threshold, all four speed-limit fields, the IP limit and its strategy,
the inbound's own `total` and `expiryTime`, and `trafficReset`. Nothing was reported,
because from the server's side those were simply the values it was sent, and the panel's
own UI never hit it because its form posts the whole object. Echoing every field back is
now belt and braces rather than a requirement.

`GET /list` and `GET /get/:id` return the same object plus `clientStats`, an array of
`{id, inboundId, enable, email, uuid, subId, up, down, allTime, total, expiryTime, reset,
lastOnline}` (`xray.ClientTraffic`).

`inboundId` on a traffic row is the account's **home** inbound only. `email` is unique
panel-wide, so there is exactly one row per account however many inbounds serve it, and
that column can only ever name one of them. Do not read it as "the inbound this account
is on".

`allTime` is monotonic across a traffic reset, which `up`/`down` are not. Anything that
has to survive a reset (the reseller ledger, for one) keys on it.

---

## 4. Creating an inbound with a minimal body

The server fills in every settings key the caller leaves out, from the same table the
panel's own Add form starts from, and then validates the result
(`NormalizeInboundSettings`, called at the top of `AddInbound`). So this is a complete,
working L2TP inbound:

```
protocol=l2tp&port=1701&settings={"clients":[{"id":"alice","password":"s3cret","email":"alice@example.com","enable":true}]}
```

and this is a complete WireGuard one, with the server minting every key:

```
protocol=wg-c&port=51820&settings={"clients":[{"id":"bob@example.com","email":"bob@example.com","enable":true}]}
```

Rules:

- Defaults **only add absent keys**. A key you send is stored exactly as you sent it,
  including a falsy one: `"userLimit": 0` and `"ipsecEnable": false` are choices, not
  omissions.
- A body that already carries the full shape is stored byte-identical. That is what keeps
  the panel's own requests unchanged.
- `ipRanges` is assigned by the server before the defaults run, so omitting it gets you an
  auto-allocated pool rather than an empty one.
- A GRE inbound's `port` is bookkeeping only and is re-picked server-side.
- **openvpn, sstp and ikev2 cannot be created from a minimal body.** `validateInboundConfig`
  requires a server certificate, and there is no server-side generator on the create path.
  Call the matching `/generate-*-cert` endpoint first and put the returned PEM into
  `settings` (see section 9).

---

## 5. Protocol constants

| `protocol` | Kind | Hands out a tunnel IP | Settings section |
|---|---|---|---|
| `l2tp` | PPP over L2TP/IPsec | yes | 6.1 |
| `pptp` | PPP over PPTP | yes | 6.2 |
| `openvpn` | OpenVPN | yes | 6.3 |
| `openconnect` | ocserv / AnyConnect | yes | 6.4 |
| `sstp` | accel-ppp MS-SSTP | yes | 6.5 |
| `ikev2` | strongSwan IKEv2/IPsec | yes | 6.6 |
| `wg-c` | kernel WireGuard | yes | 6.7 |
| `awg` | AmneziaWG | yes | 6.8 |
| `gre` | GRE (IP proto 47) | yes | 6.9 |
| `mtproto` | MTProto proxy (relay) | no | 6.10 |
| `ssh` | in-binary SSH gateway (relay) | no | 6.11 |
| `anytls` | Xray-native (added by this fork) | no | 7.1 |
| `tuic` | Xray-native (added by this fork) | no | 7.2 |
| `naive` | Xray-native (added by this fork) | no | 7.3 |
| `vmess` | Xray-native (upstream) | no | 7.4 |
| `vless` | Xray-native (upstream) | no | 7.5 |
| `trojan` | Xray-native (upstream) | no | 7.6 |
| `shadowsocks` | Xray-native (upstream) | no | 7.7 |
| `hysteria` | Xray-native (upstream) | no | 7.8 |

Note `wg-c`, not `wgc`. The literal string is `"wg-c"` (`model.WGC`).

`tunnel`, `http`, `mixed` and `wireguard` also exist as `model.Protocol` constants. They
are upstream inbound types with no VPN-account semantics here and are out of scope for
this document.

**Which protocols the server fills defaults for.** `NormalizeInboundSettings` (defaults +
validation) covers exactly the 14 rows above `vmess`: the 11 VPN/relay protocols plus
`anytls`, `tuic` and `naive`. The five upstream Xray-native protocols have **no**
server-side defaults and **no** server-side validation: `protocolSettingDefaults` returns
nil for them and the blob is passed to the core verbatim, because the core owns those
shapes and rejects what it cannot use itself. Every default quoted for those five in
section 7.4 onward is the **browser's**, and the server will not apply it. Send the
complete object.

Shared vocabulary across the addressed protocols:

- `userLimit` - devices per account. `0` = no limit, else `1..64`. An **absent** key is not
  the same as `0`: absent means a legacy single-device inbound.
- `userLimitStrategy` - at the cap, `accept` (evict the oldest device) or `reject`.
  Anything else is rejected at save time rather than silently coerced.
- `ipRanges` - the address pool, as inclusive host ranges **not CIDRs**:
  `"10.1.0.2-10.1.0.254"`, with a `"10.1.0.2-254"` last-octet shorthand. Both ends must sit
  in one `/24`. Panel-managed for most protocols; posting `10.1.0.0/24` is rejected.
- `dns1` / `dns2` - literal IPs or empty. A hostname is rejected: these are written into a
  client config as nameserver addresses.
- `mtu` - `0` means "let the protocol or kernel choose", otherwise 576-9216.
- `clientToClient` - let this inbound's accounts reach each other.
- `crossInbound` - let them reach other inbounds' accounts.
- `externalProxy` - `[{"dest":"cdn.example.com","port":443,"remark":"eu"}]`. Rewrites the
  address in generated links and configs only; no daemon reads it.

---

## 6. VPN and relay protocol settings

Each table is the complete key set for that protocol. "Default" is what the server fills in
when you omit the key.

### 6.1 l2tp

| Key | Type | Default |
|---|---|---|
| `ipsecEnable` | bool | `true` |
| `ipsecPsk` | string | minted, 16 chars |
| `allowRaw` | bool | `false` |
| `clientToClient` | bool | `false` |
| `crossInbound` | bool | `false` |
| `ipRanges` | string[] | `[]` (auto-assigned) |
| `dns1` | string | `"8.8.8.8"` |
| `dns2` | string | `"8.8.4.4"` |
| `mtu` | int | `1400` |
| `userLimit` | int | `1` |
| `userLimitStrategy` | string | `"accept"` |
| `clients` | object[] | `[]` |
| `externalProxy` | object[] | `[]` |

`ipsecEnable: true` with an empty `ipsecPsk` is rejected: libreswan would get a conn with no
key and every client would fail at phase 1 with nothing surfacing in the panel.

Client entry: `id` (the PPP username), `password`, `email`, `enable`, `expiryTime`, `tgId`,
`subId`, `comment`, `totalGB`, `limitIp`, `reset`, `slot`, `created_at`, `updated_at`.

**Two or more l2tp inbounds share one daemon**, so one value of `ipsecPsk`, `dns1` and `mtu`
applies to all of them. `CheckSharedDaemonConflicts` rejects a second inbound that disagrees
on any of the three rather than accepting a value it would then silently ignore, which was
the old failure mode: clients got a profile that could not authenticate and nothing in the
UI explained why. ikev2 is checked the same way.

### 6.2 pptp

The l2tp table minus `ipsecEnable`, `ipsecPsk` and `allowRaw`: `clientToClient`,
`crossInbound`, `ipRanges`, `dns1` `"8.8.8.8"`, `dns2` `"8.8.4.4"`, `mtu` `1400`,
`userLimit` `1`, `userLimitStrategy` `"accept"`, `clients`, `externalProxy`.
Same client entry, same shared-daemon rule.

### 6.3 openvpn

| Key | Type | Default |
|---|---|---|
| `udpEnable` | bool | `true` |
| `tcpEnable` | bool | `true` |
| `tcpPort` | int | `1194` |
| `separatePorts` | bool | `false` (TCP and UDP share `port`) |
| `tlsUseFile` | bool | `false` |
| `caCertFile`, `serverCertFile`, `serverKeyFile`, `tlsCryptFile` | string | `""` |
| `dns1` / `dns2` | string | `"8.8.8.8"` / `"8.8.4.4"` |
| `mtu` | int | `1500` |
| `caCert`, `caKey`, `serverCert`, `serverKey`, `tlsCrypt` | string | `""` (**required**) |
| `cipherMode` | string | `"all"` (`old` / `new` / `all` / `custom`) |
| `ciphers` | string[] | the 8-entry `all` preset, see below |
| `clientToClient`, `crossInbound` | bool | `false` |
| `ipRanges` | string[] | `[]` |
| `userLimit` | int | `1` |
| `userLimitStrategy` | string | `"accept"` |
| `clients`, `externalProxy` | array | `[]` |

Default `ciphers`, in order (the order **is** the `data-ciphers` preference order):
`AES-256-GCM`, `AES-128-GCM`, `CHACHA20-POLY1305`, `AES-256-CBC`, `AES-192-CBC`,
`AES-128-CBC`, `BF-CBC`, `DES-EDE3-CBC`. An empty list is rejected: openvpn then refuses
every negotiation instead of falling back.

At least one of `udpEnable` / `tcpEnable` must be true, and `caCert` + `serverCert` must be
non-empty. Client entry is the l2tp one.

### 6.4 openconnect

| Key | Type | Default |
|---|---|---|
| `dns1` / `dns2` | string | `"8.8.8.8"` / `"8.8.4.4"` |
| `mtu` | int | `1420` |
| `tlsUseFile` | bool | `false` |
| `certificateFile`, `keyFile` | string | `""` (path mode) |
| `certificate`, `key` | string | `""` (inline PEM) |
| `caCert` | string | `""` |
| `clientToClient`, `crossInbound` | bool | `false` |
| `ipRanges` | string[] | `[]` |
| `userLimit` | int | `1` |
| `userLimitStrategy` | string | `"accept"` |
| `clients`, `externalProxy` | array | `[]` |

Either `tlsUseFile: true` with both paths set, or both inline PEM fields set. Client entry
is the l2tp one.

Note: two devices on one account behind a single NAT collapse into one session, because
ocserv sends no `NAS-Port` for the panel to tell them apart.

### 6.5 sstp

Key for key identical to openconnect, default `mtu` `1420`. Same cert requirement (accel-pppd's
sstp module refuses to start without one). Same client entry.

### 6.6 ikev2

The openconnect table plus:

| Key | Type | Default |
|---|---|---|
| `authMode` | string | `"eap-mschapv2"` (or `psk`, `eap-tls`) |
| `psk` | string | `""` |
| `serverAddr` | string | `""` (falls back to the detected host) |
| `nattPort` | int | `4500` |

- `authMode: "psk"` requires a non-empty `psk`, and is a **single-account** mode: the shared
  secret is the whole authentication.
- Every mode except `psk` requires a server certificate.
- `serverAddr` must match the certificate's SAN or clients reject the connection.
- Windows clients need MODP-1024; iOS silently rejects ECDSA server certs, so use RSA.

Client entry is the l2tp one.

### 6.7 wg-c

| Key | Type | Default |
|---|---|---|
| `dns1` / `dns2` | string | `"1.1.1.1"` / `"1.0.0.1"` |
| `mtu` | int | `1420` |
| `serverPrivKey`, `serverPubKey` | string | `""`, minted server-side |
| `pskEnable` | bool | `false` |
| `clientToClient`, `crossInbound` | bool | `false` |
| `ipRanges` | string[] | `[]` |
| `userLimit` | int | `1` |
| `userLimitStrategy` | string | `"accept"` |
| `clients`, `externalProxy` | array | `[]` |

Note the DNS pair is Cloudflare here, not the PPP family's Google pair.

Client entry (identity is the **email**; there is no username or password, the public key is
the credential):

```json
{
  "id": "bob@example.com",
  "email": "bob@example.com",
  "enable": true,
  "privKey": "", "pubKey": "", "psk": "",
  "devices": [ {"privKey": "", "pubKey": "", "psk": ""} ],
  "expiryTime": 0, "tgId": "", "subId": "", "comment": "",
  "totalGB": 0, "limitIp": 0, "reset": 0, "slot": 0
}
```

`id` must equal `email`. Leave the key fields empty and `ReconcileKeys` mints one keypair
**per device slot**, sized to `userLimit`: WireGuard tracks a single endpoint per public
key, so two devices sharing one keypair cannot both be online.

If you **do** send `devices`, they are preserved verbatim. This used to be dropped on the
add path, which made the server mint fresh keys for devices 2..K and silently invalidate
every config already handed out for them.

### 6.8 awg

The wg-c table plus the AmneziaWG 1.0 obfuscation block:

| Key | Type | Default |
|---|---|---|
| `jc` | int | `4` |
| `jmin` | int | `8` |
| `jmax` | int | `80` |
| `s1` | int | `77` |
| `s2` | int | `90` |
| `h1`, `h2`, `h3`, `h4` | string | `""`, minted server-side |

`jmin` must not exceed `jmax`, and none of the five may be negative. Client entry is wg-c's.

### 6.9 gre

| Key | Type | Default |
|---|---|---|
| `mtu` | int | `0` (kernel picks: 1476 raw, 1464 under FOU) |
| `ttl` | int | `64` (0, or 1-255) |
| `ipsecEnable` | bool | `false` |
| `ipsecPsk` | string | minted, 24 chars |
| `allowRaw` | bool | `true` |
| `fouEnable` | bool | `false` |
| `fouPort` | int | `15547` |
| `clientToClient`, `crossInbound` | bool | `false` |
| `ipRanges` | string[] | `[]` |
| `userLimit` | int | `1` |
| `userLimitStrategy` | string | `"accept"` (parity only, GRE enforces K structurally) |
| `clients` | object[] | `[]` |

`ipsecEnable` + `allowRaw` give three modes: raw only, IPsec only, or either. `fouEnable`
is separate on purpose: FOU is Linux/OpenWrt-only, so bundling it with IPsec would lock
MikroTik and Cisco peers out of encryption. `fouEnable: true` with `fouPort: 0` is rejected.

Client entry (identity is the email; GRE carries no credential at all):

```json
{
  "id": "site-a@example.com",
  "email": "site-a@example.com",
  "enable": true,
  "peers": [ {"peerIp": "203.0.113.9", "remark": "branch router"} ],
  "expiryTime": 0, "tgId": "", "subId": "", "comment": "",
  "totalGB": 0, "limitIp": 0, "reset": 0, "slot": 0
}
```

`peers` has one slot per `userLimit` device, and its **length is the slot count**. An empty
`peerIp` is a supported, deliberate choice, not an incomplete record: that peer is served by
the shared catch-all tunnel and its return path is learned from its first packets, which is
what makes a customer on a dynamic IP work.

Two caveats worth knowing before you automate GRE: speed limiting only shapes traffic that
traverses Xray, and GRE has no ports, so it cannot survive CGNAT (many consumer ISPs drop
IP protocol 47 outright).

### 6.10 mtproto

Inbound settings are just `{"clients": []}`. Everything else is **per account**, because the
proxy keys its policy off the authenticated secret rather than the socket, so one inbound can
serve accounts with entirely different modes and links.

Client entry:

```json
{
  "id": "carol@example.com",
  "email": "carol@example.com",
  "secret": "0123456789abcdef0123456789abcdef",
  "enable": true,
  "modeClassic": true, "modeSecure": true, "modeTls": true,
  "tlsDomain": "www.google.com",
  "adtagEnable": false, "adtag": "",
  "userLimit": 0,
  "externalProxy": [],
  "expiryTime": 0, "tgId": "", "subId": "", "comment": "",
  "totalGB": 0, "limitIp": 0, "reset": 0
}
```

`secret` is 32 hex characters; leave it blank and the server mints one. At least one mode
must stay enabled: an account with none is dropped from the generated config entirely,
because an empty mode list would otherwise read as "unrestricted". The client-facing secret
per mode is `secret` (classic), `"dd"+secret` (secure) and `"ee"+secret+hex(tlsDomain)`
(FakeTLS). No `slot`: MTProto hands out no address.

### 6.11 ssh

| Key | Type | Default |
|---|---|---|
| `userLimit` | int | `0` (no limit) |
| `userLimitStrategy` | string | `"accept"` |
| `externalProxy` | object[] | `[]` |
| `clients` | object[] | `[]` |
| `hostKey` | string | `""`, minted ed25519 PEM, never shown in the UI |

`userLimit` defaults to `0` here and not `1`, matching what the panel's Add form creates.

Client entry: `id` (a **real SSH login username**, not the email), `password`, `email`,
`enable`, `expiryTime`, `tgId`, `subId`, `comment`, `totalGB`, `limitIp`, `reset`,
`created_at`, `updated_at`. No `slot`.

---

## 7. Xray-native protocol settings

These three are terminated by the core itself. They take a real `streamSettings` (TLS lives
there), no address pool, and no `userLimit`.

### 7.1 anytls

| Key | Type | Default |
|---|---|---|
| `clients` | object[] | `[]` |
| `paddingScheme` | string[] | the 9-line upstream default, below |

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

The scheme is server-authoritative: it is handed to the client in the session's settings
frame, so changing it never requires reconfiguring a client. Send `"paddingScheme": []`
explicitly to mean "no padding at all"; omitting the key gets you the default above.

Client entry: `password` plus the shared base (`email`, `limitIp`, `totalGB`, `expiryTime`,
`enable`, `tgId`, `subId`, `comment`, `reset`, `created_at`, `updated_at`). Passwords must be
unique within an inbound; a collision is rejected.

### 7.2 tuic

| Key | Type | Default |
|---|---|---|
| `clients` | object[] | `[]` |
| `congestionControl` | string | `"cubic"` (or `bbr`, `new_reno`) |
| `authTimeout` | int | `3` seconds |
| `zeroRttHandshake` | bool | `false` |
| `heartbeat` | int | `10` seconds |
| `udpTimeout` | int | `60` seconds |

The three timeouts read `0` as "use the built-in default"; negative is rejected. An unknown
`congestionControl` is rejected here rather than silently falling back to cubic, because a
client that picks a different algorithm talks past the server's pacing instead of failing.

Client entry: `id` (a uuid, and the identity), `password`, plus the shared base. TUIC
presents both halves on every connection.

Note the account list must be under `clients`, not the `users` that upstream TUIC configs
spell it. Everything on the panel side reads `clients`: the validator, `GetClients`, the
projection, and therefore quota, expiry and disable enforcement. A blob using `users` gets
past this panel with zero accounts and no complaint. (Whether the bundled core also
rejects the alias is a core-side question that cannot be answered from this repository,
since the core ships as a pinned binary; the panel-side rule above is the one that
matters for an API caller.)

### 7.3 naive

| Key | Type | Default |
|---|---|---|
| `clients` | object[] | `[]` |
| `network` | string | `"tcp"` |
| `masquerade` | object | `{"type":"404","file":"","url":"","string":""}` |

`network` is `tcp` (HTTP/2 over TLS), `udp` (HTTP/3 over QUIC) or `"tcp,udp"` (both on one
port). The core also accepts `h2`/`http2` and `h3`/`http3`/`quic` as spellings. **This field,
not `streamSettings.network`, decides which wires the listener owns**:
`NormalizeNaiveInboundStream` forces its transport onto the stream. An unrecognised spelling
is rejected, because the core would read it as "both" and open a listener you did not ask for.

`masquerade.type` is `404`, `file`, `proxy` or `string`, and each reads exactly one companion
field (`file`, `url`, `string` respectively), which must be non-empty for that type. All four
keys are kept so switching type does not lose what was typed under the other one.

Client entry: `password`, `username`, plus the shared base. `username` is the HTTP Basic
username; **empty means "use the email"**, which is what every naive account created before
the field existed authenticates with. It must not contain a colon and must be unique within
the inbound. The email stays the accounting identity either way.

### The five upstream Xray-native protocols

Sections 7.4 to 7.8 cover `vmess`, `vless`, `trojan`, `shadowsocks` and `hysteria`. For
all five:

- **The server fills nothing in and validates nothing.** `protocolSettingDefaults` has no
  entry for them, so `FillSettingsDefaults` returns your blob untouched and
  `ValidateProtocolSettings` returns clean. Every default in these five tables is the
  browser's (`Inbound.VmessSettings` and friends), quoted so you can reproduce what the
  panel's own Add form produces; nothing on the server applies it.
- The `settings` you post is handed to the core verbatim, minus a rewrite of
  `settings.clients` on the way out.
- They take a real `streamSettings` (TLS, Reality and the transport live there). An empty
  `streamSettings` marshals to `null` in the generated config, which the core reads as
  plain TCP with no TLS, so the examples below produce working but unencrypted inbounds.
  Add `streamSettings` for anything real.
- They have no address pool, no `userLimit`, no `ipRanges` and no `externalProxy` in
  `settings` (the per-inbound external proxy for these lives in the browser model's
  `externalProxy`, which is not part of the settings blob the core sees).

They share the same client base as anytls/tuic/naive: `email`, `limitIp`, `totalGB`,
`expiryTime`, `enable`, `tgId`, `subId`, `comment`, `reset`, `created_at`, `updated_at`.

### 7.4 vmess

Settings is `{"clients": [...]}` and nothing else.

Client entry: the shared base plus

| Field | Type | Browser default |
|---|---|---|
| `id` | string (uuid) | a fresh uuid |
| `security` | string | `"auto"` |

Identity: **`id`**.

```sh
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=vmess-1' \
  --data-urlencode 'enable=true' \
  --data-urlencode 'port=10001' \
  --data-urlencode 'protocol=vmess' \
  --data-urlencode 'settings={"clients":[{"id":"7f3a2b9c-1d4e-4a6b-8c2d-5e9f0a1b2c3d","security":"auto","email":"alice","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"alicesub","comment":"","reset":0}]}'
```

### 7.5 vless

| Key | Type | Browser default | Notes |
|---|---|---|---|
| `clients` | object[] | one seeded client | |
| `decryption` | string | `"none"` | the core requires it |
| `encryption` | string | `"none"` | |
| `fallbacks` | object[] | `[]` | `{name, alpn, path, dest, xver}` |
| `selectedAuth` | string | absent | omitted when unset |
| `testseed` | int[] | `[900, 500, 900, 256]` | only emitted when some client has a non-empty `flow` |

Client entry: the shared base plus

| Field | Type | Browser default |
|---|---|---|
| `id` | string (uuid) | a fresh uuid |
| `flow` | string | `""` (`xtls-rprx-vision` / `xtls-rprx-vision-udp443`) |

Identity: **`id`**.

```sh
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=vless-1' \
  --data-urlencode 'enable=true' \
  --data-urlencode 'port=10002' \
  --data-urlencode 'protocol=vless' \
  --data-urlencode 'settings={"decryption":"none","clients":[{"id":"7f3a2b9c-1d4e-4a6b-8c2d-5e9f0a1b2c3d","flow":"","email":"bob","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"bobsub","comment":"","reset":0}]}'
```

`flow` is also settable **per membership** rather than per account, via
`AccountInbound.flow`, so one account on two vless inbounds can run vision on one and
not the other. See section 10.

### 7.6 trojan

| Key | Type | Browser default |
|---|---|---|
| `clients` | object[] | one seeded client |
| `fallbacks` | object[] | `[]` |

Client entry: the shared base plus `password` (browser default: a random 10-character
sequence).

Identity: **`password`**.

```sh
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=trojan-1' \
  --data-urlencode 'enable=true' \
  --data-urlencode 'port=10003' \
  --data-urlencode 'protocol=trojan' \
  --data-urlencode 'settings={"clients":[{"password":"tr0j4nPass1","email":"carol","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"carolsub","comment":"","reset":0}],"fallbacks":[]}'
```

### 7.7 shadowsocks

| Key | Type | Browser default |
|---|---|---|
| `method` | string | `"2022-blake3-aes-256-gcm"` (`SSMethods.BLAKE3_AES_256_GCM`) |
| `password` | string | a random password sized to the method |
| `network` | string | `"tcp,udp"` |
| `clients` | object[] | one seeded client |
| `ivCheck` | bool | `false` |

Client entry: the shared base plus

| Field | Type | Browser default |
|---|---|---|
| `method` | string | `""` (inherit the inbound's) |
| `password` | string | a random password |

The per-client `method` is Shadowsocks multi-user's per-account cipher. It round-trips on
every write path as of `f350d437`, which added `Method` to `model.Client`. On an older
binary `/add` dropped it (the account silently collapsed onto the inbound's cipher and
could not connect with the one it was handed) while `/addClient` kept it, so if you are
driving a panel you have not upgraded, set it through `/addClient` rather than in the
`/add` body.

Identity: **`email`**. Shadowsocks is the only protocol whose identity field is literally
`email`. wg-c, awg, gre and mtproto also address an account by its email, but they do it
through an `id` field that is required to hold a copy of it, so for those the field name
in `clientIdentityKey` is `id`.

The inbound-level `password` is a real key for the 2022 methods and must be a base64
value of the length the chosen method requires. The browser mints it client-side; **the
server does not**, so the two placeholders below are the one thing in this document you
have to fill in yourself.

```sh
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=ss-1' \
  --data-urlencode 'enable=true' \
  --data-urlencode 'port=10004' \
  --data-urlencode 'protocol=shadowsocks' \
  --data-urlencode 'settings={"method":"2022-blake3-aes-256-gcm","password":"REPLACE_32_BYTE_BASE64","network":"tcp,udp","ivCheck":false,"clients":[{"method":"","password":"REPLACE_32_BYTE_BASE64","email":"dave","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"davesub","comment":"","reset":0}]}'
```

Leaving the per-client `method` empty makes the account inherit the inbound's, which is
what the panel's own form produces.

### 7.8 hysteria

Both v1 and v2 are stored under the protocol string `hysteria`, discriminated by
`settings.version`. An inbound imported from outside the panel can carry the literal
`hysteria2`, which `model.IsHysteria` accepts wherever the protocol is tested.

| Key | Type | Browser default |
|---|---|---|
| `version` | int | `2` |
| `clients` | object[] | one seeded client |

Client entry: the shared base plus `auth` (browser default: a random 10-character
sequence).

Identity: **`auth`**.

```sh
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=hy2-1' \
  --data-urlencode 'enable=true' \
  --data-urlencode 'port=10005' \
  --data-urlencode 'protocol=hysteria' \
  --data-urlencode 'settings={"version":2,"clients":[{"auth":"hy2AuthSecret","email":"erin","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"erinsub","comment":"","reset":0}]}'
```

Hysteria needs TLS, which lives in `streamSettings`; the example above omits it and so
produces an inbound no real client will complete a handshake with.

---

## 8. One working create per protocol

Every command below is complete as written (the three that need a certificate call the
generator first). Ports are placeholders: `/add` refuses a port another inbound already
holds.

### The 14 protocols the server fills defaults for

For these, everything you leave out of `settings` is filled from the table in section 6
or 7, so the whole body is the account you want plus the four form fields.

```sh
add() {  # add <remark> <port> <protocol> <settings-json>
  curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
    --data-urlencode "remark=$1" --data-urlencode 'enable=true' \
    --data-urlencode "port=$2" --data-urlencode "protocol=$3" \
    --data-urlencode "settings=$4"
}

# l2tp: username in id, password is the identity
add l2tp-1 1701 l2tp \
  '{"ipsecPsk":"sharedsecret1234","clients":[{"id":"alice","password":"alicePass1","email":"alice","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"alicesub","comment":"","reset":0}]}'

# pptp
add pptp-1 1723 pptp \
  '{"clients":[{"id":"bob","password":"bobPass1","email":"bob","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"bobsub","comment":"","reset":0}]}'

# openconnect (ocserv will not serve TLS without a cert; see below)
add oc-1 4443 openconnect \
  '{"clients":[{"id":"dave","password":"davePass1","email":"dave","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"davesub","comment":"","reset":0}]}'

# wg-c: identity is the email, and id must equal it. Keys are minted server-side.
add wg-1 51820 wg-c \
  '{"clients":[{"id":"grace","email":"grace","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"gracesub","comment":"","reset":0}]}'

# awg: same client shape as wg-c, plus the obfuscation block on the inbound
add awg-1 51821 awg \
  '{"clients":[{"id":"heidi","email":"heidi","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"heidisub","comment":"","reset":0}]}'

# gre: omit the port entirely, the server picks one. peers[] length is the slot count.
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=gre-1' --data-urlencode 'enable=true' \
  --data-urlencode 'protocol=gre' \
  --data-urlencode 'settings={"clients":[{"id":"ivan","email":"ivan","peers":[{"peerIp":"203.0.113.9","remark":"branch-office"}],"enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"ivansub","comment":"","reset":0}]}'

# mtproto: leave secret out and ReconcileSecrets mints a 32-hex one
add mtproto-1 8443 mtproto \
  '{"clients":[{"id":"judy","email":"judy","enable":true,"modeClassic":true,"modeSecure":true,"modeTls":true,"tlsDomain":"www.google.com","adtagEnable":false,"adtag":"","userLimit":0,"externalProxy":[],"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"judysub","comment":"","reset":0}]}'

# ssh: id is a real login name, not the email. userLimit defaults to 0 = no limit.
add ssh-1 2222 ssh \
  '{"clients":[{"id":"karl","password":"karlPass1","email":"karl","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"karlsub","comment":"","reset":0}]}'

# anytls: passwords must be unique within the inbound
add anytls-1 10006 anytls \
  '{"clients":[{"password":"anytlsPass1","email":"frank","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"franksub","comment":"","reset":0}]}'

# tuic: uuid AND password, identity is the uuid, and it must keep its dashes
add tuic-1 10007 tuic \
  '{"clients":[{"id":"3c9e1f70-8a2b-4d55-9f01-6b7c8d9e0a1b","password":"tuicPass1","email":"grace2","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"grace2sub","comment":"","reset":0}]}'

# naive: identity is the password; an empty username falls back to the email
add naive-1 10008 naive \
  '{"clients":[{"password":"naivePass1","username":"","email":"heidi2","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"heidi2sub","comment":"","reset":0}]}'
```

### The three that refuse to save without a certificate

```sh
# openvpn
CERTS=$(curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/generate-openvpn-certs")
SETTINGS=$(printf '%s' "$CERTS" | jq -c '{
  caCert: .obj.caCert, caKey: .obj.caKey, serverCert: .obj.serverCert,
  serverKey: .obj.serverKey, tlsCrypt: .obj.tlsCrypt,
  clients: [{id:"carol2", password:"carolPass1", email:"carol2", enable:true,
             limitIp:0, totalGB:0, expiryTime:0, tgId:0, subId:"carol2sub",
             comment:"", reset:0}]}')
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=openvpn-1' --data-urlencode 'enable=true' \
  --data-urlencode 'port=1194' --data-urlencode 'protocol=openvpn' \
  --data-urlencode "settings=$SETTINGS"

# sstp
CERT=$(curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/generate-sstp-cert")
SETTINGS=$(printf '%s' "$CERT" | jq -c '{
  tlsUseFile: false, certificate: .obj.certificate, key: .obj.key,
  clients: [{id:"erin2", password:"erinPass1", email:"erin2", enable:true,
             limitIp:0, totalGB:0, expiryTime:0, tgId:0, subId:"erin2sub",
             comment:"", reset:0}]}')
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=sstp-1' --data-urlencode 'enable=true' \
  --data-urlencode 'port=8444' --data-urlencode 'protocol=sstp' \
  --data-urlencode "settings=$SETTINGS"

# ikev2 (eap-mschapv2; authMode "psk" needs no cert but allows exactly one account)
CERT=$(curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/generate-ikev2-cert")
SETTINGS=$(printf '%s' "$CERT" | jq -c '{
  authMode: "eap-mschapv2", tlsUseFile: false,
  certificate: .obj.certificate, key: .obj.key, caCert: .obj.caCert,
  clients: [{id:"frank2", password:"frankPass1", email:"frank2", enable:true,
             limitIp:0, totalGB:0, expiryTime:0, tgId:0, subId:"frank2sub",
             comment:"", reset:0}]}')
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/add" \
  --data-urlencode 'remark=ikev2-1' --data-urlencode 'enable=true' \
  --data-urlencode 'port=500' --data-urlencode 'protocol=ikev2' \
  --data-urlencode "settings=$SETTINGS"
```

For an openconnect inbound that actually serves TLS, use the same pattern with
`/generate-ocserv-cert` (which returns `certificate` and `key`). The panel does not
force it, but ocserv needs it.

### Adding an account to an existing inbound, per identity field

The `:clientId` for a later edit or delete is the value of the identity field, which
differs per protocol:

```sh
# password-identity (trojan, anytls, naive, l2tp, pptp, openvpn, openconnect, sstp, ikev2)
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/addClient" \
  --data-urlencode 'id=3' \
  --data-urlencode 'settings={"clients":[{"id":"newuser","password":"newPass1","email":"newuser","enable":true,"limitIp":0,"totalGB":0,"expiryTime":0,"tgId":0,"subId":"newusersub","comment":"","reset":0}]}'
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/updateClient/newPass1" --data-urlencode 'id=3' --data-urlencode 'settings={"clients":[{...}]}'
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/3/delClient/newPass1"

# uuid-identity (vmess, vless, tuic)
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/3/delClient/7f3a2b9c-1d4e-4a6b-8c2d-5e9f0a1b2c3d"

# email-identity (shadowsocks by email; wg-c, awg, gre, mtproto by id, which IS the email)
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/3/delClient/grace"

# auth-identity (hysteria)
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/3/delClient/hy2AuthSecret"

# username-identity (ssh)
curl -sS -b "$JAR" -X POST "$BASE/panel/api/inbounds/3/delClient/karl"
```

`/:id/delClientByEmail/:email` deletes by email on every protocol and sidesteps the
question entirely.

---

## 9. Protocol-specific endpoints

### Certificate generation

```sh
curl -b jar.txt -X POST 'https://HOST:PORT/<basePath>/panel/api/inbounds/generate-ocserv-cert'
```

```json
{ "success": true, "obj": { "certificate": "-----BEGIN CERTIFICATE-----\n...", "key": "-----BEGIN PRIVATE KEY-----\n..." } }
```

- `generate-openvpn-certs` returns `caCert`, `caKey`, `serverCert`, `serverKey`, `tlsCrypt`.
- `generate-ocserv-cert` and `generate-sstp-cert` return `certificate`, `key`.
- `generate-ikev2-cert` returns `certificate`, `key`, `caCert`. It takes **no parameters**:
  the SAN is the panel's own detected server IP. If your clients dial a different name, set
  `settings.serverAddr` to it and supply a certificate whose SAN matches, because charon's
  cert will not.
- `check-ikev2-cert` binds a whole inbound body (the same fields as `/add`) and returns
  `{"keyType": "RSA", "warning": "..."}`. Use it before saving: iOS silently rejects an
  ECDSA server cert, so `keyType` is worth asserting on.

With `:id` the material is written onto the inbound in content mode (`tlsUseFile: false`) and
the daemon is reloaded. Without it, the PEM is returned for you to put into `settings`
yourself, which is how you create openvpn/sstp/ikev2 in one pass:

```sh
CERT=$(curl -s -b jar.txt -X POST '.../generate-ocserv-cert')
# take .obj.certificate and .obj.key, embed them in the settings JSON, then POST /add
```

### Client config rendering

`GET /:id/wgc-configs?email=bob@example.com`:

```json
{ "success": true, "obj": [
  { "deviceIndex": 0, "ip": "10.7.0.8/29", "remark": "", "publicKey": "...", "config": "[Interface]\n..." }
] }
```

One entry per device slot, times one per external-proxy endpoint. `awg-configs` has the same
shape. `ssh-configs` returns `{remark, host, port, singbox, plain, link}` per endpoint, where
`singbox` is a sing-box `ssh` outbound and `link` an `ssh://` share link.

`gre-configs` returns per-peer parameters rather than a config file, since the peer is a
router you configure yourself: `{peerIndex, remark, peerIp, dynamic, serverIp, innerIp,
innerMask, gatewayIp, mtu, mode, ipsecPsk, ipsecId, fouPort, config}`. `mode` is `raw`,
`ipsec` or `ipsec-or-raw`. `ipsecId` is the identity the peer must present as the
server's id, and is required on a shared charon: without it charon cannot tell which
pre-shared key to use. `config` is the whole recipe as text (both platforms), which is
what the subscription hands out as a `.txt`.

`GET /:id/ovpn/udp` returns the `.ovpn` file itself with
`Content-Type: application/x-openvpn-profile`, **not** the JSON envelope.

### Address-plane introspection

The pool, the slot and the resulting tunnel address are all decided by the panel. These
two routes make them readable, so a caller does not have to reimplement the allocator to
find out what it was given.

`GET /:id/addressing` (permission: accessInbounds + owns) reports one inbound's address
plane. It answers `success:false` for a protocol that hands out no client address at all
(mtproto, ssh and every Xray-native one), which is a plain statement rather than an
error condition:

```json
{ "success": true, "obj": {
  "inboundId": 3,
  "protocol": "l2tp",
  "ranges":  ["10.1.0.2-10.1.0.254"],
  "subnets": ["10.1.0"],
  "userLimit": { "posted": 1, "effective": 1, "rule": "explicit" },
  "capacity": 253, "maxAccounts": 253, "used": 2,
  "accounts": [ { "email": "alice", "slot": 0, "addresses": ["10.1.0.2"] } ]
} }
```

`userLimit.posted` is a pointer, so `null` means the key was absent (a legacy
single-device inbound) as distinct from an explicit `0` (no limit); `effective` is what
the allocator actually uses and `rule` is one of `absent-legacy`, `no-limit` or
`explicit`, saying how it got there.

Read that block rather than assuming, because the resolution is not the identity and
three different rules apply:

| Posted | Protocol | `effective` | `rule` |
|---|---|---|---|
| absent (`null`) | any pool protocol | `1` | `absent-legacy` |
| `0` | every pool protocol except `wg-c` / `awg` | **`16`** (`noLimitDevices`) | `no-limit` |
| `0` | `wg-c`, `awg` | **`64`** (`maxUserLimit`) | `no-limit` |
| `1`-`64` | any pool protocol | as posted | `explicit` |

So "no limit" is **not** 64 on most protocols: an account has to own a real run of
consecutive addresses for per-account routing to work at all, so the block is generous but
bounded at 16. On `wg-c` and `awg` the number only sizes the account's gateway block and
gates nothing, so `0` there really is the full 64. A caller who sets `0` expecting 64 and
gets 16 is reading the browser model's comment rather than the server's rule.

`capacity` and `maxAccounts` both count **accounts, not addresses** (an account occupies
`effective` addresses): `capacity` is what the pool holds as it stands now, `maxAccounts`
an upper bound after the pool has auto-expanded as far as it is allowed to. `used` is
scoped to the accounts the caller may see, so for a reseller it is their own count and
not the inbound's.

A reseller granted the inbound may call it, and the report is narrowed to their own
accounts **before** it is built. That ordering is the only reason it is safe to expose:
the addresses come from a panel-wide map, so an unfiltered report would hand one reseller
the tunnel address of every other seller's customer on a shared inbound.

`GET /pools` (permission: **createInbound**) returns the `/24` map, for checking what is
free before hand-picking a range:

```json
{ "success": true, "obj": [
  { "subnet": "10.1.0", "protocol": "l2tp", "inboundId": 3, "remark": "l2tp-main" }
] }
```

It is gated on `createInbound` rather than on the read bit deliberately. The map names
every inbound on the box, including ones the caller was never granted, with its remark. A
reseller's mask is derived from their role and carries no `*Inbound` bit beyond access, so
gating it this way excludes them by construction rather than by a check that could later
be forgotten.

An OpenVPN inbound appears **twice**, once for its UDP `/24` and once for the `10.3.x`
TCP mirror, both attributed to the same `inboundId`. The mirror is held by that inbound
just as firmly as the UDP block, and an operator who cannot see it will eventually try to
allocate over it. Relay and Xray-native protocols never appear: they own no address
space.

### Core install status and VPN outbounds, which are NOT under /panel/api

Two things an API caller commonly wants are served by sibling route groups rather than by
the inbounds API, and looking for them under `/panel/api` is why they read as missing.

**These are on the `/panel` group, so they fail authentication differently from
everything else in this document.** Send `X-Requested-With: XMLHttpRequest` on
them or an expired session comes back as a `200` HTML login page rather than an
error. See section 1.

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/panel/core/status` | coreSettings | Per-core install and run state, plus host and kernel status |
| GET | `/panel/core/catalog` | coreSettings | What each protocol's core needs and whether it is present |
| POST | `/panel/core/provision` | coreSettings | Install a core; `/panel/core/provision-status` polls it |
| POST | `/panel/xray/vpnoutbound/list` | xraySettings | The configured VPN outbound tunnels (also the fallback for an unknown action) |
| POST | `/panel/xray/vpnoutbound/kinds` | xraySettings | Which outbound kinds this build supports |
| POST | `/panel/xray/vpnoutbound/save` | xraySettings | Create or update one; returns `{iface}` |
| POST | `/panel/xray/vpnoutbound/delete` | xraySettings | Remove one, by `tag` |
| POST | `/panel/xray/vpnoutbound/status` | xraySettings | Is one up: `{running, detail}`, by `tag` |

They take the same session cookie and the same form-urlencoded bodies. The difference
worth knowing is what an **unauthenticated** call gets back, because the two groups answer
differently and neither answer is a 401 by default:

| Group | Gate | Unauthenticated response |
|---|---|---|
| `/panel/api/*` | `checkAPIAuth` | `404`, always, with an empty body |
| `/panel/*` | `checkLogin` | `401` + `success:false` **only if** the request carries `X-Requested-With: XMLHttpRequest`; otherwise a `307` redirect to the base path |

`checkLogin` branches on that header alone (`isAjax`), not on whether the caller looks like
a browser. So a plain `curl -X POST` at `/panel/xray/vpnoutbound/list` with no session gets
a **307 with an empty body**, or, if your client follows redirects, a **404 from the base
path** because a 307 re-POSTs and nothing there accepts a POST. Both read as a routing
problem rather than as "log in". See section 1 for the full table, including the GET shape,
which is worse again because it returns `200`. Send the header on `/panel/*` calls and you
get the readable JSON error instead:

```sh
curl -sS -b "$JAR" -H 'X-Requested-With: XMLHttpRequest' \
  -X POST "$BASE/panel/xray/vpnoutbound/list"
```

Note this is a different rule from the one the permission middleware uses. `deny()` and
`denyNotFound()` treat any non-GET or any request whose `Accept` does not ask for HTML as
"wants JSON", so a **permission** failure on `/panel/*` returns readable JSON without the
header. It is only the **logged-out** check that insists on it.

`save` returning `{iface}` is the one non-obvious reply: it is the network interface the
synthesized outbound binds to, which only the server knows, and it is what a caller needs
to correlate the tunnel with anything it inspects on the host.

Creating an inbound for a protocol whose core is not installed is refused, so
`/panel/core/status` is the check to make before `/add` rather than after it.

---

## 10. Accounts and membership

An **account** is one sellable identity that can be served on several inbounds of different
protocols under one quota, one expiry and one subscription. It sits above the settings JSON
rather than replacing it: `settings.clients` is maintained as a projection of the account
onto each member inbound, which is what leaves RADIUS, the slot allocator, every daemon
config writer and `GetXrayConfig` working unchanged.

> **What this section is not.** It is the wire contract only. What the upgrade does to a
> live panel, which cases the backfill handles, what it fixes on the way, why the
> projection cannot lose your WireGuard keys, the three rollback levels and the known
> limits are all in **[accounts-upgrade-guide.md](accounts-upgrade-guide.md)**. Read that
> before you turn this on; none of it is repeated here.

### Account fields (`accounts` table)

| Field | JSON | Notes |
|---|---|---|
| Email | `email` | The identity. Unique, matched case-insensitively after trimming |
| SubID | `subId` | Subscription key, indexed and validated |
| UUID | `uuid` | vmess / vless / tuic |
| VpnUsername | `vpnUsername` | l2tp, pptp, openvpn, openconnect, sstp, ikev2, ssh login |
| Password | `password` | trojan, shadowsocks, anytls, naive, tuic, and every credential VPN |
| Auth | `auth` | hysteria |
| Security | `security` | vmess |
| Secret | `secret` | mtproto |
| NaiveUser | `naiveUser` | naive Basic-auth username; empty = use Email |
| TotalGB | `totalGB` | Bytes despite the name |
| ExpiryTime | `expiryTime` | Unix ms |
| Enable, Reset, LimitIP, TgID, Comment | | One set per account, however many inbounds |

Credentials are stored **per field, not per inbound**: one uuid serves every vmess membership,
one password every trojan membership. The projection picks the field the member inbound's
protocol keys on.

### Membership (`account_inbounds`)

`{accountId, inboundId, slot, flow, createdAt}`, composite primary key.

- `slot` is per **membership**, never per account: one email on N pool inbounds legitimately
  holds N slots at N different addresses.
- `flow` is a per-membership vless override; empty means the protocol default.
- There is also an `extra` column, not exposed in JSON, holding the verbatim original client
  entry. The projection overlays onto it rather than rebuilding, which is what stops a write
  from destroying wg-c/awg `devices` or GRE `peers`.

### Setting memberships over the API

`/addClient` and `/updateClient/:clientId` accept repeated **`inboundIds`** form keys naming
every inbound the account should be served on:

```sh
curl -b jar.txt -X POST 'https://HOST:PORT/<basePath>/panel/api/inbounds/addClient' \
  --data-urlencode 'id=3' \
  --data-urlencode 'settings={"clients":[{"id":"dave","password":"pw","email":"dave@example.com","enable":true}]}' \
  --data-urlencode 'inboundIds=3' \
  --data-urlencode 'inboundIds=7'
```

- `id` is the **target** inbound and arrives in the body, not the path. It is always included
  in the membership set whether or not you repeat it in `inboundIds`.
- Omitting `inboundIds` entirely means "just the target", and is the legacy single-inbound
  path.
- Sending `inboundIds=` (one empty value) means the group was explicitly cleared.
- The caller must own **every** inbound named. An admin holding one inbound cannot provision
  a live account on another admin's by listing it here; the whole request is refused.
- Membership changes only remove the account from inbounds the caller can actually see, so
  not ticking an invisible inbound never unprovisions the account there.

The `settings.clients` array on these two endpoints must hold exactly **one** client for the
membership machinery to resolve the email.

### Refused: two same-protocol memberships on l2tp, pptp or ikev2

`AccountService.ValidateMembershipSet` runs on both `/addClient` and
`/updateClient/:clientId` and rejects a set naming two inbounds of the same protocol when
that protocol is one of `l2tp`, `pptp` or `ikev2`:

> an account cannot be on two l2tp inbounds at once ("A" and "B"). l2tp authenticates
> through a shared daemon that does not name the inbound, so the account would always be
> served by whichever has the lower id, silently taking that inbound's address range and
> user limit.

The cause is the **bare NAS-Identifier**. Those three protocols run through one shared
daemon per protocol, and it sends `l2tp` / `pptp` / `ikev2` rather than `l2tp-3`, so the
in-binary RADIUS server has nothing to resolve the inbound by and matches first-wins on
the lowest id.

It is refused rather than allowed because the failure mode is invisible: the account is
created, shows up on both inbounds, and logs in fine. It simply always lands on one of
them, on that inbound's addresses and under that inbound's User Limit, forever.

`openvpn`, `openconnect` and `sstp` send `<proto>-<inboundId>` and resolve exactly, so two
memberships on those are allowed. The Xray-native protocols and the two relays carry no
NAS-Identifier question at all and are unaffected. Lifting the restriction needs
per-inbound NAS-Identifiers in those three shared daemon configs.

After the write the server reconciles every protocol in the **union** of the new and the
previous membership sets, not just the target's. An account spanning l2tp, wg-c and vless
therefore regenerates all three subsystems from one request, and an inbound the account
was just removed from has its daemon config rewritten too (otherwise the account keeps
working there until something unrelated triggers a regeneration).

### Client identity per protocol

`:clientId` on `/updateClient/:clientId` and `/:id/delClient/:clientId` is the account's
identity, and which field that is depends on the protocol:

| Identity field | Protocols |
|---|---|
| `password` | trojan, l2tp, pptp, openvpn, openconnect, sstp, ikev2, anytls, naive |
| `email` | shadowsocks |
| `auth` | hysteria, hysteria2 |
| `id` | vmess, vless, tuic (uuid); ssh (login name); wg-c, awg, gre, mtproto (the email) |

For the four email-identity protocols the stored entry carries `id` equal to `email`; posting
one without it results in a request to `/updateClient/undefined` and an "empty client ID"
error. `/:id/delClientByEmail/:email` sidesteps the whole question.

---

## 11. Bulk operations

`/bulkPreview` and `/bulkUpdateClients` both bind a **single form field named `data`** whose
value is the JSON request. Not the usual per-field form binding:

```sh
curl -b jar.txt -X POST 'https://HOST:PORT/<basePath>/panel/api/inbounds/bulkUpdateClients' \
  --data-urlencode 'data={"op":"addDays","days":30,"skipDisabled":true,"targets":[{"inboundId":3,"email":"alice@example.com"}]}'
```

| Field | Type | Notes |
|---|---|---|
| `op` | string | `addDays`, `subDays`, `addTraffic`, `subTraffic`, `enable`, `disable`, `delete`, `freeze`, `unfreeze` |
| `days` | int64 | For the day ops |
| `amountBytes` | int64 | For the traffic ops |
| `skipFirstUse` | bool | Skip accounts that have never connected |
| `skipUnlimited` | bool | Skip accounts with no quota |
| `skipDisabled` | bool | Skip disabled accounts |
| `targets` | array | `[{"inboundId": 3, "email": "..."}]` |

Response `obj` is `{"applied": N, "skipped": M}`. `/bulkPreview` computes the same counts
without writing. The batch is refused outright unless the caller owns every inbound named:
a partial apply would be worse than a refusal.

---

## 12. Validation errors

`AddInbound` fills defaults and then validates, so a create either stores a complete,
parseable settings blob or fails with a message naming the field. All arrive as HTTP 200 with
`success:false`.

### The order checks run in

A body with more than one problem reports only the **first** failure in this order, and
nothing after it has run. This matters when you are debugging a rejection that names
something you did not expect:

1. Per-protocol settings shape (defaults filled, then `ValidateProtocolSettings`)
2. Client emails trimmed
3. `validateInboundConfig`: traffic multiplier, speed limits, IP limit and strategy, the
   **certificate requirement** for openvpn / sstp / ikev2, and the port range
4. `CheckSharedDaemonConflicts`: the panel-wide l2tp and ikev2 values (section 13)
5. Port already in use
6. Client identity rules (section 12.1)
7. Duplicate email, panel-wide
8. Empty client identity for the protocol
9. Duplicate VPN username, then the anytls password and naive username collisions

The consequence worth internalising: **the certificate, port and shared-daemon checks all
fire before anything looks at your clients.** Posting a second l2tp inbound with a
different `ipsecPsk` is refused at step 4, so a client identity problem in the same body is
never reported at all, and fixing the identity will not make the request succeed. Fix what
the message actually names, then re-post.

**Expect the error to move as you fix things, and expect that especially from step 1.**
The settings shape is judged first because it has to be: nothing can validate the clients
inside a blob it cannot parse, and steps 3 and 6 both unmarshal that same JSON. So a single
`"mtu": ""` masks all eight later steps, and correcting it can make the very next attempt
fail somewhere completely different, on a port clash or a duplicate email you were never
told about. That is the checks running in order rather than a moving target. Re-post until
it succeeds instead of trying to fix everything the first message implies.

| Message contains | Cause |
|---|---|
| `"mtu" must be a number` | A numeric field sent as a string, including `""`. The protocol's own Go struct cannot unmarshal it, and the daemon config writer that hits it has nowhere to report from |
| `"mtu" must be 0 (protocol default) or 576-9216` | Out of range |
| `"dns1" must be an IP address` | A hostname where a resolver address goes |
| `"ipRanges" entry ... is not an address range` | A CIDR, a backwards range, or one spanning two `/24`s |
| `"userLimit" must be 0 (no limit) or 1-64` | Out of range |
| `"userLimitStrategy" must be one of "accept", "reject"` | A typo. The resolver would otherwise absorb it as `accept` |
| `"ipsecPsk" is required when "ipsecEnable" is true` | l2tp or gre |
| `"psk" is required when "authMode" is "psk"` | ikev2 |
| `"fouPort" is required when "fouEnable" is true` | gre |
| `"ciphers" must list at least one cipher` | openvpn |
| `"congestionControl" must be one of ...` | tuic |
| `"network" has an unknown transport` | naive |
| `"masquerade.url" is required when "masquerade.type" is "proxy"` | naive, and the `file` / `string` equivalents |
| `"clients" must be an array` | An object where the account list goes. `GetClients` ignores its own unmarshal error, so this would otherwise be an inbound that listens and can authenticate nobody |
| `OpenVPN certificate is required` | Also `SSTP` and `IKEv2` variants |
| `Duplicate email: ...` | Emails are the panel's global account identity, unique across every inbound |
| `Port already exists` | Another inbound holds it |
| `Client email ... contains a control character or '>'` | See the identity rules below |
| `Subscription id ... cannot contain / \ ? # or %` | See the identity rules below |
| `VPN username ... cannot contain a path separator` | See the identity rules below |

### 12.1 Client identity rules

Three fields on a client entry are checked on write, because each one is spliced into
something that has no escaping and no way to report a problem later. Enforced since
`f350d437`; on an older binary these functions existed but nothing called them, so
anything below got through.

| Field | Rejected | Why |
|---|---|---|
| `email` | empty; leading or trailing whitespace; any control character; `>` | It is the global account identity, and Xray's counter is named `user>>><email>>>>traffic`, so a `>` misattributes traffic between accounts |
| `subId` | leading or trailing whitespace; any control character; `/` `\` `?` `#` `%`; the literal `.` or `..` | It is used directly as the `/sub/<subId>` URL path component, so an escaped value would no longer match the stored id |
| `id` (the VPN username) | empty is fine; otherwise leading or trailing whitespace, control characters, `>`, spaces, tabs, `/`, `\`, and the literal `.` or `..` | The credential files are whitespace-delimited, and on openvpn the value becomes a filename under the per-inbound client-config-dir |

The username rule applies only to the protocols that actually key on it: **l2tp, pptp,
openvpn, openconnect, sstp, ikev2 and ssh**. It is deliberately not applied to wg-c, awg,
gre or mtproto (whose `id` holds a copy of the email, which nothing reads as a login) nor
to the Xray-native protocols (whose `id` holds a uuid or a password), because the filename
and whitespace rules would reject values that are correct there.

Checked on all four write paths: `/add`, `/update/:id`, `/addClient` and
`/updateClient/:clientId`. On the two client paths the protocol is taken from the
**stored** inbound rather than the request body, since those bodies carry only `id` and
`settings` and a body-derived protocol would skip the username rules for exactly the
protocols that need them.

**Not** checked on the delete paths and **not** applied by the accounts migration, so an
account created before these rules keeps working and stays deletable.

**Unchanged entries are exempt, on both edit paths.** Each posted entry is compared
against what is stored and skipped when its identity triple (`email`, `subId`, `id`) is
byte-identical to one already there:

| Path | Exemption |
|---|---|
| `/update/:id` | yes, against every client stored on that inbound |
| `/updateClient/:clientId` | yes, against the clients stored on the target inbound |
| `/add` | no, and nothing to exempt against: the inbound does not exist yet |
| `/addClient` | no: the account is new, so its identity is new by definition |

It matters most on `/update/:id`, which posts **every** client on the inbound rather than
just the edited one. Without the exemption a single account created years ago with a space
in its username would fail validation on every later save, so the operator could not change
the inbound's DNS, rename it, or add an unrelated account until they had gone and fixed
that row. On a panel with hundreds of sold accounts that is an upgrade that bricks an
inbound, which is worse than the hole the rules close.

The exemption is on the whole triple rather than per field, which is what stops it being a
loophole: touch any part of an account's identity and the tuple is new and held to the
current rules. A pre-existing bad value can be carried forward and can still take a quota
or expiry edit, but it can never be edited into a *different* bad value, and a bad value
can never be created.

A validation failure on `/add` writes nothing.

---

## 13. Known traps

- **Whole-inbound update does not sync `client_traffics`.** An expiry or quota set by
  `/update/:id` never auto-disables the account. Use the client endpoints for per-account
  changes.
- **An account that predates the identity rules keeps working and stays editable, as long
  as you leave its identity alone.** The rules in section 12.1 exempt any client entry
  whose identity triple (`email`, `subId`, `id`) is byte-identical to one already stored,
  so a legacy account with (say) a space in its VPN username still authenticates, still
  deletes, still takes a quota or expiry edit, and does not block edits to anything else
  on its inbound. Change any part of the triple and the entry is new and held to the
  current rules. So a bad value can be carried forward, but never edited into a different
  bad value and never created.
- **`inbounds/list` is a GET, not a POST.** So are `/get/:id`,
  `/getClientTraffics/:email`, `/getClientTrafficsById/:id`, `/resellerBalance`,
  `/:id/ovpn/:proto` and all four `*-configs` routes. Meanwhile `/onlines` and
  `/lastOnline`, which read nothing and change nothing, are POSTs. There is no rule to
  infer; use the table in section 2. A POST to a GET-only route is a Gin 404, which under
  this API's convention is indistinguishable from an expired session.
- **A client posted without `"enable": true` is filtered out of the generated Xray config.**
  The port listens, nobody can authenticate, and nothing is logged. `model.Client.Enable`
  is a plain bool with no `omitempty` and no default, so an absent key unmarshals to
  `false`.
- **The inbound's own `enable` has the same trap, one level up.** `model.Inbound.Enable`
  carries no gorm default, so a create that omits `enable` stores a **disabled** inbound.
  Always send `enable=true` explicitly.
- **`totalGB` is bytes, despite the name.** The browser divides by 1 GB purely for
  display. A reseller's `allowanceBytes` and `spentBytes` are bytes too, and a unit
  mismatch on that pair is free traffic.
- **A negative `expiryTime` is a delayed start, not a past date.** Its magnitude is a
  duration in milliseconds, converted to a real deadline on the account's first use.
- **`security=tls` with a blank `certificateFile` makes Xray refuse the entire config**, not
  just that inbound. `up=0, down=0` on an inbound that should have traffic usually means it
  never worked at all.
- **Country geo files are not bundled.** Selecting one writes `ext:geoip_IR.dat:ir` and Xray
  refuses the whole config.
- Installing a protocol's **core** installs the server, not the outbound client.

---

## 14. Where the browser model and the server disagree

The Go table in `web/service/protocoldefaults.go` was ported from the JS classes in
`web/assets/js/model/inbound.js`, key for key. It matches them, with the exceptions below.
**The Go value is what gets stored**, because `FillSettingsDefaults` runs on the way in.

Verified field by field against both files: l2tp, pptp, openvpn, openconnect, sstp, ikev2,
wg-c, awg, gre, mtproto, ssh, anytls, tuic and naive all agree on every key and every
default, except as listed here. The openvpn `ciphers` list and the anytls
`paddingScheme` list are byte-identical in both.

Everything in 14.1, 14.2 and 14.4 to 14.6 is a live constructor-versus-`fromJson` split
that you can work around by sending the key explicitly. 14.3 records two entries that were
real bugs and have since been fixed, kept because the behaviour differs across binaries.
14.7 and 14.8 are not divergences at all: they are two things that look like one when you
diff the Go against the JS, listed so you do not go hunting.

### 14.1 openvpn `separatePorts`: constructor `false`, `fromJson` `true`

`Inbound.OpenvpnSettings`'s constructor defaults it to `false` (TCP and UDP share
`inbound.port`), but its own `static fromJson()` resolves an absent key to `true`. Go uses
**`false`**, matching the constructor, which is what the Add form starts from and the only
reading that cannot collide with another inbound already holding 1194.

Consequence: an openvpn inbound stored **without** the key was created by the server as
"shared port" but reads back in the browser as "separate ports". Send the key explicitly
and neither side has to guess.

### 14.2 ssh `userLimit`: constructor `0`, `fromJson` `1`

Same split. Go uses **`0`** (no limit), matching the constructor. The `fromJson` value of
1 exists so inbounds stored before the field existed resolve the way `effectiveSshK(nil)`
resolves them. For a new inbound created over the API, 0 is what you get.

### 14.3 Two entries that used to live here are now fixed

Both were real bugs rather than model divergences, and both were closed in `f350d437`.
They are kept named here because the behaviour differs across binaries, and a script
written against an older panel may still be working around them.

**A per-client `method` was dropped on `/add` (shadowsocks).** `AddInbound` re-marshals
`settings.clients` through `[]model.Client`, which had no `method` field, so a shadowsocks
inbound created in one `/add` call lost every per-account cipher and collapsed onto the
inbound's. The same account created through `/addClient` worked, because that path splices
the raw client map, which is why it presented as protocol flakiness rather than as a
path-specific bug. `model.Client.Method` now exists (`omitempty`), so the field round-trips
on every path. Same class as the `Username`, `Slot`, `Secret`, MTProto mode flag, `Peers`
and `Devices` fields added before it.

**The three identity validators were never called.** `ValidateClientEmail`,
`ValidateClientSubID` and `ValidateVpnUsername` existed with tests, and both a code
comment and `accounts-upgrade-guide.md` claimed they were enforced, but no write path
invoked them: pure functions validate nothing until something calls them. They are now
wired into all four write paths, with the protocol taken from the stored inbound on the
two client paths. The rules themselves, and the deliberate carve-out for deletes and for
the migration, are documented as live behaviour in **section 12.1**, not here.

If you are driving a panel older than `f350d437`, neither of the above holds: send a
shadowsocks per-client `method` through `/addClient` rather than `/add`, and treat the
section 12.1 rules as your own responsibility, since nothing server-side will enforce
them.

### 14.4 The JS constructors seed one account, the Go defaults seed none

`Inbound.L2tpSettings` and every sibling start with one client in the array, so the
panel's Add form always shows an account. `DefaultSettingsFor` deliberately returns
`"clients": []`: the browser can mint a credential locally, but an account created
server-side would be one the caller never asked for and never sees the password of. Post
no `clients` and you get an inbound with none.

### 14.5 The IPsec pre-shared keys are minted by only one of the two JS entry points

For l2tp (`randomSeq(16)`) and gre (`randomSeq(24)`) the JS **constructor** mints a PSK
while `fromJson` does not: l2tp passes an absent `ipsecPsk` through as `undefined`, gre
defaults it to `""`. Go mints one, matching the constructor, so a new inbound created over
the API always has a usable secret. GRE mints it even with `ipsecEnable` off, exactly as
the form does, so turning IPsec on later does not also require inventing a secret.

### 14.6 anytls `paddingScheme` seeds only on a new inbound

Constructor seeds the 9-line default; `fromJson` reads an absent key as `[]` so an
operator who deliberately cleared the field sees it stay cleared. Go seeds the default,
matching the constructor. The practical rule for an API caller is in section 7.1: omit the
key for the default, send `[]` for no padding at all. Note that `[]` survives, because
`FillSettingsDefaults` only adds keys that are **absent**; a present empty array is a
choice and is left alone.

### 14.7 Key order differs, and that is expected

`DefaultSettingsFor` and `FillSettingsDefaults` build a `map[string]any` and marshal it,
and Go sorts map keys, so the stored settings JSON comes out **alphabetical**. The JS
`toJson()` emits in the order its object literal is written. The ordering in
`protocoldefaults.go` follows the JS so the table reads as a diff against the spec, but it
does not survive into storage.

Nothing depends on order, and `AddInbound` already re-marshals a UI-created inbound the
same sorted way, so a panel-created and an API-created inbound of the same protocol agree.
It is listed here only because anyone diffing the two texts sees it immediately and
reasonably wonders whether something was rewritten.

### 14.8 Three settings keys exist on the Go side with no place in the defaults table

`localIp` and the legacy singular `ipRange` are real keys the server reads but that
`protocolSettingDefaults` deliberately does not list, so they will not appear in any
section 6 table. **Do not post either one.**

| Key | Where | What it is |
|---|---|---|
| `localIp` | `l2tpSettings`, `pptpSettings`, `sstpSettings` (Go structs only) | The PPP gateway address, derived server-side as the first range's `.1`. It has no JS counterpart at all and nothing reads a posted value as authoritative |
| `ipRange` | read generically by `decodeRanges` in `vpnrange.go` | The legacy single-range field, kept as a **read-only fallback**: consulted only when `ipRanges` is absent or contains nothing but blanks |

One correction worth making explicitly, because it is easy to get backwards: `ipRange` is
**not** Go-only and **not** limited to the three PPP-family structs. `decodeRanges` reads
it out of the raw settings map for any protocol that goes through `NormalizeVpnRanges`,
and the browser reads it too, on l2tp and pptp, whose `fromJson` seeds `ipRanges` from it
when the list is empty. It is a compatibility path on both sides, not a server-side
oddity. `localIp` is the one that is genuinely Go-only.
