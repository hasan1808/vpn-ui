# Inbounds list page: five design directions

Prototypes for the last major surface in `redesign-plan.md` Phase 4, "table primitive,
then inbounds". The inbound add/edit form and the inbound info modal were done in the two
previous commits; this is the list page itself, `web/html/inbounds.html`, the page
operators actually live in.

STATUS: **Manifest picked and built.** The other four stay in the gallery as the record of
what was considered. Watch is still the ceiling and still composes on top of this; see
"What Manifest deliberately does not do" at the bottom.

Open them at `redesign/inbounds/gallery.html`. Every direction is live, both themes, with a
compact toggle, and each scheme deep-links by hash (`gallery.html#watch`). Registered in
`redesign/index.html` under "Inbounds list".

---

## What the page is today

Measured out of `web/html/inbounds.html` (1,951 lines), not estimated.

  - A five-cell stat band, then one `a-table-sortable` with **eleven columns**:
    select, ID (xs only), operate, enable, remark, port, protocol, clients, traffic,
    all-time traffic, expiry. Plus a separate five-column `mobileColumns` array swapped in
    by the `isMobile` data property at `inbounds.html:211`.
  - The protocol cell can render up to **four** tags (protocol, network, TLS, Reality) and
    for OpenVPN two download buttons on top of that.
  - The clients cell renders **five** `a-popover` tags, one per account state, each
    carrying a full email list in its overlay. That single cell is roughly 105 lines of
    template.
  - Drag reorder via `a-table-sort-trigger`, and it is deliberately disabled under search,
    filter or pagination because the drag index addresses a different array than the one
    being reordered (`canDragInbounds`).

The tag soup is the problem. A row is 8 to 12 coloured pills and no shape.

## The fixture

All five schemes render from one array of thirteen inbounds, chosen so a scheme cannot
look good by dodging the hard cases:

  - `trojan-tcp` is **enabled and completely dead**. Its certificate path is blank, so Xray
    refuses the whole configuration and every other Xray inbound is down with it. Its
    all-time traffic is 0, which is the proof it never once worked.
  - `wg-xray` **can never be metered**. Xray synthesises WireGuard peers from the client
    list, so per-peer counters do not exist. A zero here is not a fault and must not be
    drawn as one.
  - `branch-gre` **binds no port at all**. GRE is IP protocol 47.
  - `ovpn-road` listens on **two** ports (separate TCP and UDP) and is over its 2 TB quota.
  - `l2tp-dialin` expires in six days.

## The five

| | Direction | Optimised for | Cost |
|---|---|---|---|
| 1 | **Manifest** | Continuity | Lowest. Column array plus slot rewrite |
| 2 | **Rack** | Knowing which daemon serves what | Medium. Reorder semantics |
| 3 | **Console** | Density, 40 inbounds | Medium. Needs a rate the API lacks |
| 4 | **Board** | Small fleets and phones | Highest. Table affordances reinvented |
| 5 | **Watch** | Walking up to the panel cold | Medium-high. Needs a backend health model |

**1 Manifest.** The table, earned. Eleven columns become five: remark, port, protocol,
network and security collapse into one two-line identity cell, and the five account
popovers become one segmented bar with a plain-English line under it. Drag reorder,
select-all and pagination all survive untouched because it is still an `a-table-sortable`.
Cheapest thing on this list by a wide margin, and the least memorable.

**2 Rack.** Inbounds group into bands by the process that carries them (Xray core, VPN
dial-in, Relay), and each band header states whether that process is up. In the fixture the
Xray band header reads `xray rejected config` in red, which explains all six rows under it
at once. The cost is reordering: `SortOrder` is one global sequence, so a drag inside a band
has to map back to global positions.

**3 Console.** Monospace, port first, fixed columns, one line per inbound, plus a live
throughput trace per row so a dead listener is visible without opening anything. Fits 21
rows where Manifest fits 11. The honest cost: **that trace does not exist**. The API returns
cumulative counters only, so per-inbound rate means client-side differencing across polls or
a new sampling endpoint.

**4 Board.** No table at all, one card per inbound, actions on the card. The grid reflows to
one column on a phone, which deletes the `isMobile ? mobileColumns : columns` fork entirely.
In exchange, drag reorder, select-all, pagination and column sorting all have to be
reinvented outside the table, and it falls apart past roughly thirty inbounds.

**5 Watch.** The page opens on what is wrong. Anything broken, depleted, expiring or
switched off is promoted to the top with a diagnosis in a sentence and the button that fixes
it; everything healthy collapses to one quiet line each. This is the only direction that
tells you `trojan-tcp` took the whole core down rather than leaving you to notice its
counters are zero.

**Watch has a prerequisite the others do not.** The panel today stores only an `enable`
flag. "The core refused this configuration" is not recorded anywhere, so the diagnosis it
shows would have to be invented. Making it real means capturing the `xray -test` failure per
inbound in the backend. That is the price of the whole idea, and it is also the most
valuable thing on this page, because a silently refused inbound is currently invisible.

## Recommendation

**Manifest as the floor, Watch as the ceiling.** They are not exclusive: Watch's attention
band can sit on top of Manifest's table, which gets the cheap win now and lets the health
model land later without redrawing anything. Rack's band headers would graft onto either.

## Verification done

Rendered in headless chromium at 1440x1000, both themes, and read as images rather than
trusted from a parse check, per `browser-verify-harness`. All five schemes populate: 13 rows
each in Manifest, Rack, Console and Board; 4 attention cards plus 9 quiet rows in Watch.
Zero `undefined` or `NaN` in the rendered DOM.

Four defects were caught that way and fixed: a dangling separator on the accounts sub-line
when a category was empty, `wiregua` and `shadows` from slicing protocol keys instead of
mapping them, and two wrong row counts in the rationale strips.

---

# What was built

Manifest, in `web/html/inbounds.html`, `web/assets/css/components.css` and the thirteen
translation files.

## The table

Eleven columns became seven, five of which carry content:

| | Cell | Replaces |
|---|---|---|
| 1 | select | select |
| 2 | menu | operate |
| 3 | enable | enable |
| 4 | **Inbound** | remark + port + protocol + network + security |
| 5 | **Traffic** | traffic + all-time traffic |
| 6 | **Clients** | five `a-popover` tags |
| 7 | Duration | expiry |

  - **Identity** is a lamp, the remark, and one monospace signature line built by
    `inboundMeta()`: `VLESS :8443 · tcp · reality`. It was four tags that reflowed, so a
    list of inbounds had no left edge to read down. `inboundListen()` keeps the three real
    shapes: OpenVPN's separate TCP and UDP ports, GRE's `proto 47`, everything else's one
    port.
  - **The lamp is health; the switch three columns left is intent.** They disagree on
    exactly the rows worth looking at. Every state is derived from what the panel already
    stores, and each carries its word on a tooltip.
  - **Traffic** is used against cap over a meter, with all-time underneath. No cap draws
    nothing: a neutral full track was tried first and made an uncapped inbound that had
    moved 56 GB look fuller than a capped one at 86%.
  - **Clients** is one segmented bar and a sentence. Five popovers carrying full email
    lists became `4` / bar / `1 Ended · 1 Depleting · 1 Disabled`. An inbound that can
    carry accounts and has none says `None`; one that can carry none at all is an em-dash.
  - The two OpenVPN `.ovpn` download buttons moved into the row menu. They were the only
    reason one protocol's row was twice as tall as the rest.

## Type

Two sizes, both off the scale. `--fs-base` (14px) for anything that answers the row's
question - the remark, the used figure, the account count, the expiry - and `--fs-sm`
(12.5px) for anything that qualifies the answer: the signature line, the cap, both
sub-lines. The header goes from `--fs-xs` to `--fs-sm` on this page so it is not two steps
under its own content.

The first pass ran a step lower throughout, 13.5/11px, which is the scale the prototype was
drawn at in a page of its own. `ant-bridge.css` already sets **every** table in the panel to
`--fs-sm`, one step under the shell, so drawing the row below that put it two steps down and
it read as fine print. That global rule is untouched and still applies to every other table;
if the tables generally want to be a size bigger, it is the one line to change.

  - **Both ID columns are gone.** Both were already dead: the wide one is
    `responsive:["xs"]` and at xs the page is on `mobileColumns` instead (`isMobile` is
    width ≤ 768, xs is ≤ 575); the narrow one asked for a breakpoint named `"s"`, which
    antd does not have.
  - **`protocolFamily()` and the per-account comment map are gone from this page.** The
    family hue lived on the protocol tag, which no longer exists; the protocol name is
    spelled out in bold instead, and a second coloured dot 100px from the status lamp would
    have been read as a second status. The comment map fed only the popovers that went.
    `clients.html` keeps its own copy of `protocolFamily`.
  - **Mobile.** `mobileColumns` is select, menu, identity, info. The info popover now
    carries the three dropped cells in the same shapes, so the phone and the desktop teach
    the same reading. Three things had to give for it to fit in the ~226px the card body
    actually has: cell padding drops to 6px under 768px, the menu and info headers go
    blank (the words "Menu" and "Info" were each wider than the control under them), and
    the info trigger is a bare icon rather than a round button in a badge.

## Verified

Real browser, not a parse check, per `browser-verify-harness`. A throwaway panel on a fresh
DB, seeded with seven inbounds chosen to hit the awkward cases: over quota, expiring inside
the window, disabled, accounts-capable-but-empty, no accounts at all, and a 38-character
remark.

  - Renders in both themes at 1440×1000 and on a 400px phone, with no Vue exception and
    nothing behind `v-cloak`.
  - Lamps `ok/off/ok/ok/off/ok/warn`; meters empty when uncapped, error at 100%, warn
    inside the traffic window; account segments proportional.
  - Drag handle present and `canDragInbounds` true; it correctly goes false under search
    and under a filter. Select-all toggles. The row menu, the traffic popover and the
    mobile info popover all open with the right contents.
  - `inboundListen()` driven directly over every branch: `proto 47`, `tcp:1194 udp:1195`,
    a shared OpenVPN port, UDP-only, neither enabled, and the ordinary case.
  - Persian: header, lamp tooltips and both sub-lines translate, and the signature line
    stays LTR.
  - `go test ./web/... ./util/...` fails only `TestWgcXrayConfig` and
    `TestDenyShapeMatchesRequestKind`, which fail at pristine HEAD.
  - `test_unit/live/uitest.js`: 57 passed, 3 failed, all three on the Clients page and all
    three explained by the seeded fixture accounts colliding with the suite's own.

Four things the browser caught that no static check would have: the neutral full meter
reading as "full", `Healthy` printed under an empty account bar, the mobile table pushing
its info column off the right edge, and the info button's chrome eating the width the
remark needed.

## Open: the port

`redesign/inbounds/port.html`, five directions, only the port changing between tabs. The
complaint is fair: `:8443` is set in the same dim grey as `tcp` and `reality` and reads as
one more transport token, when it is one of the two or three facts the page is opened for.

| | Direction | Optimised for | Cost |
|---|---|---|---|
| 1 | **Weighted** | Costing nothing | One CSS rule. Still a token in a run of tokens |
| 2 | **Named** | Being unambiguous | The longest line of the five |
| 3 | **Chip** | Scanning a column of ports | Takes width from the remark |
| 4 | **Column** | "Is anything on 443?" | A sixth column, ~80px |
| 5 | **Endpoint** | The thing you were going to paste | The panel must know its own hostname |

All five are drawn over the three shapes a port really takes: one port, two (OpenVPN's
separate TCP and UDP), and none at all (GRE). The leading select/menu/enable cells are in
the mockup so the identity column is the ~355px it actually is; a chip pinned to the right
of a 780px column would have been judged in the wrong place.

**Column was picked and built.** See "The Endpoint column" below.

**Endpoint was picked, and taken further** in `redesign/inbounds/endpoint.html`. The first
sketch answers the right question - a port on its own is half an address - and has three
faults worth designing away: it makes the row a line taller, it repeats one hostname down
the whole column, and on a fronted inbound the address it prints is not the one a client
dials. The fixture grew two rows that decide whether a scheme tells the truth: `cdn-ws`,
bound to one interface, and `cdn-fronted`, reached at a CDN name the panel has never been
told.

| | Direction | Gives up | To get |
|---|---|---|---|
| 1 | **Shared host** | A caption line, easy to miss | The host said once; rows read `:8443` and need no third line at all |
| 2 | **Ghost host** | Contrast the panel otherwise refuses to spend | The full address with no extra line and no extra column |
| 3 | **Column** | ~190px, taken from Traffic | Endpoints that stack down one edge |
| 4 | **Handoff** | One control carrying four meanings | The artifact itself: links, `.ovpn`, or the address |
| 5 | **Reachable** | A probe the backend does not have | Whether anything actually answers there |

Two details worth keeping whichever wins. Hostnames elide from the **middle**, not the
left: a hostname's distinguishing part is its first label, and left-elision keeps the half
every host on the box shares. And an inbound with no port is not an inbound that failed a
check - Reachable forces GRE to the neutral dot with no verdict, because red there would be
the scheme's first lie on the one row it cannot know about.

## The Endpoint column

Built. Six content columns now: identity, **endpoint**, traffic, clients, expiry, plus the
select/menu/enable trio. The port left the signature line, which is now transport and
security only.

**The address is resolved the way `Inbound.links()` resolves it, in the same order**, so the
column and the share link can never disagree:

  1. An **External Proxy** list, wherever it lives - on the stream for the Xray protocols,
     on the settings for the VPN ones. When it is set, the panel's own address is not
     advertised at all, so printing it would be printing an address nobody dials. The
     per-entry remark is the line's label because the operator chose it.
  2. A **listen** address, when the inbound is bound to one interface.
  3. This **panel's own hostname**, which is the usual answer.

OpenVPN gets one line per transport. GRE gets `proto 47`: it is IP protocol 47 and has no
port for a client to dial, which is a different thing from an empty cell. At most two lines
render and the rest are counted `+N`, so an External Proxy list cannot set the height of
every row in the table. Click copies the whole address, un-elided.

Hostnames elide from the **middle**. Two details cost a round each: left-elision keeps the
half every inbound on the box shares and throws away the label that identifies it, and a
CSS `text-overflow` on top of the JS elision produced a host with **two** ellipses, which
reads as corruption rather than truncation. There is one elision mechanism now.

On a phone there is no room for a sixth column, so the endpoint sits in the info popover in
the same shape.

### A real bug this surfaced

`searchInbounds()` and `filterInbounds()` rebuilt each matching row's settings from a bare
`{ clients: [...] }`, so `Settings.fromJson` filled every other field with **class
defaults**. Under a search, a UDP-only OpenVPN inbound claimed to be listening on
`tcp:1194` - the default, not its own data. This predates the redesign: the old port cell
and the `.ovpn` download buttons read the same fiction. Both now narrow the client list
inside a copy of the full settings.

## OpenVPN downloads

They were never gone from the code, only from sight: moving them into the row menu made
them undiscoverable, which is the same thing.

They now sit **against the protocol name**, inline in the identity cell, in the accent.
That is the right place for the same reason the accent is the right colour: this is not a
row action like edit or delete, it is what the word "OpenVPN" means here - the file you
hand to a person. One home at every width, so nothing is duplicated between the row and
the menu. With both transports enabled the icon opens a two-item menu; with one, the icon
**is** the download and there is no menu of one (`ovpnTransports()`).

## What Manifest deliberately does not do

It invents nothing the backend does not record. The panel stores an `enable` flag; "the
core refused this configuration" is not stored anywhere, so a blank-certificate inbound
still renders as healthy and enabled while Xray refuses the whole config behind it. That
was Watch's whole idea and its whole cost. The attention band still composes on top of
this table when the health model lands - nothing here has to be redrawn for it.

Nor is it the generic table primitive `redesign-plan.md` Phase 4 asks for. The `bo-il-*`
classes are the start of that vocabulary but they are this page's, and
`component/aClientTable.html` has not been touched.
