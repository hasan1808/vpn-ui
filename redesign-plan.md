# Panel UI redesign - research and implementation plan

Recomposing the whole panel UI onto the `bento` direction from `redesign/`, with the
`aurora` treatment for VPN Services. This document is the research record and proposed
implementation contract, produced from a 2-agent recon of the current frontend and the
mockups. Mirrors the style of `ikev2-plan.md` / `wireguard-plan.md` / `ssh-plan.md`.

STATUS: RESEARCH DONE, PHASE 1 PARTIALLY EXECUTED (see "Work already banked").
Nothing committed. No template touched yet.

---

## The strategic reality check (read this before the decisions)

Three findings change the shape of this job. None were obvious going in.

**1. The mockups contain no tables, and the panel is mostly tables and forms.**

`bento.html` and `aurora.html` have zero `<table>`, `<thead>`, `<tr>`, and no table
primitive among their ~18 components. The panel has **11 `a-table`s driven by 56 scoped
slots**, plus a custom drag-sortable wrapper (`component/aTableSortable.html`, 236 lines).
`inbounds.html` is a master table with a *nested expandable client table* inside it
(`inbounds.html:252` and `:814` plus `component/aClientTable.html`).

The mockups also invent no form vocabulary, and **686 `a-form-item` / 349 `a-input` /
301 `a-select-option`** is what the panel actually is. Across all 88 files, **81% of tags
are ant components** (3,872 `<a-*>` vs 910 plain HTML).

So the design work that remains is not "port bento to the other pages". It is *designing
the two primitives bento never had*: a table and a form row. Everything else is porting.

**2. Light mode has never had tokens.**

All 58 CSS custom properties in `custom.min.css` are `--dark-color-*`, plus a single brand
token `--color-primary-100:#008771`. Light mode is stock ant-design with no semantic layer
at all. The mockups define a full light palette. This is a genuine improvement, but it means
roughly half the theme work is net-new authoring, not a variable swap.

**3. There are three theme states plus a transient guard, and the panel ignores the OS.**

  - `body.dark` / `body.light`, set by `aThemeSwitch.html:50` via
    `setAttribute('class', theme)`. That **replaces the entire body class list**, so
    nothing else may live there. Defaults to dark.
  - `html[data-theme='ultra-dark']` (`custom.css:98`), which *redefines the same
    `--dark-color-*` vars*. Stored under a separate localStorage key and therefore
    **independent** of the dark/light flag: `light` + `ultra-dark` is a reachable state.
  - `html[data-theme-animations='off']` (`custom.css:59`) is **not** a user preference.
    `aThemeSwitch.html:52-71` sets it while the theme control is hovered and removes it on
    `mouseleave`/`touchend`. It is an anti-flicker guard that suppresses every transition
    firing at once during a theme swap.
  - OS `prefers-color-scheme` is honoured by the mockups and **ignored** by the panel.

Ultra-dark must survive the port or the redesign is a feature regression, and new
components must opt into the anti-flicker guard or theme switching will visibly tear.

None of this argues against the redesign. It argues for doing the theme layer properly
first and treating tables and forms as design work, not porting work.

---

## What "every page recomposed" means concretely

Scope was chosen as full recomposition. That is ambiguous in one important place, so this
plan draws the line explicitly:

**In scope: page-level composition.** Every page's layout, card structure, headers,
toolbars, spacing, and visual hierarchy get rebuilt on the bento vocabulary.

**Out of scope: replacing ant-design form controls.** `a-input`, `a-select`, `a-switch`,
`a-form-item` and friends stay, restyled through the token layer. Replacing 686 form-items
with hand-rolled controls would mean reimplementing ant's validation, label-col semantics,
and slot contracts, and would put **1,371 `{{ i18n }}` call sites across 698 keys in 13
locales** at risk for close to zero visual gain. The forms will look new because the
controls are restyled and the layout around them is rebuilt.

If that boundary is wrong, say so now. Moving it later is expensive.

---

## Architecture: the token bridge

This is the load-bearing decision. The existing 752 CSS rules must keep working while new
components use a clean vocabulary.

**Do not rename `--dark-color-*`.** Instead, introduce the mockups' semantic tokens as the
source of truth and make the legacy names alias them. `ultra-dark` already proves the
pattern works by re-declaring the same vars at a more specific selector.

```css
:root {                      /* semantic layer, light values */
  --surface:#ffffff; --surface-2:#eef2f4; --border:#e4e9ee; --border-strong:#d2dae1;
  --text:#1b2430; --text-2:#5a6675; --text-3:#6b7787;   /* text-3 darkened, see below */
  --accent:#008771; --accent-weak:#e2f2ee; --on-accent:#ffffff;
  /* ... status colours + -weak pairs ... */
}
body.dark {                  /* semantic layer, dark values */
  --surface:#151f31; --surface-2:#1c2740; --border:#2c3950; --border-strong:#3c4b68;
  --accent:#1bbf9f; --on-accent:#071a16;
  /* ... */
}
:root {                      /* ant-compat aliases, unchanged consumers */
  --dark-color-surface-100:var(--surface);
  --dark-color-stroke:var(--border);
  /* ... partial map, see below ... */
}
```

Why this works: every legacy rule is `.dark`-scoped (352 `.dark` selectors), so aliasing in
`:root` is safe in light mode. `ultra-dark` keeps overriding `--dark-color-*` directly and
still wins on specificity.

The alias map is **partial by necessity**. Roughly 10-12 of the 58 legacy vars map cleanly.
The rest have no mockup equivalent and stay as literals:
`--dark-color-surface-400` (translucent), `--dark-color-surface-700` (darker than
background, used for insets), the five `tag-{green,red,blue,orange,purple}` triplets, the
CodeMirror and scrollbar vars. Leave them. Do not invent mockup tokens to cover them.

**The mockups are missing a whole token tier.** They define 23 properties, all colour and
shadow. Zero spacing, radius, font-size, or z-index tokens; every dimension is a hardcoded
literal. Phase 1 must add that tier. The mockups' own values give the scale: radii cluster
at 8/9/10/12/16/999px, grid gaps at 16/18/20px.

**Three defects to fix during the lift, not inherit.** All ratios below were computed, not
estimated (`scratchpad/contrast.py`):

  - `--text-3` is `#94a1b2` on white, **2.63:1**, used on 11-12.5px text. Fails WCAG AA
    (4.5:1). Fixed to `#6b7787` (4.55:1). Dark was `rgba(255,255,255,.40)` = 3.77:1, fixed
    to `.48` = 4.81:1.
  - **The brand green fails AA behind white text.** `--on-accent` white on `--accent`
    `#008771` is **4.46:1**, fractionally under, and that pairing is every primary button
    in light mode. The brand colour is not changed: `--accent` stays `#008771` for text,
    borders, icons and rings, and a new `--accent-strong` `#00806b` (4.88:1) is used only
    for filled surfaces carrying `--on-accent`. The two greens are near-indistinguishable
    side by side. Dark mode was already fine at 7.70:1.
  - The mockups write each palette out **four times** (`:root`, the
    `prefers-color-scheme` media query, and both `[data-theme]` blocks). Collapse to one
    declaration per theme. The JS already resolves OS preference in `effectiveTheme()`, so
    the media query block is redundant.

---

## Status as of 2026-07-21

| Phase | State |
|---|---|
| 1 theme layer | DONE |
| 2 layout shell | DONE |
| 3 Overview | DONE |
| 4 table primitive | DONE as an ant restyle; `inbounds.html` markup NOT recomposed |
| 5 remaining pages | Shell + control restyle applied to all; page bodies NOT recomposed |
| 6 cleanup | NOT STARTED |

**Verified in a real browser.** A headless-chromium CDP harness in the session scratchpad
(`probe.js`, `shot.js`, `jscheck.py`) logs in, visits each page, reports console errors and
whether Vue actually mounted, and captures screenshots per theme. All six panel pages mount
with zero console errors. Overview renders 10 tiles; the rail renders 7 items.

Still unchecked: ultra-dark, RTL (`fa_IR` / `ar_EG`), and mobile widths.

Bugs the browser caught that no static check could:

  - `const sz = SizeFormatter.sizeFormat` detached the method from its receiver;
    `sizeFormat` reads `this.ONE_KB`, so it threw and aborted the whole Overview render.
    The page was blank behind `v-cloak`. **This is why template-parse tests are not
    verification.**
  - `coreStateKey` mapped through `coreStateColor()`, which returns hex literals rather
    than palette names, so every VPN service collapsed to "stopped" while still displaying
    "Running".
  - The `sparkline` component hard-clamps to `0..100` because it was written for CPU
    percent. Fed bytes/sec it pinned every point to the ceiling and drew a solid block.
    Added an opt-in `autoscale` prop; percent charts keep the fixed axis.
  - Table headers were uppercase with letter-spacing, which broke "Enabled" mid-word into
    "ENABLE D" in a narrow column.
  - `.ant-checkbox-inner` inherits a teal tint from custom.css in dark mode, so unchecked
    boxes read as half-selected.

**Debug mode does not hot-reload translations.** `locale.InitLocalizer` always reads the
embedded `i18nFS` (`web/web.go:243`), so templates and CSS come off disk but new i18n keys
need a rebuild. Use `SKIP_SUBMODULES=1 SKIP_CORE=1 ./build.sh` to avoid the submodule
rewind trap. Browsers also cache the stylesheets, since the cache-buster is the app version
and that does not change during iteration.

Known cosmetic issue, not fixed: `assets/img/logo.png` has a dark background baked into the
asset, so on the now-white light-mode rail it reads as a dark box. Needs a transparent or
theme-aware logo.

The strategy that made phases 4 and 5 cheap: rather than recomposing 24,000 lines of
markup, `ant-bridge.css` re-skins ant-design itself through the token layer. All 11 tables,
22 modals and 686 form items pick up the new design with zero template edits and zero risk
to the 1,371 i18n call sites. Recomposing individual page bodies is now optional polish
rather than a prerequisite.

Files added: `web/assets/css/tokens.css`, `components.css`, `ant-bridge.css`.
`custom.min.css` became `custom.css`. Templates touched: `common/page.html`,
`component/aSidebar.html`, and the seven page files.

---

## Phases

Ordered so that each phase is independently reviewable in the browser and nothing later
invalidates something earlier.

### Phase 1 - theme layer  [DONE, pending visual check]

  - DONE. `custom.min.css` expanded to `custom.css` via `git mv` (history preserved),
    3,076 lines, round-trip verified. `common/page.html:10` updated. There is no CSS build
    step, so a minified checked-in artifact only made edits impossible.
  - DONE. New `web/assets/css/tokens.css`, loaded *before* `custom.css`
    (`common/page.html:10-11`). Semantic colour for all three themes, the net-new light
    palette, the missing spacing / radius / type / motion tiers, computed contrast fixes,
    and `.ltr-island` / `.tnum` direction utilities.
  - DONE. Ultra-dark hand-authored, preserving the surface inversion.
  - DONE. Motion tokens zero out under `html[data-theme-animations='off']` so new
    components join the existing anti-flicker guard, and under `prefers-reduced-motion`.
  - DEFERRED, deliberately: **the ant-compat alias map.** See below.
  - DEFERRED to component authoring: the RTL pass. There are no redesigned components yet
    to make direction-safe. `tokens.css` ships the two utilities needed
    (`.ltr-island` for charts, IPs, versions and numerals; `.tnum`), and the rule for
    Phases 2-5 is logical properties only (`margin-inline-start`, `border-inline-end`,
    `text-align:start/end`). Bento has just **four** physical-direction declarations to
    convert when its CSS lands.

**Why the alias map is deferred.** Pointing the legacy `--dark-color-*` names at the new
semantic tokens is the obvious way to get one source of truth, and it is still the goal.
Doing it in Phase 1 would have been wrong for two reasons:

  1. Only four legacy values map exactly (`--dark-color-background`, `-surface-100`,
     `-surface-300`, `-stroke`). The rest differ: the mockups run text brighter (`.88` vs
     `.75`) and use a different `--surface-2` (`#1c2740` vs `#222d42`). Aliasing today
     would silently restyle all seven existing pages at once, mid-project, before any of
     them has been recomposed and while there is no visual baseline to compare against.
  2. Custom properties resolve against the element that declares them. The semantic tokens
     vary at `body.dark` while the legacy names are declared at `:root`, so a naive
     `--dark-color-x: var(--y)` on `:root` would capture the **light** value and break dark
     mode. The alias map has to be declared at `body` level.

Do it per page as each is recomposed, so every visual change lands with a page someone
actually looked at. `tokens.css` carries this note at its foot.

Exit criterion not yet met: **nobody has looked at the panel.** `tokens.css` styles no
component and can only change rendering via the two new utility classes, which nothing uses
yet, so the risk is low. It is still unverified visually.

Exit: existing panel renders unchanged in all four theme axes, on the new stylesheet.

### Phase 2 - layout shell

Highest-leverage structural fix in the project. Today **there is no layout shell**: all 7
pages hand-rebuild identical chrome (`index.html:19-22`, `inbounds.html:5-9`,
`core.html:5-8`, `settings.html:5-8`, `xray.html:12-15`, `admins.html:5-8`), and
`aSidebar.html` duplicates its entire nav twice inside itself (lines 4-19 for the sider,
20-38 for the mobile drawer). Any chrome change is currently a 7-file edit plus a 2-place
edit inside the sidebar.

  - Real layout `define` in `common/page.html`.
  - Collapse the sidebar/drawer duplication to one nav template.
  - Port bento's rail nav (`bo-rail`, 84px, collapses to 60px icons-only under 560px) and
    topbar (`bo-topbar`: hostname chip, health pill, theme toggle).
  - Add the page-title bar the panel currently lacks entirely. Today each page renders its
    own bare `<h2>` or nothing.

Exit: all 7 pages share one shell; chrome changes are a 1-file edit.

### Phase 3 - Overview

The best-understood phase; the mockup is the spec.

  - Port bento's 10-tile `grid-template-areas` mosaic at its three breakpoints.
  - Port the 4 JS-backed primitives: ring gauge, sparkline, hero area chart, IP mask.
    Rewrite as computed SVG paths in Vue, not string concatenation into `innerHTML`. The
    mockups build SVG as strings, which fights the framework and is an XSS pattern you do
    not want with server data.
  - Delete the mockups' seeded-PRNG `synth` block; that is throwaway mock data.
  - VPN Services: take aurora's `.ad-chip` **visual** treatment with bento's `data-state`
    **mechanism**. Aurora encodes state twice (parallel modifier classes on both dot and
    label); bento encodes it once as an attribute, which is what you want to bind in Vue.
    Rename to `.bo-svc-chip`: `.bo-chip` already exists in bento meaning an identity pill.
  - This card is the single easiest thing in the project. `index.html:97-107` is already
    plain `<div>`s, not ant components, behind four clean helpers (`vpnCoreStatuses()`,
    `coreLabel()`, `coreStateColor()`, `coreStateText()`). Swap markup, keep the contract.

Note: bento and aurora have **byte-identical `:root` blocks**, verified. All seven mockups
share one palette. The cherry-pick is token-safe; the only conflicts are the `ad-` to `bo-`
prefix rename and the `.bo-chip` collision above.

### Phase 4 - table primitive, then inbounds

The design gap. Nothing to port; this must be designed first, and it is the one place a
static mockup earns its cost.

Design in `redesign/table.html` against real inbounds data shapes, then implement:

  - Header, sort affordance, row, expanded row, selection, pagination, empty state,
    loading skeleton, and the mobile collapse.
  - Then recompose `inbounds.html` (2,754 lines, 209 i18n keys, the page users live in).
  - Then `component/aClientTable.html` (346 lines) and `aTableSortable.html` (236 lines).

**The `isMobile` conflict lands here.** Responsive behaviour today is a JS data property
(60 uses; 19 in `index.html`, 16 in `inbounds.html`), not CSS. `inbounds.html:252` swaps
entire column arrays via `:columns="isMobile ? mobileColumns : columns"`. The mockups are
CSS-breakpoint-driven. Resolution: keep `isMobile` only where it genuinely must be JS (ant
table column arrays are defined in JS), and move every pure show/hide to CSS media queries.
Do not try to eliminate it.

### Phase 5 - remaining pages

In ascending order of pain, which is also descending order of confidence:

  - `login.html` (103 markup lines, self-contained, its own SVG wave hero)
  - `admins.html` (96 markup lines, 1 toolbar + 1 table with 6 slots, thinnest page)
  - `core.html` (358 markup lines) - already class-based, with a 580-line inline
    `<style>` block at `core.html:662-1242` defining ~60 bespoke classes. Fold those into
    the token layer rather than rewriting from scratch.
  - `settings.html` + `settings/panel/*` (7 files) and `xray.html` + `settings/xray/*`
    (7 files). Both parent pages are near-empty shells around one `a-tabs`; the real markup
    is in the sub-templates.
  - 22 modals (5,266 lines).

**Do not change the tab implementation on `xray.html`.** Two panes use
`force-render="true"` (`xray.html:92,123`) because CodeMirror needs a mounted DOM node.
Swapping `a-tabs` breaks the editors.

### Phase 6 - cleanup

  - Strip the inline `:style="{...}"` object literals on recomposed pages. There are **583**
    total, densest in `form/protocol` (126), `.` (112), and `modals` (84). They are mostly
    layout (width, flex, margin), so they do not fight a colour restyle, but they will fight
    a layout rebuild and must go from pages that get recomposed.
  - Add the `aria-live` regions the mockups lack entirely (0 in both files). This is a
    live-updating monitoring panel; throughput and service-state changes are currently
    silent to screen readers.
  - Give charts `<title>`/`aria-label`. They are `aria-hidden="true"` with `role="img"` and
    no accessible name.
  - Define or delete `.num`, used 23 times in bento but never defined there. Aurora defines
    it. Currently harmless only because the root container sets `tabular-nums`.

---

## Risks

**i18n regression is the top risk.** 1,371 call sites, 698 distinct keys, 13 locales, and
keys are embedded in JS method bodies too, not just markup (`index.html:911, 1074, 1451,
1488`). Every recomposed page must carry its keys across. Mitigation: the key-parity
ratchet test in `web/i18n_toml_test.go` is the regression suite; run it after every phase.

**Portal-rendered overlays lose the theme.** There are 49 manual
`:class="themeSwitcher.currentTheme"` / `:overlay-class-name` / `:wrap-class-name` bindings
forcing modals, dropdowns and popovers to inherit the theme, because ant renders them
outside the app root. Any shell change must preserve these or overlays go light-on-dark.

**Scoped slots couple markup to JS.** 470 `slot=` plus 56 `slot-scope`/`scopedSlots`. Table
column definitions live in JS and reference render slots by name, so table markup and JS
must change in lockstep.

**Chart resize.** The mockups re-render SVG on a 150ms-debounced `resize` because viewBoxes
are computed from `clientWidth`. Carry that over or charts distort.

**One number, two sources of truth.** `.bo-ring-progress` hardcodes
`stroke-dasharray:100.5` in CSS while the JS computes `2 * pi * 16 = 100.53` and overwrites
it. Pick one.

---

## Verification

No E2E. Per project convention, stop at build plus browser check.

  - `VPNUI_DEBUG=true` serves **both** templates and assets from disk
    (`web/web.go:260-268`), so the loop is edit, refresh, look. No `./build.sh` needed for
    template or CSS work.
  - `./build.sh` (repo root, no flags) only when Go changes.
  - `go test ./web/...` after each phase, for the i18n ratchet and template-parse tests.
  - Check all three theme states each phase: light, dark, ultra-dark. Also hover the theme
    control and confirm the anti-flicker guard still suppresses transitions.
  - Check RTL with `fa_IR` and `ar_EG`.

**Two test failures are pre-existing. Do not chase them.** Both were reproduced at pristine
HEAD in a detached worktree, with no redesign changes present:

  - `TestWgcXrayConfig` (`web/service/wgc_test.go:135`), `xray -test` exit 23. Environmental:
    the test needs `geoip.dat` beside `corebundle/core/amd64/xray`, but that directory is
    gitignored (`.gitignore:53`) and currently holds only `xray` and `.xray.commit`. The
    guard at `wgc_test.go:123` skips when the *binary* is missing but not when the *geo
    files* are, so it skips cleanly on a fresh checkout and hard-fails on a machine that has
    built once. Widening that guard would make it honest.
  - `TestDenyShapeMatchesRequestKind` (`web/controller/permission_test.go:111`),
    "page navigation denial = 200; want 307 redirect". A real pre-existing behaviour bug,
    not environmental: permission denial on page navigation returns 200 instead of
    redirecting. Unrelated to the redesign, but worth a look given the multi-admin work.

The tests that gate this project, `TestAllTemplatesParseAndProtocolFormsDefined`,
`TestEditedTemplatesParse` and `TestTranslationsAreValidToml`, all pass.

---

## Work already banked

The unminified stylesheet exists and is verified. `custom.min.css` is 63,077 bytes on a
single line with zero newlines, inherited from upstream 3x-ui (its git history is all
upstream PR numbers: #3980, #3607, #3520, #3487, #3483). Every edit today is a surgical
string replace inside one line.

A dependency-free Python expander (no node, prettier or npx on this box) produced a
**3,076-line** readable file, byte-verified semantically identical by a whitespace-
insensitive canonical round-trip that also normalises the optional trailing `;` before `}`.

    scratchpad/unmin.py     the expander, with the round-trip checker
    scratchpad/custom.css   verified output, 70,174 bytes, 3,076 lines

Structure it revealed: 752 top-level rules, 15 `@media`, 12 `@keyframes` (plus 5
vendor-prefixed), 1 `@supports`, 1 `@property`, and **63 uses of native CSS nesting**.

Both files are in the session scratchpad, not the repo. Landing them is the first task of
Phase 1.

---

## Resolved decisions

**1. Ultra-dark stays, and is hand-authored, not derived.**

A lightness shift off the dark palette would be wrong, because ultra-dark deliberately
**inverts the surface relationship**. Normal dark is `background:#0a1222` with
`surface-100:#151f31`, so cards sit *lighter* than the page. Ultra-dark is
`background:#21242a` with `surface-100:#0c0e12`, so cards sit *darker* than the page
(`custom.css:98-107`). That near-black-card-on-grey look is the whole point of the theme
and no algorithmic derivation preserves it. Hand-author the ultra-dark semantic tokens,
keeping the inversion.

**2. Rail nav: 96px with icon plus wrapping label, collapsible to 64px icons-only.**

Bento's 84px rail assumes short English words. The real menu has 7 items and the longest
labels do not fit: `Администраторы` (14 chars), `Настройки Xray`, `Panel Settings`,
`پیکربندی ایکس‌ری`. At 84px that is roughly 11-12 chars per line.

Resolution: widen the rail to **96px**, allow the label to wrap to two lines, and keep the
existing i18n keys. No new short-form menu keys, which would mean 7 new strings times 13
locales for the translators to review. The collapse toggle and its `localStorage`
persistence already exist in `aSidebar.html`; keep both, and style the collapsed 64px state
as bento's icons-only rail.

Rejected: icon-only as the default. Three of the seven items are settings-flavoured
(`Panel Settings`, `Xray Configs`, `Core Settings`) and are not reliably distinguishable by
glyph alone.

**3. Service chips are clickable.**

They become `<button>`s, not `<div>`s, with focus-visible rings, keyboard activation, and
`aria-label` carrying both protocol and state (the mockups' chips are non-interactive and
have no accessible name beyond the visible text).

Destination: `core.html`, anchored to that service's card. That page renders a card per
core via `v-for` and is where a service is actually started, stopped, and configured, so it
is the natural target for a status chip. Requires giving those cards stable anchor ids.
