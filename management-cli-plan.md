# Management CLI (`vpn-ui` menu script)

Goal: an `x-ui`-style terminal management app for this fork, with the 17 items
below. Status of each is measured against the code as of v1.7.1.

## Naming / install

- Binary stays `/opt/vpn-ui/vpn-ui-amd64` (live box) or `<exedir>/vpn-ui-amd64`.
- Menu script installs to `/usr/bin/vpn-ui`, `chmod +x`. No name clash: the
  binary is `vpn-ui-amd64`, the command is `vpn-ui`.
- Source lives at repo root as `vpn-ui.sh` (beside `deploy.sh`, `build.sh`).
- `deploy.sh` installs/refreshes it on every deploy (fresh + update).
- `vpn-ui-amd64 --uninstall` must delete `/usr/bin/vpn-ui`. Add it to the
  inventory in `web/service/uninstall.go` (model: the systemd-unit removal).

Upstream 3x-ui installs its script by curling raw.githubusercontent at `main`
and mv-ing into `/usr/bin/x-ui`. Do NOT copy that: it pins `main` even from a
tagged release, so a v2.9.3 box self-updates into a v3.5.0 menu whose numbering
does not match its own binary. Ship the script from the release we build.

## Contract with the binary

Upstream's script scrapes the Go binary's human stdout:

    local info=$(x-ui setting -show true)
    existing_port=$(echo "$info" | grep -Eo 'port: .+' | awk '{print $2}')

Do not copy this coupling. Two rules:

1. Anything the script only DISPLAYS: the binary prints it, script just runs it.
2. Anything the script must BRANCH on: add `vpn-ui-amd64 info --json`.

## Item status

Legend: OK = exists today, FIX = exists but broken/incomplete, NEW = to build.

| # | Item | Status | Backing |
|---|------|--------|---------|
| 1 | Update | NEW (thin) | `web/service/panelupdate.go` has the whole updater |
| 2 | Un-Install | OK | `vpn-ui-amd64 --uninstall [--yes]`, `main.go:332` |
| 3 | Change Username | OK | `--user <n>`, `main.go:1570` |
| 4 | Change Password | OK | `--pass <p>`, `main.go:1572` |
| 5 | Change Port | OK | `--port <n>`, `main.go:1576` |
| 6 | Change Web-Path | OK | `--path <p>`, `main.go:1574` |
| 7 | Reset Login (--random) | OK | `--random`, `main.go:424` |
| 8 | View current login info | FIX | `showSetting`, `main.go:624` |
| 9 | Start (systemd) | NEW (thin) | `systemctl` + `GetServiceName()` |
| 10 | Stop (systemd) | NEW (thin) | same |
| 11 | Restart (systemd) | NEW (thin) | same |
| 12 | Start Xray | NEW (IPC) | see "The Xray/cores problem" |
| 13 | Stop Xray | NEW (IPC) | same |
| 14 | Restart Xray | NEW (IPC) | same |
| 15 | Xray Logs | NEW (file) | access log is on disk |
| 16 | Restart All Cores | NEW (IPC) | `CoreService.RestartAll()`, `core.go:746` |
| 17 | Get SSL | NEW (port) | `deploy.sh:43` `obtain_letsencrypt_cert` |
| 0 | Exit | NEW | trivial |

Items 2-7 are already work-safe: they stop the unit, apply, restart it
(`main.go:522-528`). They were built as `deploy.sh`'s non-interactive backend;
the menu becomes their second consumer. No backend work for six of the items.

## The Xray/cores problem (items 12, 13, 14, 16)

Xray and the VPN daemons are CHILD PROCESSES of the running panel, tracked by
in-process state:

- `web/service/xray.go:58`: `IsXrayRunning() { return p != nil && p.IsRunning() }`
  where `p` is a package-level var.
- `web/service/procmgr.go:130`: `var procMgr = &ProcManager{...}`, a singleton,
  whose per-core logs are an in-memory ring buffer (`procLog`, `procmgr.go:82`).

A separate `vpn-ui-amd64 stop-xray` process starts with `p == nil`. Therefore:

- `StopXray()` returns "xray is not running" while Xray IS running.
- `RestartXray()` would spawn a SECOND Xray that collides on 62790 and every
  inbound port.

So 12/13/14/16 CANNOT be plain CLI subcommands. They must be IPC to the live
panel. Upstream sidesteps this the same way: their "Restart Xray" is
`systemctl reload x-ui`, i.e. a signal to the panel process.

### Chosen design: a root-only unix control socket

New `web/service/control.go`, started by `runWebServer()`:

- Listen on `<exedir>/vpn-ui.sock`, mode 0600, owner root. Unlink stale socket
  on start (mirror `ReapOrphanXray`'s orphan logic).
- Line protocol, one JSON request -> one JSON response. No auth needed: the
  socket is root-only, and every CLI path already calls `requireRoot()`.
- Commands: `xray.start`, `xray.stop`, `xray.restart`, `cores.restart-all`,
  `cores.status`, `info`.
- Handlers call the SAME services the web controllers call
  (`XrayService.RestartXray/StopXray`, `CoreService.RestartAll`), so there is
  one code path, not two.

New CLI subcommand `vpn-ui-amd64 ctl <cmd>` dials the socket and prints the
reply. If the socket is absent or refuses: print "panel is not running" and
exit non-zero. Never fall back to acting locally, that is the bug above.

Why not signals: SIGUSR1 already means restart-xray (`main.go:279`), but
signals cannot carry a command set nor return data (needed for `cores.status`).

## Item 15: Xray Logs (no IPC needed)

Xray's access log is a real file:
- `xray/process.go:71` `GetAccessLogPath()` (reads it out of the Xray config)
- `xray/process.go:61` `GetAccessPersistentLogPath()` -> `<logdir>/3xipl-ap.log`

The script tails the file directly. Verify what `web/controller/server.go:78`
(`/xraylogs/:count`) reads and match it, so the menu and panel agree.

Note the per-CORE logs (item 16's neighbours) are the in-memory ring buffer and
are NOT on disk. If a "core logs" menu item is ever wanted, it needs the socket.

## Items 9-11: systemd

- Resolve the unit via `SystemdService.GetServiceName()` (`systemd.go:53`). It
  is operator-configurable (setting `systemdServiceName`), NOT hardcoded
  "vpn-ui". Never assume the name.
- IMPORTANT (live box 65.109.217.240): the panel there runs MANUALLY via
  `setsid`, with the unit inactive-but-enabled. So "Stop (systemd)" will report
  success while the panel keeps running. The script must detect a
  running-but-not-under-systemd panel and say so, rather than lie.
  Detect: unit inactive AND a live `vpn-ui-amd64` process AND/OR the control
  socket answers.

## Item 1: Update

`web/service/panelupdate.go` already has the entire mechanism:
- `CheckPanelUpdate()` `:64` -> current vs latest tag (GitHub API)
- `UpdatePanel()` `:221` -> download, ELF+arch validate, swap, restart
- `restartPanel()` `:476` -> handles BOTH systemd and manual (setsid/re-exec)
- Same asset `deploy.sh` uses: `Sir-MmD/vpn-ui` / `vpn-ui-amd64`

Do NOT have the CLI call `UpdatePanel()` directly. `restartPanel()` ends in
`syscall.Exec(exe, os.Args, ...)` when there is no systemd, which from a CLI
process would re-exec the CLI with its own `update` args, i.e. a loop.

Plan: new `vpn-ui-amd64 update` that REUSES `downloadPanelBinary` +
`isCompatibleBinary`, and then:
1. Back up the DB first (deploy.sh:202 already does this; the in-binary updater
   does NOT). Copy the WAL/SHM sidecars too. Abort if the backup fails.
2. Swap the binary.
3. Restart via the unit if active, else instruct the operator.

Alternative considered and rejected: menu Update = `bash <(curl .../deploy.sh)`,
which is what upstream does. Rejected: requires network+curl piping to root
shell, and duplicates logic we already ship.

## Item 8: View current login info (FIX)

`showSetting` (`main.go:624`) prints port, webBasePath, SSL status,
hasDefaultCredential. It does NOT print the username and does NOT print the
access URL, which are the two things this menu item exists for.

Two real bugs in the same function:
1. `main.go:652` dereferences `userModel` after the error at `:647` without a
   nil check -> panic when the lookup fails.
2. `showSetting`/`GetCertificate`/`GetListenIP` never call `InitDB` themselves;
   they rely on `updateSetting` having run first in the same `setting`
   invocation (`main.go:1699` before `:1703`).

Plan: new `vpn-ui-amd64 info [--json]` that calls `InitDB` itself and prints
username, port, webBasePath, listen IP, SSL on/off, version, unit name+state,
and the assembled panel URL (reuse the URL logic already in
`applyExplicitSetting`, `main.go:514`). Menu item 8 just runs it.

## Item 17: Get SSL

`deploy.sh:43` `obtain_letsencrypt_cert()` already does acme.sh standalone
HTTP-01, installs the cert, sets `--reloadcmd`, and calls
`vpn-ui-amd64 cert -webCert <f> -webCertKey <f>`.

Plan: factor it into the menu script (acme.sh is a bash tool, keep it in bash).
Both `deploy.sh` and `vpn-ui.sh` should share it rather than fork it. Keep the
existing behaviour of warning when :80 is in use, and stay best-effort (never
leave the panel's TLS worse than it was found).

## Separate bug found while mapping (not a menu item)

`vpn-ui-amd64 setting -port 8443` (the legacy Go-flag path) calls `InitDB` with
NO busy timeout and NO stop-the-unit envelope, unlike the safe `--port` path.
Against a live panel it writes concurrently and the panel keeps serving the old
value until restarted. Either give `setting` the same envelope, or make it a
thin alias of the `--port` path.

## Build order

1. `vpn-ui-amd64 info [--json]` + fix the `showSetting` nil-deref.
2. `web/service/control.go` + `vpn-ui-amd64 ctl <cmd>`.
3. `vpn-ui-amd64 update` (with the DB backup the in-binary path lacks).
4. `vpn-ui.sh` menu, sharing `obtain_letsencrypt_cert` with `deploy.sh`.
5. `deploy.sh` installs the script; `uninstall.go` removes it.
6. E2E: extend `test_unit/` with a menu phase. Do NOT run incus E2E unless
   explicitly asked.

## UX

Match `deploy.sh`'s existing style (`msg`/`act`/`ok`/`warn`/`die`/`hr`, the
pacman-ish `::` headers), not upstream's `LOGD/LOGE` + raw ANSI. It is already
the house style and the two scripts sit side by side. No emoji.
