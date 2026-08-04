"""Run orchestrator: parallel job pool over server distros.

Each job is fully self-contained (own incus bridge + name prefix), so N jobs run
concurrently without server/client IP or name clashes. A job = 1 server VM + 3
client VMs (the 3rd drives the User Limit Strategy test past the K=2 cap); it
provisions, sets up inbounds/routing, runs all three protocol suites, then tears
down.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import os
import signal
import sys
import tomllib
import traceback

from . import (abort, provision, server_setup, protocols, multi_inbound, bulkops,
               backup_test, subscription_test, warp_test, random_test, systemd_test,
               uninstall_test, style)
from .console import Console
from .clients.base import Client
from .incus import Incus, image_exists, IncusError
from .model import (JobResult, SubTest, Status, ALL_PHASES, PHASE_CORE, PHASE_SETUP,
                    PHASE_OPENVPN, PHASE_BULK, PHASE_BACKUP, PHASE_SUBSCRIPTION,
                    PHASE_WARP, PHASE_RANDOM,
                    PHASE_SYSTEMD, PHASE_UNINSTALL,
                    IKEV2_MODE_PHASES, IKEV2_PHASE_BY_MODE,
                    MTPROTO_MODE_PHASES, MTPROTO_PHASE_BY_MODE,
                    PHASE_MTPROTO_TOGGLE, PHASE_MTPROTO_TERMINATION,
                    PHASE_MTPROTO_ADTAG, PHASE_SSH, PHASE_SSH_UDP,
                    PHASE_MULTI)
from .panel import Panel
from ..report.report import write_reports

def _now() -> str:
    return dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _hms() -> str:
    return dt.datetime.now().strftime("%H:%M:%S")


# `:: <section> — …` banner section -> short phase tag shown on every sub-line.
_PHASE_TAG = {
    "core-init": "CORE", "server-setup": "SETUP", "client-prep": "PREP",
    "openvpn": "OPENVPN", "l2tp": "L2TP", "pptp": "PPTP",
    "openconnect": "OCSERV", "sstp": "SSTP", "ikev2": "IKEV2",
    "ikev2-eap-mschapv2": "IKE-EAP", "ikev2-psk": "IKE-PSK", "ikev2-eap-tls": "IKE-TLS",
    "wg-c": "WGC",
    "awg": "AWG",
    "mtproto": "MTPROTO",
    "mtproto-classic": "MT-CLAS", "mtproto-secure": "MT-DD", "mtproto-tls": "MT-TLS",
    "mtproto-toggle": "MT-TOGL", "mtproto-termination": "MT-TERM",
    "mtproto-adtag": "MT-ADTAG",
    "ssh": "SSH", "ssh-udp": "SSH-UDP",
    "anytls": "ANYTLS", "tuic": "TUIC", "naive": "NAIVE",
    "multi-inbound": "MULTI",
    "bulk-ops": "BULK",
    "backup-restore": "BACKUP", "warp-socks": "WARP", "random-cfg": "RANDOM",
    "systemd": "SYSTEMD", "uninstall": "UNINSTALL",
}


class _JobLogger:
    """Per-job logger. Tracks the current phase (parsed from `::` banners) so
    every sub-step line is tagged with the phase it belongs to, e.g.
    `04:38:29 ubuntu-24 [PPTP]   -> A connect [✓ pass]`. Writes the plain form
    to the job's .log file and pushes the colored form to the shared console
    (which keeps the progress bar pinned at the bottom)."""

    def __init__(self, distro: str, log_path: str, console: Console):
        self.distro = distro
        self.log_path = log_path
        self.console = console
        self.tag = style.distro_tag(distro, width=0)   # no padding: 1 space to tag
        self.phase = "VM"

    def __call__(self, msg: str):
        header = msg.lstrip().startswith("::")
        if header:
            self._update_phase(msg)
            colored = f"{style.dim(_hms())} {self.tag} {style.stylize(msg)}"
            plain = f"[{_now()}][{self.distro}] {msg}"
        else:
            colored = (f"{style.dim(_hms())} {self.tag} "
                       f"{style.phase_tag(self.phase)} {style.stylize(msg)}")
            plain = f"[{_now()}][{self.distro}][{self.phase}] {msg}"
        with open(self.log_path, "a") as f:
            f.write(plain + "\n")
        self.console.log(colored)

    def _update_phase(self, msg: str):
        body = msg.lstrip()[2:].strip()
        token = (body.split("—", 1)[0] if "—" in body else body).strip()
        token = token.split()[0] if token else ""
        # A ":: <phase>, <description>" header separates the two with a comma rather than
        # a dash, which leaves the comma glued to the phase name: the tag lookup then
        # misses and the column renders as a raw upper-cased "MTPROTO-CLASSIC," instead
        # of "MT-CLAS".
        token = token.rstrip(",")
        new = "VM" if token == self.distro else _PHASE_TAG.get(token, token.upper())
        if new and new != self.phase:
            self.phase = new
            self.console.set_phase(self.distro, self.phase)


def _mk_logger(distro: str, log_path: str, console: Console):
    return _JobLogger(distro, log_path, console)


def run_job(spec: dict, index: int, cfg: dict,
            run_dir: str, console: Console) -> JobResult:
    distro, image = spec["name"], spec["image"]
    log_path = os.path.join(run_dir, f"{distro}.log")
    log = _mk_logger(distro, log_path, console)
    console.start_job(distro)
    result = JobResult(distro=distro, image=image, started_at=_now())

    if abort.is_set():          # queued job never started -> no VMs to make
        result.notes = "aborted before start"
        _skip_remaining(result)
        result.finished_at = _now()
        console.finish_job(distro)
        return result

    if not image_exists(image):
        result.notes = f"image '{image}' not found on this host -> skipped"
        log(f":: {distro} — image not found, skipping")
        log(f"-> {result.notes} [skip]")
        result.finished_at = _now()
        console.finish_job(distro)
        return result

    prefix = f"vpnt{index}"
    incus = Incus(prefix, logger=log)
    created = []           # full instance names to clean up
    net = None
    server_vm = ca_vm = cb_vm = cc_vm = None
    keep = False

    # The substrate a run needs depends on the --tests selection. core-init
    # (panel bring-up) is universal — every optional phase drives the panel — but
    # the client VMs + client-prep are used ONLY by the protocol suites, and
    # server-setup (inbounds/accounts/routing) ONLY by the phases that consume
    # its result `sc` (protocols, bulk-ops, backup). A warp/random/systemd/
    # uninstall-only run therefore needs neither: we skip launching the client
    # VMs and skip those substrate phases (nothing else in a full run changes).
    def _sel(phase) -> bool:
        """True if `phase` is in the --tests selection. A missing selection
        (run_job called without main()'s resolution) means 'no filter' -> run
        all; a resolved selection is authoritative even when it picks no VM
        phase (e.g. only the host-only `export-js` id was passed)."""
        return phase in cfg.get("_selected", ALL_PHASES)

    need_clients = any(_sel(p) for p in ("openvpn", "l2tp", "pptp", "openconnect", "sstp", "ikev2", "wg-c", "awg",
                                         "gre",
                                         "mtproto", "mtproto-classic", "mtproto-secure", "mtproto-tls",
                                         "mtproto-toggle", "ssh", "ssh-udp",
                                         "anytls", "tuic", "naive",
                                         "multi-inbound"))
    need_setup = (need_clients or _sel(PHASE_SETUP)
                  or _sel(PHASE_BULK) or _sel(PHASE_BACKUP)
                  or _sel(PHASE_SUBSCRIPTION))

    try:
        nclients = 3 if need_clients else 0
        log(f":: {distro} — launching VMs (1 server + {nclients} clients)")
        incus.preclean(index)   # clear any leftover from a prior aborted run
        net = incus.create_network(index)
        server_vm = incus.launch(image, "srv", net,
                                 cfg["vm"]["server"]["cpu"],
                                 cfg["vm"]["server"]["memory"])
        created.append(server_vm)
        # Client VMs exist only to drive the protocol suites; skip them (and
        # their slow apt client-prep) entirely when no protocol is selected.
        if need_clients:
            ca_vm = incus.launch(cfg["client_image"], "cla", net,
                                 cfg["vm"]["client"]["cpu"],
                                 cfg["vm"]["client"]["memory"])
            created.append(ca_vm)
            cb_vm = incus.launch(cfg["client_image"], "clb", net,
                                 cfg["vm"]["client"]["cpu"],
                                 cfg["vm"]["client"]["memory"])
            created.append(cb_vm)
            # 3rd client: the User Limit Strategy test needs a device past the K=2 cap.
            cc_vm = incus.launch(cfg["client_image"], "clc", net,
                                 cfg["vm"]["client"]["cpu"],
                                 cfg["vm"]["client"]["memory"])
            created.append(cc_vm)

        for vm in created:
            log(f"-> waiting for agent: {vm} (up to {cfg['vm']['agent_timeout']}s)")
            incus.wait_agent(vm, cfg["vm"]["agent_timeout"])
        log("-> acquiring server IPv4 (DHCP lease)")
        server_ip = incus.ipv4(server_vm)
        result.server_ip = server_ip
        log(f"-> server reachable at {server_ip}:{cfg['panel']['port']}")

        panel = Panel(server_ip, cfg["panel"]["port"], cfg["panel"]["base_path"],
                      cfg["panel"]["scheme"], cfg["panel"]["username"],
                      cfg["panel"]["password"])

        def _aborting() -> bool:
            if abort.is_set():
                log("-> aborted by user [skip] — tearing down")
                _skip_remaining(result)
                return True
            return False

        # --- core-init ---
        if _aborting():
            return result
        log(":: core-init — provisioning (kernel modules + packages + xray)")
        usable = provision.run(incus, server_vm, panel, cfg, result)
        if not usable:
            log("-> core not usable [fail] — skipping protocol phases")
            _skip_remaining(result)
            keep = cfg.get("keep_failed_vms", False)
            return result

        # --- server setup (only when a selected phase consumes it) ---
        if _aborting():
            return result
        if need_setup:
            log(":: server-setup — inbounds, accounts, source-IP routing rules")
            sc = server_setup.run(panel, server_ip, cfg, result, log=log)
            if sc is None:
                log("-> setup failed [fail] — skipping protocol phases")
                _skip_remaining(result)
                keep = cfg.get("keep_failed_vms", False)
                return result
        else:
            sc = None
            result.phase(PHASE_SETUP).add(
                SubTest("phase", Status.SKIP, "not needed by --tests selection"))
            log(":: server-setup — skipped (no selected phase needs inbounds/routing)")

        # --- client prep (only when a protocol suite will use the clients) ---
        if _aborting():
            return result
        cA = cB = cC = None
        if need_clients:
            cA = Client(incus, ca_vm, "A", logger=log)
            cB = Client(incus, cb_vm, "B", logger=log)
            cC = Client(incus, cc_vm, "C", logger=log)
            log(":: client-prep — installing VPN tooling on all 3 clients (apt)")
            for c in (cA, cB, cC):
                log(f"-> client {c.label}: waiting for network, then apt install")
                ok, plog = c.prep()
                if not ok:
                    result.phase(PHASE_OPENVPN).add(
                        SubTest(f"client-{c.label}-prep", Status.ERROR,
                                "tooling install failed", plog[-1000:]))
                    log(f"-> client {c.label} prep [error]")
                else:
                    log(f"-> client {c.label} ready (ip {c.orig_public_ip or '?'})")
        else:
            log(":: client-prep — skipped (no protocol suite selected)")

        # Run a shell command on the SERVER VM (for server-side assertions the
        # panel API doesn't expose, e.g. reading the OpenVPN status file).
        def server_exec(cmd, timeout=30):
            return incus.exec(server_vm, cmd, timeout=timeout)

        # --- protocol suites (filtered by the --tests selection) ---
        for proto in [p for p in ("openvpn", "l2tp", "pptp", "openconnect", "sstp",
                                  "wg-c", "awg", "gre", "ssh",
                                  # Xray-native: same driver contract as the rest
                                  # (protocols.run resolves phase + inbound by name).
                                  "anytls", "tuic", "naive") if _sel(p)]:
            if _aborting():
                break
            log(f":: {proto} — connect variants + checks + peer reachability")
            try:
                protocols.run(proto, cA, cB, cC, sc, cfg, result, panel=panel,
                              server_exec=server_exec)
            except Exception as e:  # noqa: BLE001
                result.phase(protocols.PHASE[proto]).add(
                    SubTest(f"{proto}-driver", Status.ERROR,
                            str(e)[:200], traceback.format_exc()[-1500:]))
            finally:
                cA.disconnect_all()
                cB.disconnect_all()
                cC.disconnect_all()

        # --- ikev2: one full-suite phase per auth mode ------------------
        # eap-mschapv2 = the 2-account RADIUS path; psk/eap-tls = the single-account
        # rbridge-sweep path. Each is its own phase/column, selected via its own
        # ikev2-<mode> id or the "ikev2" alias.
        for mode in ("eap-mschapv2", "psk", "eap-tls"):
            ph_name = IKEV2_PHASE_BY_MODE[mode]
            if not _sel(ph_name):
                continue
            if _aborting():
                break
            log(f":: {ph_name} — connect + checks + User-Limit + accounting")
            try:
                protocols.run("ikev2", cA, cB, cC, sc, cfg, result, panel=panel,
                              server_exec=server_exec, mode=mode)
            except Exception as e:  # noqa: BLE001
                result.phase(ph_name).add(
                    SubTest(f"ikev2-{mode}-driver", Status.ERROR,
                            str(e)[:200], traceback.format_exc()[-1500:]))
            finally:
                cA.disconnect_all()
                cB.disconnect_all()
                cC.disconnect_all()

        # --- mtproto: one phase per connection mode --------------------
        # Unlike ikev2's auth modes (mutually exclusive per inbound), all three
        # MTProto modes are served by the SAME inbound at once: the client picks by
        # its secret's prefix. So these phases differ only in how the prober dials,
        # and they share one inbound rather than rebuilding it per mode.
        for mode in ("classic", "secure", "tls"):
            ph_name = MTPROTO_PHASE_BY_MODE[mode]
            if not _sel(ph_name):
                continue
            if _aborting():
                break
            log(f":: {ph_name}, handshake + relay to a real DC + accounting")
            try:
                protocols.run("mtproto", cA, cB, cC, sc, cfg, result, panel=panel,
                              server_exec=server_exec, mode=mode)
            except Exception as e:  # noqa: BLE001
                result.phase(ph_name).add(
                    SubTest(f"mtproto-{mode}-driver", Status.ERROR,
                            str(e)[:200], traceback.format_exc()[-1500:]))
            finally:
                cA.disconnect_all()
                cB.disconnect_all()
                cC.disconnect_all()

        # --- mtproto: editing an account's modes takes effect LIVE ------
        # Runs after the per-mode phases because it rewrites account A's modes; it
        # restores them at the end, but a failure mid-way must not decide another
        # phase's result.
        if _sel(PHASE_MTPROTO_TOGGLE) and not _aborting():
            log(f":: {PHASE_MTPROTO_TOGGLE}, mode toggles reach the running daemon")
            try:
                protocols.run("mtproto-toggle", cA, cB, cC, sc, cfg, result,
                              panel=panel, server_exec=server_exec)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_MTPROTO_TOGGLE).add(
                    SubTest("mtproto-toggle-driver", Status.ERROR,
                            str(e)[:200], traceback.format_exc()[-1500:]))
            finally:
                cA.disconnect_all()

        # --- mtproto: quota -> auto-disable -> the proxy stops serving ------
        # After the toggle phase (which needs account A serving every mode) because this
        # one deliberately disables account A. It restores the account in a finally, but
        # order it last among the account-A phases anyway so a mid-way failure cannot
        # decide another phase's result.
        if _sel(PHASE_MTPROTO_TERMINATION) and not _aborting():
            log(f":: {PHASE_MTPROTO_TERMINATION}, quota disables the account AND stops the relay")
            try:
                protocols.run("mtproto-termination", cA, cB, cC, sc, cfg, result,
                              panel=panel, server_exec=server_exec)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_MTPROTO_TERMINATION).add(
                    SubTest("mtproto-termination-driver", Status.ERROR,
                            str(e)[:200], traceback.format_exc()[-1500:]))
            finally:
                cA.disconnect_all()

        # --- mtproto: the ad tag / Xray-routing XOR -------------------------
        # Last of the mtproto phases: it restarts the core twice and turns the inbound's
        # Xray routing off and back on, so anything sharing this inbound must have run.
        if _sel(PHASE_MTPROTO_ADTAG) and not _aborting():
            log(f":: {PHASE_MTPROTO_ADTAG}, an ad tag forces middle-proxy and drops Xray routing")
            try:
                protocols.run("mtproto-adtag", cA, cB, cC, sc, cfg, result,
                              panel=panel, server_exec=server_exec)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_MTPROTO_ADTAG).add(
                    SubTest("mtproto-adtag-driver", Status.ERROR,
                            str(e)[:200], traceback.format_exc()[-1500:]))
            finally:
                cA.disconnect_all()

        # --- ssh-udp: UDP over the badvpn-udpgw path through the SSH relay ------
        # A dedicated phase (separate report column) that FORCES the UDP path the standard
        # ssh suite does not isolate: a +notcp DNS lookup through udpgw + UDP accounting.
        # Runs after the main ssh phase (which disables account A); the driver re-enables it.
        if _sel(PHASE_SSH_UDP) and not _aborting():
            log(f":: {PHASE_SSH_UDP}, UDP over udpgw through the SSH tunnel (functional + accounting)")
            try:
                protocols.run("ssh-udp", cA, cB, cC, sc, cfg, result,
                              panel=panel, server_exec=server_exec)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_SSH_UDP).add(
                    SubTest("ssh-udp-driver", Status.ERROR,
                            str(e)[:200], traceback.format_exc()[-1500:]))
            finally:
                cA.disconnect_all()

        # --- multi-inbound: ONE account on an inbound of every protocol ---------
        # Last of the protocol phases on purpose. It adds a third account to every
        # inbound the suite built (plus four Xray inbounds of its own), sets and clears
        # a multiplier, a quota and an IP cap on it, and disables/re-enables it — all
        # of which restart daemons. Running it before the per-protocol phases would
        # have those restarts land in the middle of somebody else's tunnel.
        if _sel(PHASE_MULTI) and not _aborting():
            log(f":: {PHASE_MULTI}, one account across every protocol "
                "(connectivity, accounting, multiplier, quota, ip limit, suspension)")
            try:
                multi_inbound.run(cA, cB, cC, sc, cfg, result, panel=panel,
                                  server_exec=server_exec, log=log)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_MULTI).add(
                    SubTest("multi-inbound-driver", Status.ERROR,
                            str(e)[:200], traceback.format_exc()[-1500:]))
            finally:
                for c in (cA, cB, cC):
                    if c is not None:
                        c.disconnect_all()

        # --- bulk client operations (pure panel API; once, after protocols so
        #     the bulk regen's daemon restarts can't race a live protocol test) ---
        if not _aborting() and _sel(PHASE_BULK):
            try:
                bulkops.run(panel, sc, cfg, result, log=log)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_BULK).add(
                    SubTest("bulk-ops-driver", Status.ERROR, str(e)[:200],
                            traceback.format_exc()[-1500:]))

        # --- db backup & restore (pure panel API). Before systemd since its
        #     importDB restarts daemons but leaves the transient unit running. ---
        if not _aborting() and _sel(PHASE_BACKUP):
            try:
                backup_test.run(panel, sc, cfg, result, log=log)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_BACKUP).add(
                    SubTest("backup-restore-driver", Status.ERROR, str(e)[:200],
                            traceback.format_exc()[-1500:]))

        # --- subscription: sub links / JSON / Clash + remaining-days/traffic stats
        #     for every protocol (pure panel + sub-server HTTP; enables the sub server
        #     and restarts the panel, so after backup and before warp). ---
        if not _aborting() and _sel(PHASE_SUBSCRIPTION):
            try:
                subscription_test.run(panel, sc, cfg, result, log=log)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_SUBSCRIPTION).add(
                    SubTest("subscription-driver", Status.ERROR, str(e)[:200],
                            traceback.format_exc()[-1500:]))

        # --- Cloudflare warp-cli SOCKS5 install (pure panel API, server-side
        #     apt/register/connect). Before systemd so it runs under the stable
        #     transient panel unit (the warp run is a child of the panel process). ---
        if not _aborting() and _sel(PHASE_WARP):
            try:
                warp_test.run(incus, server_vm, panel, cfg, result, log=log)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_WARP).add(
                    SubTest("warp-driver", Status.ERROR, str(e)[:200],
                            traceback.format_exc()[-1500:]))

        # --- `--random` CLI switch. Before systemd: it randomizes port + creds +
        #     web path, verifies the panel moves, then restores the defaults so the
        #     shared panel object (and the systemd phase) keep working. ---
        if not _aborting() and _sel(PHASE_RANDOM):
            try:
                random_test.run(incus, server_vm, panel, cfg, result, log=log)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_RANDOM).add(
                    SubTest("random-driver", Status.ERROR, str(e)[:200],
                            traceback.format_exc()[-1500:]))

        # --- `--systemd` CLI switch. Swaps the panel's supervisor (transient
        #     unit -> installed `vpn-ui` unit) on the same port. Before uninstall
        #     so the teardown has an installed unit to remove. ---
        if not _aborting() and _sel(PHASE_SYSTEMD):
            try:
                systemd_test.run(incus, server_vm, panel, cfg, result, log=log)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_SYSTEMD).add(
                    SubTest("systemd-driver", Status.ERROR, str(e)[:200],
                            traceback.format_exc()[-1500:]))

        # --- `--uninstall` CLI switch. LAST + destructive: it tears everything
        #     down (unit, daemons, nft table, /etc configs, bundles, policy
        #     routing, bin/, DB, binary) and asserts the host is left clean. ---
        if not _aborting() and _sel(PHASE_UNINSTALL):
            try:
                uninstall_test.run(incus, server_vm, panel, cfg, result, log=log)
            except Exception as e:  # noqa: BLE001
                result.phase(PHASE_UNINSTALL).add(
                    SubTest("uninstall-driver", Status.ERROR, str(e)[:200],
                            traceback.format_exc()[-1500:]))

        # Populate report columns for optional phases the --tests selection
        # skipped. core-init always runs and server-setup is handled at its own
        # step (real subtests when needed, else its own "not needed" SKIP), so
        # both are excluded here. Guarded on empty so a phase that actually ran
        # keeps its real subtests; complements _skip_remaining (which only fires
        # on a prereq failure / abort).
        for name in ALL_PHASES:
            if name in (PHASE_CORE, PHASE_SETUP) or _sel(name):
                continue
            ph = result.phase(name)
            if not ph.subtests:
                ph.add(SubTest("phase", Status.SKIP, "not selected (--tests)"))

    except Exception as e:  # noqa: BLE001 (IncusError included)
        if abort.is_set():
            # unwound by a Ctrl+C mid-op (e.g. a wait loop raised) — not an error
            _skip_remaining(result)
            log("-> aborted by user [skip] — tearing down")
        else:
            result.phase(PHASE_CORE).add(
                SubTest("infra", Status.ERROR, str(e)[:300],
                        traceback.format_exc()[-1500:]))
            keep = cfg.get("keep_failed_vms", False)
            log(f"-> job error [error]: {e}")
    finally:
        result.finished_at = _now()
        failed = result.status in (Status.FAIL, Status.ERROR)
        # keep on ANY failure when configured (not just infra exceptions), but
        # NEVER keep on a user abort — Ctrl+C means "clean everything up".
        keep = (keep or (cfg.get("keep_failed_vms", False) and failed)) \
            and not abort.is_set()
        if keep and failed:
            log(f"-> keeping VMs for post-mortem [warn]: {', '.join(created)}")
        else:
            for vm in created:
                incus.delete(vm)
            if net:
                incus.delete_network(net)
            log("-> VMs + bridge torn down")
        log(f":: {distro} — done [{result.status.value}]")
        console.finish_job(distro)
    return result


def _skip_remaining(result: JobResult):
    for name in ALL_PHASES:
        if name == PHASE_CORE:
            continue
        ph = result.phase(name)
        if not ph.subtests:
            ph.add(SubTest("phase", Status.SKIP, "prerequisite (core/setup) failed"))


def main(argv=None):
    ap = argparse.ArgumentParser(description="vpn-ui incus test unit")
    ap.add_argument("-c", "--config", default=os.path.join(
        os.path.dirname(__file__), "..", "config.toml"))
    ap.add_argument("--only", default="", help="comma-separated distro names to run")
    ap.add_argument("--concurrency", type=int, default=0,
                    help="override config concurrency (>0)")
    ap.add_argument("--tests", default="",
                    help="comma-separated tests to run (default all); see run.sh --help")
    args = ap.parse_args(argv)

    with open(args.config, "rb") as f:
        cfg = tomllib.load(f)

    if args.concurrency > 0:
        cfg["concurrency"] = args.concurrency

    # --- resolve --tests into the set of selected phase ids (cfg["_selected"]).
    #     Valid ids = the runtime phases + "ikev2" (alias that expands to the three
    #     ikev2-<mode> phases) + the host-only pseudo-id "export-js" (run.sh runs that,
    #     not this process) + the literal "all". An empty value or "all" selects every
    #     phase; substrate phases always run. A bare "ikev2" in _selected is a MARKER
    #     (not a report column, not in ALL_PHASES) kept so the l2tp/charon port
    #     arbitration and need_clients still see ikev2 as active. ---
    valid_ids = ALL_PHASES + ["ikev2", "mtproto", "export-js", "all"]
    tests = [t.strip() for t in args.tests.split(",") if t.strip()]
    unknown = [t for t in tests if t not in valid_ids]
    if unknown:
        print(f"unknown --tests id(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"valid ids: {', '.join(valid_ids)}", file=sys.stderr)
        return 2
    if not tests or "all" in tests:
        selected = set(ALL_PHASES)
    else:
        selected = {t for t in tests if t in ALL_PHASES}
        if "ikev2" in tests:                      # alias -> every ikev2 auth-mode phase
            selected.update(IKEV2_MODE_PHASES)
        if "mtproto" in tests:                    # alias -> every mtproto phase
            selected.update(MTPROTO_MODE_PHASES)
            selected.update({PHASE_MTPROTO_TOGGLE, PHASE_MTPROTO_TERMINATION,
                             PHASE_MTPROTO_ADTAG})
        if "ssh" in tests:                        # ssh -> its main phase + the udp phase
            selected.add(PHASE_SSH_UDP)
    if PHASE_MULTI in selected:
        # multi-inbound puts the account on the ikev2 inbound and dials it, so the
        # marker has to be set for it too: it is what makes server_setup build l2tp
        # RAW-only, leaving 500/4500 to charon. Without it both IKE daemons want
        # those ports and whichever loses is dead for the whole run.
        selected.add("ikev2")
    if selected & set(IKEV2_MODE_PHASES):         # marker: any ikev2 mode active
        selected.add("ikev2")
    if selected & (set(MTPROTO_MODE_PHASES) | {PHASE_MTPROTO_TOGGLE,
                                               PHASE_MTPROTO_TERMINATION,
                                               PHASE_MTPROTO_ADTAG}):
        selected.add("mtproto")                   # marker: any mtproto phase active
    cfg["_selected"] = selected

    # Resolve a relative binary path against the config's dir (test_unit/), so the
    # default "test_subject/vpn-ui" means the binary in the test_subject/ folder
    # (its sibling bin/ dir carries the xray core + geo files, pushed together).
    cfg_dir = os.path.dirname(os.path.abspath(args.config))
    if not os.path.isabs(cfg["binary"]):
        cfg["binary"] = os.path.normpath(os.path.join(cfg_dir, cfg["binary"]))
    if not os.path.isfile(cfg["binary"]):
        print(f"FATAL: binary not found: {cfg['binary']}", file=sys.stderr)
        return 2

    servers = [s for s in cfg["servers"] if s.get("enabled", True)]
    if args.only:
        want = {x.strip() for x in args.only.split(",")}
        servers = [s for s in servers if s["name"] in want]
    if not servers:
        print("no servers selected", file=sys.stderr)
        return 2

    run_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    results_base = os.environ.get(
        "TEST_UNIT_RESULTS",
        os.path.join(os.path.dirname(__file__), "..", "results"))
    run_dir = os.path.join(results_base, run_id)
    os.makedirs(run_dir, exist_ok=True)

    # ---- pacman-style run banner ----
    bar = style.bold_blue("::")
    print(f"\n{style.bold_blue('╭─')} {style.bold_white('vpn-ui test unit')}")
    print(f"{bar} distros      {style.cyan(', '.join(s['name'] for s in servers))}")
    print(f"{bar} concurrency  {style.bold(str(cfg['concurrency']))} "
          f"({cfg['concurrency']*3} VMs max at once)")
    print(f"{bar} binary       {cfg['binary']}")
    print(f"{bar} routing      {style.cyan('source-IP')} "
          "(A->freedom / B->blackhole, built-in outbounds)")
    print(f"{bar} results      {run_dir}\n")

    console = Console(len(servers))

    def _sweep():
        """Force-remove every job's VMs + bridge (+ firewall entry) by
        deterministic name. Safety net — jobs also tear down their own in
        run_job's finally; preclean is idempotent so double-removal is harmless."""
        for i in range(len(servers)):
            try:
                Incus(f"vpnt{i}").preclean(i)
            except Exception:  # noqa: BLE001
                pass

    # Ctrl+C: set the cooperative abort flag so in-flight jobs unwind and tear
    # down their VMs. A second Ctrl+C force-sweeps everything and exits now.
    # The handler must not touch the console lock (it runs on the main thread,
    # which may already hold it) — write straight to stderr instead.
    _sigint_n = [0]

    def _on_sigint(signum, frame):
        _sigint_n[0] += 1
        abort.set()
        if _sigint_n[0] == 1:
            note = ("\n:: interrupt — stopping run; jobs are tearing down their "
                    "VMs (Ctrl+C again to force-clean now)\n")
        else:
            note = "\n:: forced abort — removing all test VMs + bridges...\n"
        try:
            sys.stderr.write(note)
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            pass
        if _sigint_n[0] >= 2:
            _sweep()
            os._exit(130)

    signal.signal(signal.SIGINT, _on_sigint)

    results = []
    with cf.ThreadPoolExecutor(max_workers=cfg["concurrency"]) as ex:
        futs = {ex.submit(run_job, spec, i, cfg, run_dir, console): spec
                for i, spec in enumerate(servers)}
        for fut in cf.as_completed(futs):
            spec = futs[fut]
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001
                res = JobResult(distro=spec["name"], image=spec["image"],
                                notes=f"job crashed: {e}", finished_at=_now())
            results.append(res)
    console.close()

    if abort.is_set():
        # safety-net sweep: remove anything a killed job left behind
        sys.stderr.write(":: aborted — sweeping any leftover VMs + bridges...\n")
        sys.stderr.flush()
        _sweep()

    # stable order matching config
    order = {s["name"]: i for i, s in enumerate(servers)}
    results.sort(key=lambda r: order.get(r.distro, 999))

    meta = {"run_id": run_id,
            "binary": cfg["binary"], "concurrency": cfg["concurrency"]}
    json_path, html_path = write_reports(results, run_dir, meta)

    # ---- pacman-style summary ----
    print(f"\n{style.bold_blue('::')} {style.bold_white('Results')}")
    for r in results:
        chip = style.status_chip(r.status.value)
        phases = "  ".join(
            f"{p.name}:{style.status_chip(p.status.value)}" for p in r.phases
        ) if r.phases else style.dim(r.notes or "not run")
        print(f"  {chip}  {style.distro_tag(r.distro)}  {phases}")
    passed = sum(1 for r in results if r.status == Status.PASS)
    tot = len(results)
    verdict = style.green(f"{passed}/{tot} distros fully passed") if passed == tot \
        else style.yellow(f"{passed}/{tot} distros fully passed")
    print(f"\n{style.bold_blue('::')} {verdict}")
    print(f"{style.bold_blue('::')} JSON  {json_path}")
    print(f"{style.bold_blue('::')} HTML  {html_path}\n")
    if abort.is_set():
        print(f"{style.bold_blue('::')} {style.yellow('run aborted by user (Ctrl+C)')}\n")
        return 130
    return 0 if passed == tot else 1


if __name__ == "__main__":
    sys.exit(main())
