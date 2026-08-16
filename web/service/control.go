package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/logger"
)

// The panel's control socket: a root-only unix socket that lets a separate CLI
// process (`vpn-ui-amd64 ctl <cmd>`) drive the LIVE panel's Xray and daemons.
//
// It exists because Xray and the VPN daemons are CHILD PROCESSES of the running
// panel, tracked only by in-process state: XrayService's package-level `p`
// (IsXrayRunning is `p != nil && p.IsRunning()`, xray.go) and the procMgr
// singleton with its in-memory log ring (procmgr.go). A second process starts with
// p == nil and an empty procMgr, so a CLI that called those services directly
// would be wrong in both directions, and dangerously so:
//
//   - StopXray() returns "xray is not running" while Xray is very much running.
//   - RestartXray() does not stop anything (its guard sees no process) and spawns a
//     SECOND Xray that collides with the panel's on the API port (62790) and on
//     every inbound port. That is the same orphan/collision failure ReapOrphanXray
//     exists to clean up after.
//
// So the CLI must ask the live panel to act rather than act itself, and the
// handlers below call the very same service methods the web controllers call: one
// code path, not two.
//
// Why not a signal: SIGUSR1 already means restart-xray (main.go), but signals carry
// neither a command set nor a reply, and cores.status has to return data.

const (
	controlSocketName = "vpn-ui.sock"
	// How long to wait for the stale-socket probe. Only a live panel's accept loop
	// answers, and it is local, so this is generous already.
	controlDialTimeout = 500 * time.Millisecond
	// Idle time allowed between requests on one connection, and the budget for
	// writing a reply. Neither covers command EXECUTION: cores.restart-all restarts
	// eleven cores and takes tens of seconds, so the deadlines are (re)armed around
	// the read and the write only.
	controlIdleTimeout  = 30 * time.Second
	controlWriteTimeout = 10 * time.Second
	// Ceiling on what one CONNECTION may send, so a rogue client cannot make the panel
	// buffer unbounded input. A command is a single short JSON line and the CLI sends
	// exactly one per connection, so this is orders of magnitude of headroom.
	controlMaxRequest = 4 << 10
)

// ControlCommands lists every command the socket accepts, in the order the CLI
// documents them. Exported so `vpn-ui-amd64 ctl` prints the set without keeping a
// second copy that can drift from the switch in handleControlCommand.
var ControlCommands = []string{
	"ping",
	"xray.start",
	"xray.stop",
	"xray.restart",
	"cores.restart-all",
	"cores.status",
}

// ControlRequest is one line of the socket protocol: a JSON object per line.
type ControlRequest struct {
	Cmd string `json:"cmd"`
}

// ControlResponse is the single JSON line sent back for each request. Error is
// empty exactly when OK is true, so a client can branch on either.
type ControlResponse struct {
	OK    bool         `json:"ok"`
	Cmd   string       `json:"cmd,omitempty"`
	Msg   string       `json:"msg,omitempty"`
	Error string       `json:"error,omitempty"`
	Cores []CoreStatus `json:"cores,omitempty"`
}

// ControlSocketPath returns the control socket's path: vpn-ui.sock next to the
// panel binary.
//
// Deliberately derived from os.Executable() rather than config.GetDBFolderPath():
// the panel calls godotenv.Load() at startup and the CLI does not, so a
// VPNUI_DB_FOLDER in a .env would move the panel's socket while the CLI kept
// dialing a path that never existed. Both are the SAME binary, so its directory is
// the one location they can never disagree on.
func ControlSocketPath() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return filepath.Join(config.GetDBFolderPath(), controlSocketName)
	}
	return filepath.Join(filepath.Dir(exe), controlSocketName)
}

// StartControlSocket binds the control socket and serves it in a background
// goroutine. Callers must treat a failure as non-fatal and keep going: the socket
// only serves the CLI, and a panel carrying VPN traffic without it is far better
// than a panel that refused to start over it.
func StartControlSocket() error {
	path := ControlSocketPath()

	// A socket file left behind by a panel that died without cleanup makes Listen
	// fail with EADDRINUSE, so the stale entry would block every later start. Unlink
	// it, but only after proving nothing answers on it, because a successful dial
	// means a live panel owns it and stealing its socket would be worse than not
	// having one (same rule as ReapOrphanXray: never touch a live peer).
	if conn, derr := net.DialTimeout("unix", path, controlDialTimeout); derr == nil {
		_ = conn.Close()
		return fmt.Errorf("another vpn-ui panel is already serving %s", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale control socket %s: %w", path, err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod control socket %s: %w", path, err)
	}
	logger.Info("control socket listening on", path)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Accept only fails permanently here (the listener is never closed while
				// the panel runs), so log and stop rather than spin on the same error.
				logger.Warning("control socket accept failed, stopping:", err)
				return
			}
			go serveControlConn(conn)
		}
	}()
	return nil
}

// serveControlConn reads request lines until the peer hangs up, answering each.
func serveControlConn(conn net.Conn) {
	defer conn.Close()

	if !controlPeerIsRoot(conn) {
		logger.Warning("control socket: rejected a non-root peer")
		_ = conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
		_ = writeControlResponse(conn, ControlResponse{Error: "permission denied: the control socket is root-only"})
		return
	}

	r := bufio.NewReader(io.LimitReader(conn, controlMaxRequest))
	for {
		// Armed per request so a client that connects and says nothing cannot pin this
		// goroutine forever, and re-armed after each reply for the next one.
		_ = conn.SetReadDeadline(time.Now().Add(controlIdleTimeout))
		line, err := r.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			if err != nil {
				return // EOF / timeout / hang-up: nothing left to answer
			}
			continue
		}

		var req ControlRequest
		var resp ControlResponse
		if jerr := json.Unmarshal([]byte(line), &req); jerr != nil {
			resp = ControlResponse{Error: fmt.Sprintf("malformed request: %v", jerr)}
		} else {
			resp = handleControlCommand(strings.TrimSpace(req.Cmd))
		}

		_ = conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
		if werr := writeControlResponse(conn, resp); werr != nil {
			logger.Debug("control socket write failed:", werr)
			return
		}
		if err != nil {
			return
		}
	}
}

// handleControlCommand executes one command against the LIVE panel's own services:
// the same calls the web controllers make, so the CLI and the dashboard can never
// diverge in behaviour.
func handleControlCommand(cmd string) ControlResponse {
	var xrayService XrayService
	var coreService CoreService

	switch cmd {
	case "ping":
		return ControlResponse{OK: true, Cmd: cmd, Msg: fmt.Sprintf("vpn-ui %s panel is running (pid %d)", config.GetVersion(), os.Getpid())}

	case "xray.start":
		// Xray has no separate Start: "stopped" means p == nil / !IsRunning, and
		// RestartXray(true) is exactly what the panel itself calls to bring it back
		// (it also clears isManuallyStopped, without which the health job would
		// deliberately leave Xray down).
		if xrayService.IsXrayRunning() {
			return ControlResponse{OK: true, Cmd: cmd, Msg: "xray is already running"}
		}
		if err := xrayService.RestartXray(true); err != nil {
			return ControlResponse{Cmd: cmd, Error: err.Error()}
		}
		return ControlResponse{OK: true, Cmd: cmd, Msg: "xray started"}

	case "xray.stop":
		if err := xrayService.StopXray(); err != nil {
			return ControlResponse{Cmd: cmd, Error: err.Error()}
		}
		return ControlResponse{OK: true, Cmd: cmd, Msg: "xray stopped"}

	case "xray.restart":
		if err := xrayService.RestartXray(true); err != nil {
			return ControlResponse{Cmd: cmd, Error: err.Error()}
		}
		return ControlResponse{OK: true, Cmd: cmd, Msg: "xray restarted"}

	case "cores.restart-all":
		// RestartAll aggregates per-core errors instead of stopping at the first, so a
		// partial failure still restarted the rest. Report it as a failure with the
		// detail, never as a silent success.
		if err := coreService.RestartAll(); err != nil {
			return ControlResponse{Cmd: cmd, Error: err.Error()}
		}
		return ControlResponse{OK: true, Cmd: cmd, Msg: "all cores restarted"}

	case "cores.status":
		return ControlResponse{OK: true, Cmd: cmd, Cores: coreService.GetCoresStatus()}

	case "":
		return ControlResponse{Error: "empty command (known: " + strings.Join(ControlCommands, ", ") + ")"}
	}
	return ControlResponse{Cmd: cmd, Error: fmt.Sprintf("unknown command %q (known: %s)", cmd, strings.Join(ControlCommands, ", "))}
}

// writeControlResponse emits one JSON line. json.Encoder appends the newline that
// terminates the record.
func writeControlResponse(conn net.Conn, resp ControlResponse) error {
	return json.NewEncoder(conn).Encode(resp)
}

// controlPeerIsRoot reports whether the connected peer runs as root.
//
// The socket is already mode 0600, but the mode can only be applied AFTER bind, so
// an unprivileged process could in principle connect inside that window. Every
// command here restarts daemons, so "root only" has to be a guarantee rather than
// a file permission we hope nobody beat us to: SO_PEERCRED is recorded by the
// kernel at connect() time and cannot be raced or spoofed.
func controlPeerIsRoot(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return false
	}
	return cred.Uid == 0
}
