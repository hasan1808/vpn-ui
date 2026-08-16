package service

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"

	"golang.org/x/crypto/ssh"
)

// sshMgr is the package-level singleton that owns all live SSH state: the bound
// listeners, the per-account session table, and the per-account byte counters. It is
// a singleton (not SshService fields) because the traffic job drives a zero-value
// SshService copy, so the state must be shared package-wide, the same reason
// mtprotoCounters and procMgr are package globals.
var sshMgr = newSshManager()

type sshManager struct {
	mu       sync.Mutex
	servers  map[int]*sshServer                  // inboundId -> bound listener
	sessions map[string]map[*sshSession]struct{} // email -> live sessions
	counters map[string]*sshAcct                 // email -> byte counters
}

func newSshManager() *sshManager {
	return &sshManager{
		servers:  map[int]*sshServer{},
		sessions: map[string]map[*sshSession]struct{}{},
		counters: map[string]*sshAcct{},
	}
}

// sshAcct holds an account's byte counters. The atomics are incremented lock-free on
// every io.Copy chunk and swapped to zero by CollectTraffic once per tick.
type sshAcct struct {
	up   atomic.Int64
	down atomic.Int64
}

// sshServer is one bound SSH listener for one inbound.
type sshServer struct {
	inboundId int
	port      int
	hostKey   string // the settings.hostKey this server was built with (restart on change)
	socksPort int
	ln        net.Listener
	cfg       *ssh.ServerConfig
	svc       *SshService
	closing   atomic.Bool
}

// sshSession is one live authenticated SSH connection.
type sshSession struct {
	inboundId int
	email     string
	srcIP     string
	since     time.Time
	conn      *ssh.ServerConn
	acct      *sshAcct
}

// reconcile binds a listener for each enabled inbound and closes any that are no
// longer wanted or whose port/host key changed. Runs under the manager lock only for
// the map bookkeeping; the actual Listen happens outside it.
func (m *sshManager) reconcile(svc *SshService, inbounds []*model.Inbound) {
	desired := map[int]*model.Inbound{}
	for _, in := range inbounds {
		if in.Enable {
			desired[in.Id] = in
		}
	}

	// Stop servers no longer wanted, or whose port/host key changed (a rebind).
	m.mu.Lock()
	var toStop []*sshServer
	for id, srv := range m.servers {
		in, ok := desired[id]
		if !ok {
			toStop = append(toStop, srv)
			continue
		}
		settings, err := svc.parseSettings(in)
		if err != nil {
			continue
		}
		if in.Port != srv.port || settings.HostKey != srv.hostKey {
			toStop = append(toStop, srv)
		}
	}
	for _, srv := range toStop {
		delete(m.servers, srv.inboundId)
	}
	m.mu.Unlock()
	for _, srv := range toStop {
		srv.close()
	}

	// Start servers that should be running but are not.
	for id, in := range desired {
		m.mu.Lock()
		_, running := m.servers[id]
		m.mu.Unlock()
		if running {
			continue
		}
		srv, err := m.startServer(svc, in)
		if err != nil {
			logger.Warning("SSH: failed to bind inbound", id, "port", in.Port, ":", err)
			continue
		}
		m.mu.Lock()
		m.servers[id] = srv
		m.mu.Unlock()
	}
}

// startServer builds the ssh.ServerConfig and binds the listener for one inbound.
func (m *sshManager) startServer(svc *SshService, inbound *model.Inbound) (*sshServer, error) {
	settings, err := svc.parseSettings(inbound)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey([]byte(settings.HostKey))
	if err != nil {
		return nil, fmt.Errorf("host key parse: %w", err)
	}

	srv := &sshServer{
		inboundId: inbound.Id,
		port:      inbound.Port,
		hostKey:   settings.HostKey,
		socksPort: svc.GetSocksPort(inbound),
		svc:       svc,
	}

	cfg := &ssh.ServerConfig{
		MaxAuthTries: 6,
		// Password only for v1. The callback reads the DB live (lookupAccount), so a
		// client add/edit/disable takes effect with no restart.
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			acct, ok := svc.lookupAccount(inbound.Id, conn.User(), string(password))
			if !ok {
				return nil, fmt.Errorf("ssh: authentication failed")
			}
			// The routing/accounting identity travels in Permissions, read back from
			// ServerConn.Permissions after the handshake (never trust the last password
			// seen). Email is the account identity Xray routes by.
			return &ssh.Permissions{Extensions: map[string]string{"email": acct.Email}}, nil
		},
	}
	cfg.AddHostKey(signer)
	srv.cfg = cfg

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", inbound.Port))
	if err != nil {
		return nil, err
	}
	srv.ln = ln
	go m.acceptLoop(srv)
	logger.Info("SSH: listening on port", inbound.Port, "for inbound", inbound.Id)
	return srv, nil
}

func (m *sshManager) acceptLoop(srv *sshServer) {
	for {
		conn, err := srv.ln.Accept()
		if err != nil {
			if srv.closing.Load() {
				return
			}
			// A non-temporary Accept error means the listener is gone.
			return
		}
		go m.handleConn(srv, conn)
	}
}

// handleConn runs the SSH handshake, enforces the User Limit, then serves the
// permitted channels. It is the whole per-connection lifecycle.
func (m *sshManager) handleConn(srv *sshServer, nConn net.Conn) {
	// TCP keepalive so a peer that dies without a FIN is detected and its session (and
	// its User-Limit slot) is released rather than lingering until the OS TCP timeout.
	if tcp, ok := nConn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	// Bound the handshake so a stalled peer cannot hold the goroutine forever.
	_ = nConn.SetDeadline(time.Now().Add(20 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, srv.cfg)
	if err != nil {
		nConn.Close()
		return
	}
	_ = nConn.SetDeadline(time.Time{})

	email := ""
	if sshConn.Permissions != nil {
		email = sshConn.Permissions.Extensions["email"]
	}
	if email == "" {
		sshConn.Close()
		return
	}
	srcIP := hostOnly(nConn.RemoteAddr().String())

	sess := &sshSession{
		inboundId: srv.inboundId,
		email:     email,
		srcIP:     srcIP,
		since:     time.Now(),
		conn:      sshConn,
		acct:      m.acctFor(email),
	}

	// User Limit: reject the (K+1)th distinct device, or admit and evict the oldest.
	k, strategy := srv.svc.inboundLimit(srv.inboundId)
	evicted, ok := m.admit(sess, k, strategy)
	if !ok {
		sshConn.Close()
		return
	}
	for _, e := range evicted {
		e.conn.Close()
	}

	// Reject every global request (WantReply -> false). This denies reverse
	// forwarding (tcpip-forward) and everything else; only direct-tcpip channels below
	// are served.
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.Prohibited, "only direct-tcpip is permitted")
			continue
		}
		go m.handleDirectTCPIP(srv, sess, nc)
	}

	m.removeSession(sess)
	sshConn.Close()
}

// directTCPIP is the parsed payload of a direct-tcpip channel-open (RFC 4254 7.2).
type directTCPIP struct {
	destHost string
	destPort uint32
	origHost string
	origPort uint32
}

func parseDirectTCPIP(data []byte) (*directTCPIP, bool) {
	d := &directTCPIP{}
	var ok bool
	if d.destHost, data, ok = sshReadString(data); !ok {
		return nil, false
	}
	if d.destPort, data, ok = sshReadUint32(data); !ok {
		return nil, false
	}
	if d.origHost, data, ok = sshReadString(data); !ok {
		return nil, false
	}
	if d.origPort, _, ok = sshReadUint32(data); !ok {
		return nil, false
	}
	return d, true
}

func sshReadString(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", b, false
	}
	n := binary.BigEndian.Uint32(b)
	b = b[4:]
	if uint32(len(b)) < n {
		return "", b, false
	}
	return string(b[:n]), b[n:], true
}

func sshReadUint32(b []byte) (uint32, []byte, bool) {
	if len(b) < 4 {
		return 0, b, false
	}
	return binary.BigEndian.Uint32(b), b[4:], true
}

// handleDirectTCPIP serves one forwarded connection. A channel to the udpgw port is
// the UDP bridge; anything else is a plain TCP CONNECT dialed through Xray's socks
// inbound with the account email as the socks username (so Xray routes it per client).
func (m *sshManager) handleDirectTCPIP(srv *sshServer, sess *sshSession, nc ssh.NewChannel) {
	d, ok := parseDirectTCPIP(nc.ExtraData())
	if !ok {
		nc.Reject(ssh.ConnectionFailed, "bad direct-tcpip request")
		return
	}

	// UDP path: the client points its udpgw at the loopback udpgw port through the
	// SOCKS proxy, so a channel to that port carries the udpgw protocol, not TCP.
	if int(d.destPort) == sshUdpgwPort {
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go ssh.DiscardRequests(chReqs)
		m.handleUdpgw(srv, sess, ch)
		return
	}

	upstream, err := dialSocksConnect(srv.socksPort, sess.email, d.destHost, int(d.destPort))
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, "upstream dial failed")
		return
	}
	ch, chReqs, err := nc.Accept()
	if err != nil {
		upstream.Close()
		return
	}
	go ssh.DiscardRequests(chReqs)

	// client -> upstream is the account's UPLOAD; upstream -> client its DOWNLOAD.
	done := make(chan struct{}, 2)
	go func() {
		copyCount(upstream, ch, &sess.acct.up)
		if hc, ok := upstream.(interface{ CloseWrite() error }); ok {
			hc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		copyCount(ch, upstream, &sess.acct.down)
		ch.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
	ch.Close()
	upstream.Close()
}

// copyCount copies src into dst, adding the number of bytes moved to ctr as they flow.
func copyCount(dst io.Writer, src io.Reader, ctr *atomic.Int64) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			ctr.Add(int64(n))
		}
		if rerr != nil {
			return
		}
	}
}

// admit applies the User Limit for one account. A device is a distinct client source
// IP. A new session from a known device is always allowed. A new device is allowed
// while under K; at K, "reject" refuses it and "accept" admits it and evicts the
// oldest device (all its sessions). k <= 0 means unlimited.
func (m *sshManager) admit(sess *sshSession, k int, strategy string) (evicted []*sshSession, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	set := m.sessions[sess.email]
	if set == nil {
		set = map[*sshSession]struct{}{}
		m.sessions[sess.email] = set
	}

	ipFirst := map[string]time.Time{}
	for s := range set {
		if t, seen := ipFirst[s.srcIP]; !seen || s.since.Before(t) {
			ipFirst[s.srcIP] = s.since
		}
	}
	_, sameDevice := ipFirst[sess.srcIP]
	if k <= 0 || sameDevice || len(ipFirst) < k {
		set[sess] = struct{}{}
		return nil, true
	}
	if strategy != "accept" {
		return nil, false
	}

	// accept: evict the oldest device (all sessions sharing its source IP).
	oldestIP := ""
	var oldestT time.Time
	for ip, t := range ipFirst {
		if oldestIP == "" || t.Before(oldestT) {
			oldestIP, oldestT = ip, t
		}
	}
	for s := range set {
		if s.srcIP == oldestIP {
			evicted = append(evicted, s)
			delete(set, s)
		}
	}
	set[sess] = struct{}{}
	return evicted, true
}

func (m *sshManager) removeSession(sess *sshSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if set := m.sessions[sess.email]; set != nil {
		delete(set, sess)
		if len(set) == 0 {
			delete(m.sessions, sess.email)
		}
	}
}

func (m *sshManager) acctFor(email string) *sshAcct {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.counters[email]
	if a == nil {
		a = &sshAcct{}
		m.counters[email] = a
	}
	return a
}

// collect returns per-account usage since the last call (atomic read-and-reset) and
// prunes counters for accounts with no live sessions so the map cannot grow forever.
func (m *sshManager) collect() []*xray.ClientTraffic {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*xray.ClientTraffic
	for email, a := range m.counters {
		up := a.up.Swap(0)
		down := a.down.Swap(0)
		if up == 0 && down == 0 {
			if _, live := m.sessions[email]; !live {
				delete(m.counters, email)
			}
			continue
		}
		out = append(out, &xray.ClientTraffic{Email: email, Up: up, Down: down})
	}
	return out
}

// enforce closes the sessions of disabled accounts and trims every account to its
// User Limit K (oldest devices out). Called each traffic tick, so a disable or a
// lowered K takes effect within a tick without a reconnect.
func (m *sshManager) enforce(svc *SshService, disabled map[string]bool) {
	var toClose []*sshSession
	m.mu.Lock()
	for email, set := range m.sessions {
		if len(set) == 0 {
			continue
		}
		if disabled[email] {
			for s := range set {
				toClose = append(toClose, s)
			}
			continue
		}
		inboundId := 0
		ipFirst := map[string]time.Time{}
		for s := range set {
			inboundId = s.inboundId
			if t, seen := ipFirst[s.srcIP]; !seen || s.since.Before(t) {
				ipFirst[s.srcIP] = s.since
			}
		}
		k, _ := svc.inboundLimit(inboundId)
		if k <= 0 || len(ipFirst) <= k {
			continue
		}
		type ipt struct {
			ip string
			t  time.Time
		}
		arr := make([]ipt, 0, len(ipFirst))
		for ip, t := range ipFirst {
			arr = append(arr, ipt{ip, t})
		}
		sort.Slice(arr, func(i, j int) bool { return arr[i].t.Before(arr[j].t) })
		evictIP := map[string]bool{}
		for _, e := range arr[:len(arr)-k] {
			evictIP[e.ip] = true
		}
		for s := range set {
			if evictIP[s.srcIP] {
				toClose = append(toClose, s)
			}
		}
	}
	m.mu.Unlock()
	for _, s := range toClose {
		s.conn.Close()
	}
}

func (m *sshManager) anyRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.servers) > 0
}

func (m *sshManager) stopAll() {
	m.mu.Lock()
	servers := make([]*sshServer, 0, len(m.servers))
	for _, srv := range m.servers {
		servers = append(servers, srv)
	}
	m.servers = map[int]*sshServer{}
	m.mu.Unlock()
	for _, srv := range servers {
		srv.close()
	}
}

func (srv *sshServer) close() {
	srv.closing.Store(true)
	if srv.ln != nil {
		srv.ln.Close()
	}
}

// hostOnly strips the port from a host:port, returning just the host.
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
