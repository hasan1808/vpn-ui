package service

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hasan1808/pro-ui/logger"

	"github.com/goccy/go-json"
	"golang.org/x/crypto/ssh"
)

// SshOutboundService manages operator-configured SSH egress tunnels. Each tunnel is an
// in-process ssh.Client plus a local SOCKS5 server on 127.0.0.1:SocksPort ("ssh -D"
// in-process); a synthesized native `socks` outbound (tag == cfg.Tag) in the Xray
// template routes egress into it. Reverse and routing target it purely by that tag, so
// no special-casing is needed - it is just a tagged socks outbound (the shipped WARP
// pattern). Config lives in the `sshOutbounds` setting; live state is the package-level
// sshOutMgr singleton (the boot path drives a zero-value service copy).
type SshOutboundService struct{}

// SshOutboundConfig is one tunnel. Secrets (Password/PrivateKey/Passphrase) are stored
// in the `sshOutbounds` setting (PermXraySettings-gated) and never echoed back by List.
type SshOutboundConfig struct {
	Tag        string `json:"tag" form:"tag"`
	Remark     string `json:"remark" form:"remark"`
	Address    string `json:"address" form:"address"`
	Port       int    `json:"port" form:"port"`
	Username   string `json:"username" form:"username"`
	AuthType   string `json:"authType" form:"authType"` // "password" | "privateKey"
	Password   string `json:"password" form:"password"`
	PrivateKey string `json:"privateKey" form:"privateKey"`
	Passphrase string `json:"passphrase" form:"passphrase"`
	KnownHost  string `json:"knownHost" form:"knownHost"` // SHA256/MD5 fingerprint pin; "" = TOFU
	SocksPort  int    `json:"socksPort" form:"socksPort"`

	// Via is the tag of the outbound that carries this tunnel: the panel's own TCP
	// connection to Address:Port travels through that carrier, so the SSH server sees
	// the carrier's exit address and never this host's. Empty is the ordinary case, a
	// tunnel dialled straight out of the host's WAN.
	//
	// Nothing in the dial path above reads it, and that is deliberate rather than an
	// omission. Carrying is destination-based policy routing into the carrier's netdev
	// (vpnoutvia.go): the rule is `to <ssh server> lookup <carrier table>`, so the
	// kernel redirects the ssh.Dial in supervise() with no change to the dial code.
	// The one L4-agnostic mechanism serves every tunnel kind, TCP here included.
	//
	// POPULATED FROM THE OUTBOUND ROW'S sockopt.dialerProxy, exactly as a VPN tunnel's
	// Via is. There is one chaining control in the panel and it is the Dialer Proxy
	// select, present on every outbound row including the socks facade that fronts this
	// tunnel; the browser posts whatever it holds into this field. The stored name stays
	// Via because that is what the routing side calls it, and because the key must not
	// survive into the Xray config: there dialerProxy means "dial through that outbound
	// instead", which would redirect the facade's loopback CONNECT to the local SOCKS
	// port somewhere else entirely and break the tunnel it was meant to carry.
	//
	// omitempty is load-bearing rather than tidy. Every stored tunnel predates this
	// field, the whole list lives in ONE settings row, and that row is re-marshalled and
	// written back in full whenever anything in it changes (any Save, any Delete, and
	// every TOFU host key that gets learned). Without omitempty the first such write
	// would stamp `"via":""` onto tunnels nobody touched, and the same list is what the
	// synthesized socks outbounds are derived from (applySshOutbounds), so an upgrade
	// would rewrite stored config and restart the core over rows that did not change.
	Via string `json:"via,omitempty" form:"via"`
}

const sshOutboundsSettingKey = "sshOutbounds"

// sshOutCfgMu serialises the read-modify-write of the whole tunnel list, which
// lives in ONE settings row. Without it two concurrent saves both load the same
// list, both append their own tunnel and both write: the loser's tunnel vanishes
// from the setting while its listener stays bound and its goroutines keep running,
// so it is invisible in the UI, unstoppable, and re-raised by nothing at boot.
// Single-process panel, so a plain mutex is enough.
var sshOutCfgMu sync.Mutex

// --- Service API (thin; live state lives in sshOutMgr) ---

// InitSshOutbound raises every configured tunnel at panel boot.
func (s *SshOutboundService) InitSshOutbound() {
	for _, cfg := range s.load() {
		// The stored port is deliberately re-bound as-is rather than re-allocated:
		// the saved Xray config already names it. If it is taken, the tunnel stays
		// down and says so, which is recoverable by re-saving it in the panel;
		// moving it here would leave a running tunnel that the outbound pointing at
		// the old port can never reach, and nothing on screen would look wrong.
		if _, err := sshOutMgr.start(cfg, false); err != nil {
			logger.Warning("ssh outbound: start failed for", cfg.Tag,
				"on local socks port", cfg.SocksPort, ":", err,
				"- re-save it in the panel to bind a free port")
		}
	}
}

// List returns the configured tunnels with secrets stripped (never leak the PEM/password).
func (s *SshOutboundService) List() []SshOutboundConfig {
	list := s.load()
	out := make([]SshOutboundConfig, len(list))
	for i, c := range list {
		c.Password = ""
		c.PrivateKey = ""
		c.Passphrase = ""
		out[i] = c
	}
	return out
}

// Save upserts a tunnel by tag, starts it, and returns the loopback SOCKS port it
// is listening on. A blank secret on edit keeps the stored one, so the UI can show
// an empty field without wiping the key.
//
// SocksPort <= 0 means "allocate one". The tunnel is started BEFORE the config is
// persisted, because starting is what decides the port: the listener is bound on
// 127.0.0.1:0 and the kernel hands back one that was free at bind time. Picking a
// number first and binding it later is the version with a race in it.
func (s *SshOutboundService) Save(cfg SshOutboundConfig) (SshOutboundConfig, error) {
	cfg.Tag = strings.TrimSpace(cfg.Tag)
	cfg.Address = strings.TrimSpace(cfg.Address)
	// Trimmed like the tag it names. The carrier is resolved by exact tag match, so a
	// stray space would resolve to nothing and the tunnel would dial straight out of the
	// host's WAN while the panel showed a carrier on it.
	cfg.Via = strings.TrimSpace(cfg.Via)
	if cfg.Tag == "" {
		return cfg, errors.New("tag is required")
	}
	if cfg.Address == "" {
		return cfg, errors.New("address is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 22
	}
	if cfg.SocksPort > 65535 {
		return cfg, errors.New("local socks port must be 65535 or below")
	}

	sshOutCfgMu.Lock()
	defer sshOutCfgMu.Unlock()

	all := s.load()
	if prev, hadPrev := findTunnel(all, cfg.Tag); hadPrev {
		cfg = sshOutKeepStored(cfg, prev)
	}

	out := make([]SshOutboundConfig, 0, len(all)+1)
	for _, c := range all {
		if c.Tag == cfg.Tag {
			continue // replaced below
		}
		if cfg.SocksPort > 0 && c.SocksPort == cfg.SocksPort {
			return cfg, fmt.Errorf("local socks port %d is already used by outbound %q", cfg.SocksPort, c.Tag)
		}
		out = append(out, c)
	}

	// allowRepick: a save can move the port, because the resolved one is returned
	// to the caller and written into the outbound that points at it.
	port, err := sshOutMgr.start(cfg, true)
	if err != nil {
		return cfg, err
	}
	cfg.SocksPort = port

	out = append(out, cfg)
	if err := s.persist(out); err != nil {
		// The tunnel is up but its config would be lost on restart, and the caller
		// is about to point an outbound at a port nothing will re-bind. Take it
		// back down rather than leave that mismatch.
		sshOutMgr.stop(cfg.Tag)
		return cfg, err
	}
	// The socks outbound fronting this tunnel is derived from the stored list at
	// config-build time (XrayService.applySshOutbounds), so the core has to be
	// rebuilt for the change to reach it.
	(&XrayService{}).SetToNeedRestart()
	return cfg, nil
}

// sshOutKeepStored fills in the fields an edit CANNOT re-send, from the tunnel that is
// already stored. List() strips Password/PrivateKey/Passphrase before the panel ever
// sees them, so every edit posts them blank; taking that at face value would wipe the
// key or password of any tunnel whose remark was changed, and the tunnel would then
// fail to authenticate at the next reconnect with nothing on screen having asked for
// that. SocksPort is here for a different reason: the saved Xray outbound names it by
// number, so re-allocating on an edit would break a working tunnel silently.
//
// Via is deliberately NOT merged, and keeping that decision in one named place is the
// point of this function. The carrier comes from the row's Dialer Proxy select, which
// the browser posts on EVERY save including an empty one, so blank means "no carrier"
// and never "I could not tell you". Merging it the way the secrets are merged would
// make clearing that box a no-op: the routing rules steering this tunnel's TCP
// connection into the old carrier would outlive a save that removed the carrier from
// the screen, and nothing anywhere would report the difference.
func sshOutKeepStored(cfg, prev SshOutboundConfig) SshOutboundConfig {
	if cfg.Password == "" {
		cfg.Password = prev.Password
	}
	if cfg.PrivateKey == "" {
		cfg.PrivateKey = prev.PrivateKey
	}
	if cfg.Passphrase == "" {
		cfg.Passphrase = prev.Passphrase
	}
	if cfg.SocksPort <= 0 {
		cfg.SocksPort = prev.SocksPort
	}
	return cfg
}

// Delete removes a tunnel by tag and stops it.
func (s *SshOutboundService) Delete(tag string) error {
	sshOutCfgMu.Lock()
	defer sshOutCfgMu.Unlock()

	all := s.load()
	out := make([]SshOutboundConfig, 0, len(all))
	for _, c := range all {
		if c.Tag != tag {
			out = append(out, c)
		}
	}
	if err := s.persist(out); err != nil {
		return err
	}
	sshOutMgr.stop(tag)
	// Drops the synthesized outbound too; see Save.
	(&XrayService{}).SetToNeedRestart()
	return nil
}

// Status reports whether a tunnel's SSH client is currently connected, plus its log.
func (s *SshOutboundService) Status(tag string) (bool, string) { return sshOutMgr.status(tag) }

// StopAll tears every tunnel down (panel shutdown).
func (s *SshOutboundService) StopAll() { sshOutMgr.stopAll() }

func (s *SshOutboundService) load() []SshOutboundConfig {
	var settingService SettingService
	raw, err := settingService.getString(sshOutboundsSettingKey)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []SshOutboundConfig
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		logger.Warning("ssh outbound: bad sshOutbounds setting:", err)
		return nil
	}
	return out
}

func (s *SshOutboundService) persist(list []SshOutboundConfig) error {
	var settingService SettingService
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return settingService.setString(sshOutboundsSettingKey, string(b))
}

func findTunnel(list []SshOutboundConfig, tag string) (SshOutboundConfig, bool) {
	for _, c := range list {
		if c.Tag == tag {
			return c, true
		}
	}
	return SshOutboundConfig{}, false
}

// --- Live state: the tunnel manager ---

var sshOutMgr = newSshOutManager()

func newSshOutManager() *sshOutManager {
	return &sshOutManager{tunnels: map[string]*sshTunnel{}}
}

type sshOutManager struct {
	mu      sync.Mutex
	tunnels map[string]*sshTunnel // keyed by cfg.Tag
}

type sshTunnel struct {
	cfg     SshOutboundConfig
	ln      net.Listener // local SOCKS5 listener; stays bound across reconnects
	log     *procLog     // procmgr.go ring buffer, reused for the Logs viewer
	gen     atomic.Int64 // bumped on stop/restart; loops compare to exit cleanly
	client  atomic.Pointer[ssh.Client]
	closing atomic.Bool
	// Fingerprint adopted on the first connect when no pin was configured, and
	// enforced on every reconnect after. Read and written from the handshake
	// callback, which runs on the dialing goroutine, hence atomic.
	learnedKey atomic.Pointer[string]
}

// start binds the local SOCKS5 listener once, then runs a supervisor that keeps an
// ssh.Client dialed with capped backoff. The listener persists across reconnects so the
// Xray socks outbound never sees the port vanish (CONNECTs fail transiently while
// reconnecting rather than the outbound looking misconfigured). Replaces any existing
// tunnel for the same tag.
// Returns the port actually bound, which is the requested one when cfg.SocksPort
// is set and free, and a kernel-assigned one otherwise.
func (m *sshOutManager) start(cfg SshOutboundConfig, allowRepick bool) (int, error) {
	m.stop(cfg.Tag)
	ln, err := listenLoopback(cfg.SocksPort, allowRepick)
	if err != nil {
		return 0, err
	}
	cfg.SocksPort = ln.Addr().(*net.TCPAddr).Port
	t := &sshTunnel{cfg: cfg, ln: ln, log: &procLog{}}
	m.mu.Lock()
	m.tunnels[cfg.Tag] = t
	m.mu.Unlock()
	go t.serveSocks()
	go t.supervise()
	return cfg.SocksPort, nil
}

// The band auto-allocated tunnel ports are drawn from. It starts above WARP's
// SOCKS port (warpsocks.go DefaultSocksPort = 10808) and stays well clear of the
// per-inbound bands at 12300/13300/14300 + inbound.Id.
//
// Deliberately NOT the kernel's own choice via ":0". That returns a port from the
// ephemeral range (32768-60999 on Linux), which is the pool outgoing connections
// are drawn from - and this port is PERSISTED. After a reboot the panel's own
// dials (SSH, RADIUS, acme, update checks) can be handed the number the stored
// config still expects the tunnel on, and Xray then talks to a stranger's socket.
const (
	sshOutPortFirst = 10810
	sshOutPortLast  = 11309
)

// listenLoopback binds a tunnel's local SOCKS listener and returns it live.
//
// preferred > 0 is tried first and, if it binds, used: an existing tunnel keeps
// the port the saved Xray outbound already names. Otherwise the band above is
// scanned by ACTUALLY BINDING, and the first listener that succeeds is the one
// returned - never probed-then-closed. That is what makes this safe without a
// lock: two tunnels starting concurrently cannot land on the same port because
// the kernel refuses the second bind and the loser simply advances.
//
// The ":0" fallback only runs if all 500 slots are held, where an ephemeral port
// beats no tunnel at all.
// allowRepick decides what happens when `preferred` is taken. A SAVE passes true:
// it hands the resolved port back to the caller, who rewrites the outbound to
// match, so moving is safe and is the only way an operator can recover a tunnel
// whose port was stolen. BOOT passes false: nothing is listening to the answer
// there, so a silent move would leave the saved outbound pointing at whatever
// else now owns the old port. Failing is the recoverable outcome.
func listenLoopback(preferred int, allowRepick bool) (net.Listener, error) {
	if preferred > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", preferred))
		if err == nil || !allowRepick {
			return ln, err
		}
		logger.Warning("ssh outbound: local socks port", preferred,
			"is taken, allocating another:", err)
	}
	for port := sshOutPortFirst; port <= sshOutPortLast; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return ln, nil
		}
	}
	logger.Warning("ssh outbound: no free port in", sshOutPortFirst, "-", sshOutPortLast,
		"- falling back to an ephemeral one, which may not survive a reboot")
	return net.Listen("tcp", "127.0.0.1:0")
}

func (m *sshOutManager) stop(tag string) {
	m.mu.Lock()
	t := m.tunnels[tag]
	delete(m.tunnels, tag)
	m.mu.Unlock()
	if t == nil {
		return
	}
	t.closing.Store(true)
	t.gen.Add(1)
	if t.ln != nil {
		_ = t.ln.Close() // unblocks the accept loop
	}
	if cl := t.client.Load(); cl != nil {
		_ = cl.Close() // unblocks supervise()'s cl.Wait()
	}
}

func (m *sshOutManager) stopAll() {
	m.mu.Lock()
	tags := make([]string, 0, len(m.tunnels))
	for tag := range m.tunnels {
		tags = append(tags, tag)
	}
	m.mu.Unlock()
	for _, tag := range tags {
		m.stop(tag)
	}
}

func (m *sshOutManager) status(tag string) (bool, string) {
	m.mu.Lock()
	t := m.tunnels[tag]
	m.mu.Unlock()
	if t == nil {
		return false, ""
	}
	return t.client.Load() != nil, t.log.String()
}

// supervise dials (and redials) the SSH server, keeping t.client populated while up.
func (t *sshTunnel) supervise() {
	gen := t.gen.Load()
	backoff := time.Second
	for !t.closing.Load() && t.gen.Load() == gen {
		cl, err := ssh.Dial("tcp", net.JoinHostPort(t.cfg.Address, strconv.Itoa(t.cfg.Port)), t.clientConfig())
		if err != nil {
			t.log.add("dial: " + err.Error())
			if !t.sleep(backoff, gen) {
				return
			}
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second
		t.client.Store(cl)
		t.log.add("connected to " + t.cfg.Address)
		cl.Wait() // blocks until the SSH connection drops
		t.client.Store(nil)
		if !t.closing.Load() && t.gen.Load() == gen {
			t.log.add("disconnected, reconnecting")
		}
	}
}

// sleep waits d, but wakes early (returning false) if the tunnel is stopped/restarted.
func (t *sshTunnel) sleep(d time.Duration, gen int64) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if t.closing.Load() || t.gen.Load() != gen {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !t.closing.Load() && t.gen.Load() == gen
}

// clientConfig builds the ssh.ClientConfig from the tunnel's auth settings. The host key
// is pinned to cfg.KnownHost when set (SHA256 or legacy MD5 fingerprint), else TOFU-logged
// - never InsecureIgnoreHostKey silently.
func (t *sshTunnel) clientConfig() *ssh.ClientConfig {
	cfg := &ssh.ClientConfig{
		User:    t.cfg.Username,
		Timeout: 15 * time.Second,
	}
	switch t.cfg.AuthType {
	case "privateKey":
		var signer ssh.Signer
		var err error
		if strings.TrimSpace(t.cfg.Passphrase) != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(t.cfg.PrivateKey), []byte(t.cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(t.cfg.PrivateKey))
		}
		if err != nil {
			t.log.add("private key error: " + err.Error())
		} else {
			cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
		}
	default:
		cfg.Auth = []ssh.AuthMethod{ssh.Password(t.cfg.Password)}
	}
	if pin := strings.TrimSpace(t.cfg.KnownHost); pin != "" {
		cfg.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) == pin || ssh.FingerprintLegacyMD5(key) == pin {
				return nil
			}
			return fmt.Errorf("host key mismatch (got %s)", ssh.FingerprintSHA256(key))
		}
	} else {
		// Real trust-on-first-use. This used to log the fingerprint and return nil
		// unconditionally, on EVERY reconnect - which is InsecureIgnoreHostKey with
		// a log line, not TOFU: nothing was ever recorded, so nothing was ever
		// compared, and a MITM on the SSH address could present a fresh key at any
		// time. With password auth that hands over the password in plaintext and
		// exposes all proxied traffic.
		//
		// Now the first key seen is adopted as the pin, persisted so it survives a
		// restart, and enforced from then on. An operator who genuinely rotates the
		// server key clears the field to re-learn.
		cfg.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			if learned := t.learnedKey.Load(); learned != nil {
				if *learned == fp {
					return nil
				}
				return fmt.Errorf("host key changed since first connect (trusted %s, got %s) - "+
					"clear the host key pin to accept the new one", *learned, fp)
			}
			t.learnedKey.Store(&fp)
			t.log.add("host key learned (trust on first use): " + fp)
			// Off the handshake goroutine: persisting takes the config lock, which
			// the Save that started this tunnel may still hold.
			go persistLearnedHostKey(t.cfg.Tag, fp)
			return nil
		}
	}
	return cfg
}

// persistLearnedHostKey records a TOFU-adopted fingerprint against its tunnel so
// the pin survives a panel restart.
//
// Updates in place only, never appends: the tunnel may have been deleted or
// replaced while the handshake was in flight, and resurrecting it from a
// background goroutine would be worse than losing the pin. A tunnel whose pin was
// set by the operator meanwhile is left alone for the same reason.
func persistLearnedHostKey(tag, fingerprint string) {
	sshOutCfgMu.Lock()
	defer sshOutCfgMu.Unlock()

	var svc SshOutboundService
	all := svc.load()
	updated := false
	for i := range all {
		if all[i].Tag == tag && strings.TrimSpace(all[i].KnownHost) == "" {
			all[i].KnownHost = fingerprint
			updated = true
			break
		}
	}
	if !updated {
		return
	}
	if err := svc.persist(all); err != nil {
		logger.Warning("ssh outbound: could not record the learned host key for", tag, ":", err)
	}
}

func (t *sshTunnel) serveSocks() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return // listener closed on stop
		}
		go t.handleSocks(conn)
	}
}

// handleSocks negotiates a minimal SOCKS5 CONNECT (no auth; loopback only) and relays it
// over a direct-tcpip channel on the SSH client - the inverse of the inbound's
// handleDirectTCPIP. UDP ASSOCIATE is rejected (TCP-only for now).
func (t *sshTunnel) handleSocks(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) // handshake window
	br := bufio.NewReader(conn)

	// Greeting: VER, NMETHODS, METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHead); err != nil || reqHead[0] != 0x05 {
		return
	}
	host, err := socksReadAddr(br, reqHead[3])
	if err != nil {
		t.socksReply(conn, 0x08) // address type not supported
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	if reqHead[1] != 0x01 { // CONNECT only
		t.socksReply(conn, 0x07) // command not supported
		return
	}

	client := t.client.Load()
	if client == nil {
		t.socksReply(conn, 0x04) // host unreachable (tunnel down / reconnecting)
		return
	}
	upstream, err := client.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.log.add("channel to " + host + ": " + err.Error())
		t.socksReply(conn, 0x05) // connection refused
		return
	}
	if err := t.socksReply(conn, 0x00); err != nil {
		upstream.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{}) // clear handshake deadline for the relay

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	conn.Close()
	upstream.Close()
	<-done
}

// socksReply writes a SOCKS5 reply with the given REP code and a 0.0.0.0:0 bound address.
func (t *sshTunnel) socksReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
