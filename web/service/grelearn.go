package service

import (
	"net"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// greLearner binds dynamic GRE peers to their current public address.
//
// WHY THIS EXISTS. A GRE netdev created with no `remote` accepts traffic from any source,
// which is what lets a customer on a dynamic public IP connect at all. But the device is
// NOARP and the kernel does NOT learn the reverse path: it decapsulates the inbound packet
// happily and then has no idea where to send the reply. The mapping lives in the neighbour
// table, where `lladdr` holds the peer's OUTER address for a given inner address, and
// something in userspace has to write it. NHRP daemons do exactly this job; this is the
// same idea in about a hundred lines.
//
// HOW IT READS TRAFFIC. A raw AF_INET socket bound to IPPROTO_GRE. The kernel hands such a
// socket a copy of every protocol-47 packet, INCLUDING packets a tunnel device also
// consumes, and nothing else, so no BPF program or packet-filter dependency is needed. The
// socket is passive: it takes a copy and issues no verdict, so it adds no latency and no
// new failure mode to live traffic (unlike an NFQUEUE, which sits in the packet path).
//
// WHY IT IS DUTY-CYCLED. A raw socket sees every GRE packet, so leaving it open on a busy
// server would copy a high-throughput tunnel's entire traffic into userspace for no reason.
// It does not need to: once a peer is bound, the neighbour entry is PERMANENT and the
// binding only has to change if that customer's public address changes. So the learner
// sniffs in short windows, and only listens continuously while some peer is still unbound.
// The window recurs so a peer whose address changed is rebound within about a minute
// without any steady-state cost.
type greLearner struct {
	mu    sync.Mutex
	peers map[string]greDynamicPeer // inner IP -> where it may be bound
	bound map[string]string         // inner IP -> outer IP last written

	stop    chan struct{}
	wake    chan struct{}
	started bool
}

const (
	// greLearnWindow is how long one sniffing window lasts.
	greLearnWindow = 5 * time.Second
	// greLearnHunting is the pause between windows while a peer is still unbound.
	greLearnHunting = 2 * time.Second
	// greLearnSettled is the pause between windows once every peer is bound. This is the
	// upper bound on how long a peer that changed address stays dark.
	greLearnSettled = 55 * time.Second
	// greLearnRcvBuf keeps the socket's queue small: we only need a packet or two per
	// window, so the kernel can cheaply drop the rest instead of buffering megabytes.
	greLearnRcvBuf = 64 * 1024
)

func newGreLearner() *greLearner {
	return &greLearner{
		peers: map[string]greDynamicPeer{},
		bound: map[string]string{},
		stop:  make(chan struct{}),
		wake:  make(chan struct{}, 1),
	}
}

// SetPeers publishes the set of inner addresses the learner may bind, and starts the loop on
// first use. Addresses that disappeared (account disabled, peer given a static IP, User
// Limit lowered) are forgotten here; withdrawing the kernel entry itself is
// GreService.reconcileNeigh's job, so the two never race to delete.
func (l *greLearner) SetPeers(peers map[string]greDynamicPeer) {
	l.mu.Lock()
	l.peers = peers
	for inner := range l.bound {
		if _, ok := peers[inner]; !ok {
			delete(l.bound, inner)
		}
	}
	// Anything present but unbound means there is something to learn RIGHT NOW.
	fresh := false
	for inner := range peers {
		if l.bound[inner] == "" {
			fresh = true
			break
		}
	}
	needStart := !l.started && len(peers) > 0
	if needStart {
		l.started = true
	}
	wake := l.wake
	l.mu.Unlock()

	if needStart {
		go l.run()
		return
	}
	// Interrupt the idle wait instead of letting a new peer sit out the remaining
	// settled sleep. Without this a freshly added peer could go up to a minute before
	// the learner even looked for it, which reads to the customer as "the tunnel came up
	// but nothing works" and made the E2E's dynamic-peer connect flaky.
	if fresh {
		select {
		case wake <- struct{}{}:
		default: // a wake is already pending
		}
	}
}

// Forget drops a binding so the next window rebinds the peer from scratch.
func (l *greLearner) Forget(inner string) {
	l.mu.Lock()
	delete(l.bound, inner)
	l.mu.Unlock()
}

func (l *greLearner) Stop() {
	l.mu.Lock()
	if !l.started {
		l.mu.Unlock()
		return
	}
	l.started = false
	close(l.stop)
	l.stop = make(chan struct{})
	l.wake = make(chan struct{}, 1)
	l.mu.Unlock()
}

// wanted returns the current peer set and whether any of it is still unbound.
func (l *greLearner) wanted() (map[string]greDynamicPeer, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	peers := make(map[string]greDynamicPeer, len(l.peers))
	unbound := false
	for inner, d := range l.peers {
		peers[inner] = d
		if l.bound[inner] == "" {
			unbound = true
		}
	}
	return peers, unbound
}

func (l *greLearner) run() {
	for {
		l.mu.Lock()
		stop := l.stop
		l.mu.Unlock()

		l.mu.Lock()
		wake := l.wake
		l.mu.Unlock()

		peers, unbound := l.wanted()
		if len(peers) == 0 {
			select {
			case <-stop:
				return
			case <-wake:
				continue
			case <-time.After(greLearnSettled):
				continue
			}
		}

		l.sniff(peers, stop)

		pause := greLearnSettled
		if unbound {
			pause = greLearnHunting
		}
		select {
		case <-stop:
			return
		case <-wake:
		case <-time.After(pause):
		}
	}
}

// sniff opens the raw socket for one window and binds whatever shows up.
func (l *greLearner) sniff(peers map[string]greDynamicPeer, stop <-chan struct{}) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_GRE)
	if err != nil {
		logger.Debug("gre learner: raw socket:", err)
		return
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, greLearnRcvBuf)
	// A read timeout well under the window keeps the loop responsive to Stop and lets the
	// window end on time on a completely idle box.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
		&unix.Timeval{Sec: 1})

	buf := make([]byte, 2048)
	deadline := time.Now().Add(greLearnWindow)
	for time.Now().Before(deadline) {
		select {
		case <-stop:
			return
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return
		}
		outer, inner, ok := parseGrePair(buf[:n])
		if !ok {
			continue
		}
		d, allowed := peers[inner]
		if !allowed {
			// A static peer (already served by its own device) or an address we do not own.
			continue
		}
		l.bind(inner, outer, d)
	}
}

// bind writes the inner->outer neighbour entry, skipping the netlink call when the mapping
// is unchanged so a busy tunnel costs one map lookup per packet rather than a syscall.
func (l *greLearner) bind(inner, outer string, d greDynamicPeer) {
	l.mu.Lock()
	if l.bound[inner] == outer {
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()

	link, err := netlink.LinkByName(d.Iface)
	if err != nil {
		return
	}
	innerIP := net.ParseIP(inner)
	outerIP := net.ParseIP(outer)
	if innerIP == nil || outerIP == nil || outerIP.To4() == nil {
		return
	}
	// NeighSet has REPLACE semantics. `ip neigh add` would fail EEXIST here, because a
	// packet arriving for an unresolved address already leaves an incomplete entry behind.
	// LLIPAddr, not HardwareAddr: for a GRE device the neighbour's "link address" IS an IPv4
	// address, and LLIPAddr is the field netlink serialises preferentially and parses a
	// 4-byte lladdr back into. Writing the one field and reading the other is what left every
	// dynamic peer looking unbound to Poll(), and therefore unbilled. See greNeighOuter.
	nb := &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    unix.AF_INET,
		State:     netlink.NUD_PERMANENT,
		IP:        innerIP,
		LLIPAddr:  outerIP.To4(),
	}
	if err := netlink.NeighSet(nb); err != nil {
		logger.Debugf("gre learner: bind %s -> %s on %s: %v", inner, outer, d.Iface, err)
		return
	}
	l.mu.Lock()
	l.bound[inner] = outer
	l.mu.Unlock()
	logger.Infof("GRE: learned peer %s for %s (account %s) on %s", outer, inner, d.Email, d.Iface)
}

// parseGrePair extracts (outer source, inner source) from one raw protocol-47 packet.
//
// A raw AF_INET socket hands over the full outer IPv4 header, then the GRE header, whose
// optional checksum/key/sequence fields are present only when their flag bit is set (RFC
// 2784 + 2890), then the encapsulated packet.
func parseGrePair(pkt []byte) (outer, inner string, ok bool) {
	if len(pkt) < 20 {
		return "", "", false
	}
	if pkt[0]>>4 != 4 {
		return "", "", false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+4 {
		return "", "", false
	}
	if pkt[9] != unix.IPPROTO_GRE {
		return "", "", false
	}
	outerSrc := net.IP(pkt[12:16]).String()

	g := pkt[ihl:]
	flags := uint16(g[0])<<8 | uint16(g[1])
	etype := uint16(g[2])<<8 | uint16(g[3])
	if etype != 0x0800 {
		// Not IPv4 inside. PPTP's GRE (version 1, type 0x880B) and MikroTik EoIP (0x6400)
		// both land here and are correctly ignored.
		return "", "", false
	}
	off := 4
	if flags&0x8000 != 0 { // checksum present (+ reserved1)
		off += 4
	}
	if flags&0x2000 != 0 { // key present
		off += 4
	}
	if flags&0x1000 != 0 { // sequence number present
		off += 4
	}
	if len(g) < off+20 {
		return "", "", false
	}
	ip := g[off:]
	if ip[0]>>4 != 4 {
		return "", "", false
	}
	return outerSrc, net.IP(ip[12:16]).String(), true
}
