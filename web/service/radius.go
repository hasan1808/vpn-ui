package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/service/rbridge"

	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3079"
	"layeh.com/radius/vendors/microsoft"
)

// RadiusService embeds a RADIUS server for PPP (L2TP/PPTP) authentication and accounting.
// Auth: pppd sends Access-Request with MS-CHAPv2 → we query SQLite → Accept/Reject.
// Acct: pppd sends Acct-Start/Stop → we manage nft counters and track sessions in memory.
type RadiusService struct {
	nftService  NftService
	authServer  *radius.PacketServer
	acctServer  *radius.PacketServer
	mu          sync.Mutex
	sessions    map[string]*radiusSession // key: Acct-Session-Id
	pending     map[string]time.Time      // key: freshly allocated IP awaiting Acct-Start (User Limit blocks)
	stationIP   map[string]string         // key: "proto:idx:Calling-Station-Id" -> its stable block IP
	stationSeen map[string]time.Time      // last time each station authenticated (for pruning)
	secret      []byte
	eapSessions map[string]*eapState // key: hex(State attr): in-flight EAP-MSCHAPv2 exchanges (IKEv2/strongSwan)
	// ocActiveFn overrides the OpenConnect liveness probe (isIPActive) — set in unit
	// tests where no real ocserv route table exists. nil in production.
	ocActiveFn func(ip string) bool
}

// ocIsActive reports whether an OpenConnect tunnel IP is still live (routes via an
// ocserv device), through the injectable probe so tests can stub it.
func (s *RadiusService) ocIsActive(ip string) bool {
	if s.ocActiveFn != nil {
		return s.ocActiveFn(ip)
	}
	return s.isIPActive(ip, "openconnect")
}

// pendingLeaseTTL is how long a block-allocated IP is held between the
// Access-Accept that assigned it and the Acct-Start that confirms it. An auth
// that never starts a session (retry, abandoned dial) frees the IP after this.
const pendingLeaseTTL = 90 * time.Second

// pendingReclaimGrace is the minimum age of a pending block-lease before it may
// be reclaimed for a different dial. Longer than a normal auth->Acct-Start gap
// (a few seconds), so a device still mid-handshake is never handed its slot to
// someone else; far shorter than pendingLeaseTTL, so a genuinely abandoned
// (ghost) lease is reclaimed promptly instead of wedging the account until TTL.
const pendingReclaimGrace = 15 * time.Second

// ocStaleReclaimGrace is how long an OpenConnect block session is trusted as "still
// establishing" before its missing ocserv route is taken to mean the tunnel is gone.
// Long enough that a freshly-authed session's route is in the kernel; short enough
// that a genuine re-dial of a dropped device isn't blocked as "block full" for long.
const ocStaleReclaimGrace = 15 * time.Second

// ocInterimInterval is the Acct-Interim-Interval the panel asks ocserv for, so it is
// also how often a live OpenConnect session announces itself (see handleOcservAcct).
const ocInterimInterval = 60

// ocHeartbeatGrace is how long an OpenConnect session is trusted on its last
// Interim-Update alone.
//
// ocserv reports on a 30s check tick and fuzzes the interval by a few seconds, so the
// real gap between updates is up to ~95s rather than the 60s asked for; radcli retries a
// packet the panel does not answer, so a lost one is not a third case. 150s therefore
// carries a comfortable margin over one gap while still bounding how long a session that
// went silent WITHOUT a stop (an ocserv crash) keeps its address before the route probe
// takes over.
const ocHeartbeatGrace = 150 * time.Second

type radiusSession struct {
	email    string
	ip       string
	protocol string    // "l2tp", "pptp", "openvpn", or "openconnect"
	started  time.Time // session start; used to pick the oldest device to evict
	// heard is the last time the DAEMON itself confirmed the tunnel is up (an
	// OpenConnect Interim-Update). Zero for the protocols whose accounting the panel
	// does not use as a heartbeat, so a zero value must never read as "long ago".
	heard time.Time
	// acctID is the daemon's own Acct-Session-Id, learned from that same
	// Interim-Update. OpenConnect sessions are keyed by tunnel IP, and an address
	// outlives the device that held it, so this is the only way to tell whether a later
	// Acct-Stop is ending THIS session or the predecessor that used to hold the address.
	// Empty until the first interim, and unused by the protocols keyed by session id.
	acctID string
}

// ocSessionKey is the s.sessions map key for an auth-recorded OpenConnect session.
// ocserv's accounting can identify neither the device nor its IP (it sends no
// Framed-IP-Address and no NAS-Port), so — unlike l2tp/pptp — an OpenConnect session
// can't be keyed by Acct-Session-Id at Acct-Start. It is instead recorded at AUTH and
// keyed by its assigned tunnel IP, which is unique per device (each holds a distinct
// block IP) and, with groupconfig=true, equals the real ocserv tunnel IP. The "oc:"
// prefix can't collide with a real ocserv Acct-Session-Id.
func ocSessionKey(ip string) string { return "oc:" + ip }

// runningRadius points at the RadiusService whose servers are currently bound.
// The embedded RADIUS server lives in-process (not a child daemon), so the Core
// Settings restart/stop controls act on this instance rather than a PID.
var runningRadius *RadiusService

// Start launches the RADIUS auth (1812) and accounting (1813) servers on localhost.
func (s *RadiusService) Start(secret string) error {
	s.sessions = make(map[string]*radiusSession)
	s.pending = make(map[string]time.Time)
	return s.listen(secret)
}

// listen (re)creates and serves the auth/acct packet servers. It does NOT touch
// the sessions map, so a restart preserves active-session tracking (the map is
// shared by reference with the L2TP/PPTP/OpenVPN services).
func (s *RadiusService) listen(secret string) error {
	s.secret = []byte(secret)

	s.authServer = &radius.PacketServer{
		Addr:         "127.0.0.1:1812",
		Handler:      radius.HandlerFunc(s.handleAuth),
		SecretSource: radius.StaticSecretSource(s.secret),
	}
	s.acctServer = &radius.PacketServer{
		Addr:         "127.0.0.1:1813",
		Handler:      radius.HandlerFunc(s.handleAcct),
		SecretSource: radius.StaticSecretSource(s.secret),
	}

	go func() {
		if err := s.authServer.ListenAndServe(); err != nil {
			logger.Warning("RADIUS: auth server stopped:", err)
		}
	}()
	go func() {
		if err := s.acctServer.ListenAndServe(); err != nil {
			logger.Warning("RADIUS: acct server stopped:", err)
		}
	}()

	runningRadius = s
	logger.Info("RADIUS: listening on 127.0.0.1:1812 (auth) and :1813 (acct)")
	return nil
}

// Stop gracefully shuts down both RADIUS servers.
func (s *RadiusService) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.authServer != nil {
		s.authServer.Shutdown(ctx)
		s.authServer = nil
	}
	if s.acctServer != nil {
		s.acctServer.Shutdown(ctx)
		s.acctServer = nil
	}
}

// StopRadius stops the embedded RADIUS servers. Exported for the Core Settings
// "Stop" control. Note: this halts L2TP/PPTP/OpenVPN authentication until a
// restart, so it is a deliberate, admin-triggered action.
func StopRadius() error {
	if runningRadius == nil {
		return fmt.Errorf("RADIUS server is not running")
	}
	runningRadius.Stop()
	logger.Info("RADIUS: stopped")
	return nil
}

// RestartRadius restarts the embedded RADIUS servers, picking up the current
// shared secret from settings. The in-memory session map is preserved.
func RestartRadius() error {
	if runningRadius == nil {
		return fmt.Errorf("RADIUS server is not running")
	}
	var settingService SettingService
	secret, _ := settingService.GetRadiusSecret()
	if secret == "" {
		secret = string(runningRadius.secret)
	}
	runningRadius.Stop()
	if runningRadius.sessions == nil {
		runningRadius.sessions = make(map[string]*radiusSession)
	}
	return runningRadius.listen(secret)
}

// handleAuth processes RADIUS Access-Request packets with MS-CHAPv2 authentication.
// NAS-Identifier encodes the protocol and inbound ID (e.g. "l2tp-3" or "pptp-5").
func (s *RadiusService) handleAuth(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	challenge := microsoft.MSCHAPChallenge_Get(r.Packet)
	response := microsoft.MSCHAP2Response_Get(r.Packet)

	// Per-device identity for User Limit K>1 (see allocateBlockIP): Calling-Station-Id
	// (the client's remote IP) PLUS NAS-Port (the pppd unit number). Two distinct
	// devices on one account behind the SAME NAT share a Calling-Station-Id, so the
	// NAS-Port is what tells them apart and keeps the K cap honest; a unit is reused
	// once freed, so a genuine redial that reclaims it stays idempotent.
	station := rfc2865.CallingStationID_GetString(r.Packet)
	nasPort := uint32(rfc2865.NASPort_Get(r.Packet))

	if username == "" || nasID == "" {
		logger.Debug("RADIUS: auth rejected — missing username or NAS-Identifier")
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Parse NAS-Identifier: "l2tp-{id}" or "pptp-{id}"
	protocol, inboundId, err := parseNASIdentifier(nasID)
	if err != nil {
		logger.Infof("RADIUS: auth rejected — invalid NAS-Identifier %q", nasID)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// EAP (IKEv2 via strongSwan's eap-radius plugin): EAP-MSCHAPv2 is a multi-round
	// Access-Challenge exchange, unlike the single-shot PAP / native-MS-CHAPv2 paths
	// below. Delegate the whole conversation as soon as an EAP-Message is present.
	if eap := getEAPMessage(r.Packet); len(eap) > 0 {
		s.handleEAPAuth(w, r, protocol, inboundId, username, station, nasPort, eap)
		return
	}

	// Look up the client password from the database
	password, err := s.lookupClient(protocol, inboundId, username)
	if err != nil {
		logger.Infof("RADIUS: auth rejected — %s user=%s nas=%s", err, username, nasID)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// PAP authentication. Both OpenVPN's auth hook (`vpn-ui openvpn-auth`) and
	// OpenConnect (ocserv via radcli) authenticate with a plaintext User-Password.
	userPassword := rfc2865.UserPassword_GetString(r.Packet)
	if userPassword != "" {
		if userPassword != password {
			logger.Infof("RADIUS: auth rejected (PAP) — wrong password user=%s nas=%s", username, nasID)
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		accept := r.Response(radius.CodeAccessAccept)
		// OpenConnect is RADIUS-authoritative for the tunnel IP: ocserv runs with
		// predictable-ips=false and NO local pool, so it provisions each session from
		// the Access-Accept's Framed-IP-Address. A keyless accept leaves ocserv with
		// no IP to assign — the session can't come up and the client sees an auth
		// failure. This branch therefore mirrors the MS-CHAPv2 path for openconnect:
		// assign the per-user source IP and apply the User-Limit gate (reject
		// strategy). OpenVPN assigns IPs via CCD and enforces User Limit in its
		// connect hook, so it keeps taking the bare accept unchanged.
		if protocol == "openconnect" {
			clientIP, deny := s.getClientIP(protocol, inboundId, username, station, nasPort)
			if deny {
				logger.Infof("RADIUS: auth rejected — user-limit reached (strategy=reject) user=%s nas=%s", username, nasID)
				w.Write(r.Response(radius.CodeAccessReject))
				return
			}
			// A keyless Access-Accept is not a safe fallback for OpenConnect. ocserv would
			// then lease from its OWN pool, which spans the very block the panel hands out
			// by account slot, and it registers no lease at all for an explicitly assigned
			// address (ip-lease.c sets ->db only on the pool path), so its duplicate check
			// cannot see the addresses we assign: it can pick one a live device already
			// holds. Two tunnels on one address leaves the older one's return traffic on the
			// newer tun, so it stays "connected" and passes nothing. Such an address is also
			// outside the routing backstop's valid-IP list, so Xray blackholes it anyway.
			if clientIP == nil {
				logger.Infof("RADIUS: auth rejected: no tunnel IP available (pool exhausted?) user=%s nas=%s", username, nasID)
				w.Write(r.Response(radius.CodeAccessReject))
				return
			}
			rfc2865.FramedIPAddress_Set(accept, clientIP)
			// The session was recorded at auth (getClientIP -> allocateBlockIP). ocserv
			// won't drive Acct-Start usefully, so create the nft accounting counters here
			// too, off the lock, otherwise this device's traffic is never counted and
			// account usage/quota enforcement silently no-ops for OpenConnect. Idempotent.
			if err := s.nftService.AddClientAccounting(protocol, clientIP.String()); err != nil {
				logger.Warning("RADIUS: failed to add openconnect nft accounting:", err)
			}
			// Interim accounting is not billing here (nft counters do that): it is the only
			// liveness signal ocserv gives the panel, see handleOcservAcct.
			rfc2869.AcctInterimInterval_Set(accept, rfc2869.AcctInterimInterval(ocInterimInterval))
			logger.Infof("RADIUS: auth accepted (PAP) user=%s nas=%s ip=%v", username, nasID, clientIP)
		} else {
			logger.Infof("RADIUS: auth accepted (PAP) user=%s nas=%s", username, nasID)
		}
		w.Write(accept)
		return
	}

	// MS-CHAPv2 authentication
	if len(challenge) != 16 || len(response) != 50 {
		logger.Infof("RADIUS: auth rejected — bad MS-CHAPv2 lengths (challenge=%d response=%d) user=%s",
			len(challenge), len(response), username)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	ident := response[0]
	peerChallenge := response[2:18]
	peerResponse := response[26:50]

	ntResponse, err := rfc2759.GenerateNTResponse(challenge, peerChallenge, []byte(username), []byte(password))
	if err != nil {
		logger.Warning("RADIUS: GenerateNTResponse failed:", err)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if !bytes.Equal(ntResponse, peerResponse) {
		logger.Debugf("RADIUS: auth rejected — wrong password user=%s nas=%s", username, nasID)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Build Access-Accept with MS-CHAPv2 success + MPPE keys
	accept := r.Response(radius.CodeAccessAccept)

	// Authenticator response (S=... string for client verification)
	authResp, _ := rfc2759.GenerateAuthenticatorResponse(challenge, peerChallenge, ntResponse, []byte(username), []byte(password))
	success := make([]byte, 43)
	success[0] = ident
	copy(success[1:], authResp)
	microsoft.MSCHAP2Success_Add(accept, success)

	// MPPE keys (required for PPTP, harmlessly ignored by L2TP)
	recvKey, _ := rfc3079.MakeKey(ntResponse, []byte(password), false)
	sendKey, _ := rfc3079.MakeKey(ntResponse, []byte(password), true)
	microsoft.MSMPPERecvKey_Add(accept, recvKey)
	microsoft.MSMPPESendKey_Add(accept, sendKey)
	microsoft.MSMPPEEncryptionPolicy_Add(accept, microsoft.MSMPPEEncryptionPolicy_Value_EncryptionRequired)
	// 128-bit only: with "40or128 allowed" the server pppd settles on weak 40-bit
	// MPPE (offers +L -S), which 128-bit-requiring clients (Windows/NM default)
	// reject with "MPPE required but peer negotiation failed".
	microsoft.MSMPPEEncryptionTypes_Add(accept, microsoft.MSMPPEEncryptionTypes_Value_RC4128bitAllowed)

	// Assign deterministic IP so per-user Xray routing works via source IP. A deny
	// means the account is at its User Limit and the strategy is "reject".
	clientIP, deny := s.getClientIP(protocol, inboundId, username, station, nasPort)
	if deny {
		logger.Infof("RADIUS: auth rejected — user-limit reached (strategy=reject) user=%s nas=%s", username, nasID)
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}
	if clientIP != nil {
		rfc2865.FramedIPAddress_Set(accept, clientIP)
	}

	// Request periodic accounting updates (60s minimum for pppd)
	rfc2869.AcctInterimInterval_Set(accept, rfc2869.AcctInterimInterval(60))

	logger.Infof("RADIUS: auth accepted user=%s nas=%s ip=%v", username, nasID, clientIP)
	w.Write(accept)
}

// handleAcct processes RADIUS Accounting-Request packets (Start/Stop/Interim-Update).
func (s *RadiusService) handleAcct(w radius.ResponseWriter, r *radius.Request) {
	statusType := rfc2866.AcctStatusType_Get(r.Packet)
	sessionID := rfc2866.AcctSessionID_GetString(r.Packet)
	username := rfc2865.UserName_GetString(r.Packet)
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	framedIP := rfc2865.FramedIPAddress_Get(r.Packet)

	// Always acknowledge
	defer w.Write(r.Response(radius.CodeAccountingResponse))

	protocol, _, err := parseNASIdentifier(nasID)
	if err != nil {
		logger.Debugf("RADIUS: acct ignored — invalid NAS-Identifier %q", nasID)
		return
	}

	// OpenConnect sessions are CREATED by the AUTH path (see allocateBlockIP), because
	// ocserv's Acct-Start identifies nothing: main opens the accounting session before it
	// leases the tunnel IP, so that packet carries no Framed-IP-Address (and ocserv sends
	// no NAS-Port at all). Its LATER packets do carry one: the worker reports its assigned
	// address with every stats message, which sec-mod copies into the accounting info, so
	// Interim-Update and Stop both name the tunnel IP that keys the session. Those two are
	// the only word the panel ever gets from ocserv about a session it did not just
	// authenticate, so they are handled rather than discarded. The deferred
	// Accounting-Response above still ACKs every packet so ocserv does not retry.
	if protocol == "openconnect" {
		s.handleOcservAcct(statusType, sessionID, username, framedIP)
		return
	}

	switch statusType {
	case rfc2866.AcctStatusType_Value_Start:
		ip := framedIP.String()
		if ip == "<nil>" || ip == "" {
			// NOTE: ocserv's Accounting-Request omits Framed-IP-Address, so OpenConnect
			// sessions are not recorded here and User-Limit accept-eviction has nothing
			// to evict (strategy-accept). A recovery keyed by Calling-Station-Id proved
			// ambiguous when two devices share a station (handed the 2nd device the 1st's
			// IP), so proper tracking needs the auth step to record the session directly.
			logger.Debugf("RADIUS: acct-start missing Framed-IP user=%s", username)
			return
		}

		// Look up email for this username
		email := s.lookupEmail(protocol, username)
		if email == "" {
			logger.Debugf("RADIUS: acct-start no email found for user=%s nas=%s", username, nasID)
			return
		}

		s.mu.Lock()
		s.sessions[sessionID] = &radiusSession{
			email:    email,
			ip:       ip,
			protocol: protocol,
			started:  time.Now(),
		}
		delete(s.pending, ip) // confirmed: the session now holds this block IP
		s.mu.Unlock()

		// Add nft accounting counters for this client
		if err := s.nftService.AddClientAccounting(protocol, ip); err != nil {
			logger.Warning("RADIUS: failed to add nft accounting:", err)
		}

		logger.Infof("RADIUS: acct-start user=%s email=%s ip=%s proto=%s session=%s", username, email, ip, protocol, sessionID)

	case rfc2866.AcctStatusType_Value_Stop:
		s.mu.Lock()
		sess, ok := s.sessions[sessionID]
		if ok {
			delete(s.sessions, sessionID)
		}
		// Whose IP is being stopped, and does ANOTHER live session still own it? Under
		// User-Limit "accept" a freed IP is immediately reassigned to a new device, and
		// the evicted device's Acct-Stop can arrive AFTER the newcomer's Acct-Start (the
		// evicted IKEv2 SA is torn down asynchronously — see allocateBlockIP). Removing
		// the nft counter (or folding+resetting it) on that late stop would wipe the
		// newcomer's accounting → its traffic counts as 0 (the multi-user regression).
		// So if the IP is now held by a different session, this stop is stale: ACK it but
		// touch nothing. The evicting path already folded the old device's bytes.
		stopIP := framedIP.String()
		if ok {
			stopIP = sess.ip
		}
		reassigned := false
		if stopIP != "" && stopIP != "<nil>" {
			for sid, o := range s.sessions {
				if sid != sessionID && o.ip == stopIP && o.protocol == protocol {
					reassigned = true
					break
				}
			}
		}
		s.mu.Unlock()

		if reassigned {
			logger.Infof("RADIUS: acct-stop stale — ip=%s reassigned to a live session, keeping its accounting (user=%s session=%s)", stopIP, username, sessionID)
			return
		}

		if ok {
			// Fold the final counter bytes (accumulated since the last 10s collection)
			// into the client's quota BEFORE the counters are deleted — otherwise a
			// disconnect (or a rapid reconnect) silently drops that traffic, which
			// under-counts usage and under-enforces limits.
			up, down := s.nftService.ReadAndResetClientCounters(sess.protocol, sess.ip)
			foldClientTraffic(sess.email, sess.protocol, up, down)
			// Remove nft accounting counters
			if err := s.nftService.RemoveClientAccounting(sess.protocol, sess.ip); err != nil {
				logger.Warning("RADIUS: failed to remove nft accounting:", err)
			}
			logger.Infof("RADIUS: acct-stop user=%s email=%s ip=%s proto=%s session=%s", username, sess.email, sess.ip, sess.protocol, sessionID)
		} else {
			// Unknown session (e.g. after panel restart) — try cleanup by IP if available
			ip := framedIP.String()
			if ip != "<nil>" && ip != "" {
				s.nftService.RemoveClientAccounting(protocol, ip)
				logger.Infof("RADIUS: acct-stop (orphan) user=%s ip=%s proto=%s session=%s", username, ip, protocol, sessionID)
			} else {
				logger.Debugf("RADIUS: acct-stop unknown session=%s user=%s", sessionID, username)
			}
		}

	case rfc2866.AcctStatusType_Value_InterimUpdate:
		// For L2TP/PPTP we use nft counters, so interim updates are logged but not processed
		logger.Debugf("RADIUS: acct-interim user=%s session=%s", username, sessionID)

		// Re-add session if missing (e.g. after panel restart)
		s.mu.Lock()
		if _, ok := s.sessions[sessionID]; !ok {
			ip := framedIP.String()
			if ip != "<nil>" && ip != "" {
				email := s.lookupEmail(protocol, username)
				if email != "" {
					s.sessions[sessionID] = &radiusSession{
						email:    email,
						ip:       ip,
						protocol: protocol,
						started:  time.Now(),
					}
					s.mu.Unlock()
					s.nftService.AddClientAccounting(protocol, ip)
					logger.Infof("RADIUS: re-added session from interim user=%s email=%s ip=%s", username, email, ip)
					return
				}
			}
		}
		s.mu.Unlock()
	}
}

// handleOcservAcct applies one OpenConnect Accounting-Request to the auth-created
// session at that tunnel IP (see ocSessionKey).
//
//   - Interim-Update is a heartbeat. It is what lets the route-probe sweep stop
//     second-guessing a live tunnel, and it re-adopts a session the panel lost (a
//     restart, or a sweep that ran while the tunnel was still coming up) instead of
//     leaving its address looking free to the next device on the account.
//   - Stop is the authoritative end of the session, and the only prompt one: without it
//     a dead device's address stays occupied until the next 60s sweep notices its route
//     is gone, which both refuses the account's own redial and delays the counters.
//
// A start (no Framed-IP yet) is ignored, as is any packet the panel cannot key.
func (s *RadiusService) handleOcservAcct(statusType rfc2866.AcctStatusType, sessionID, username string, framedIP net.IP) {
	ip := framedIP.String()
	if ip == "" || ip == "<nil>" {
		logger.Debugf("RADIUS: oc acct without Framed-IP ignored user=%s status=%v", username, statusType)
		return
	}
	sid := ocSessionKey(ip)
	now := time.Now()

	switch statusType {
	case rfc2866.AcctStatusType_Value_InterimUpdate:
		s.mu.Lock()
		if sess, ok := s.sessions[sid]; ok {
			sess.heard = now
			sess.acctID = sessionID // whose session this address currently is
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		// Unknown live tunnel: adopt it. The email lookup is a DB read, so it runs off
		// the lock (every RADIUS auth on the box waits behind that mutex).
		email := s.lookupEmail("openconnect", username)
		if email == "" {
			return
		}
		s.mu.Lock()
		if _, exists := s.sessions[sid]; !exists {
			s.sessions[sid] = &radiusSession{email: email, ip: ip, protocol: "openconnect", started: now, heard: now, acctID: sessionID}
		}
		s.mu.Unlock()
		if err := s.nftService.AddClientAccounting("openconnect", ip); err != nil {
			logger.Warning("RADIUS: failed to add openconnect nft accounting:", err)
		}
		logger.Infof("RADIUS: re-added openconnect session from interim user=%s email=%s ip=%s", username, email, ip)

	case rfc2866.AcctStatusType_Value_Stop:
		s.mu.Lock()
		sess, ok := s.sessions[sid]
		if !ok {
			s.mu.Unlock()
			return
		}
		// Under User-Limit "accept" the freed address is handed to the incoming device
		// immediately, so the evicted device's stop can arrive once the newcomer already
		// owns this key. Acting on it would delete a live session and wipe the newcomer's
		// counters (the l2tp Acct-Stop case documents the same hazard). The daemon's own
		// session id settles it whenever the session has been heard from: a stop naming a
		// different one is the predecessor's, and the evicting path has already folded and
		// removed that device's accounting. Before the first interim there is nothing to
		// compare (ocserv's Access-Request carries no session id), so age stands in.
		//
		// A cookie reconnect is deliberately NOT a case here: ocserv refcounts the auth
		// session, so the old worker's close does not reach the accounting module and no
		// stop is sent while the session lives on.
		if sess.acctID != "" && sessionID != "" && sess.acctID != sessionID {
			s.mu.Unlock()
			logger.Infof("RADIUS: oc acct-stop stale: ip=%s belongs to session %s now (stop was for %s)", ip, sess.acctID, sessionID)
			return
		}
		if sess.acctID == "" && now.Sub(sess.started) < ocStaleReclaimGrace {
			s.mu.Unlock()
			logger.Infof("RADIUS: oc acct-stop stale: ip=%s just reassigned, keeping its accounting (user=%s)", ip, username)
			return
		}
		delete(s.sessions, sid)
		s.mu.Unlock()

		// Fold the bytes counted since the last collection before deleting the counters,
		// exactly as the l2tp/pptp Acct-Stop path does.
		up, down := s.nftService.ReadAndResetClientCounters("openconnect", ip)
		foldClientTraffic(sess.email, sess.protocol, up, down)
		if err := s.nftService.RemoveClientAccounting("openconnect", ip); err != nil {
			logger.Warning("RADIUS: failed to remove openconnect nft accounting:", err)
		}
		logger.Infof("RADIUS: oc acct-stop user=%s email=%s ip=%s", username, sess.email, ip)
	}
}

// GetSessions returns an IP→email map for the given protocol, used by traffic collection.
func (s *RadiusService) GetSessions(protocol string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]string)
	for _, sess := range s.sessions {
		if sess.protocol == protocol {
			result[sess.ip] = sess.email
		}
	}
	return result
}

// RadiusService is the rbridge.Sink: the rbridge Sweeper writes reconciled sessions and reads the
// disabled-account set through it, so ownership of the session store stays here in RADIUS.
var _ rbridge.Sink = (*RadiusService)(nil)

// localSessionKey is the s.sessions key for a tunnel reconciled by the rbridge sweep (non-RADIUS
// protocols: ikev2 psk/eap-tls, wireguard, ...). The "cp:<proto>:" prefix keeps it distinct from a
// daemon Acct-Session-Id and from the "oc:" openconnect keys, and namespaces protocols so one
// protocol's reconcile never touches another's sessions.
func localSessionKey(protocol, ip string) string { return "cp:" + protocol + ":" + ip }

// ReconcileLocalSessions replaces the tracked rbridge-managed sessions for one protocol with
// `desired` (tunnel IP -> account email). Newly seen IPs gain an nft accounting counter; vanished
// IPs are folded into client_traffics and their counter removed (mirrors Acct-Stop). Called each
// tick by the rbridge Sweeper. It only touches this protocol's "cp:<proto>:"-keyed sessions, so it
// never disturbs RADIUS-tracked sessions (e.g. ikev2 eap-mschapv2, keyed by Acct-Session-Id).
func (s *RadiusService) ReconcileLocalSessions(protocol string, desired map[string]string) {
	type kv struct{ email, ip string }
	var gone []kv
	var added []string
	prefix := "cp:" + protocol + ":"

	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = make(map[string]*radiusSession)
	}
	for sid, sess := range s.sessions {
		if sess.protocol != protocol || !strings.HasPrefix(sid, prefix) {
			continue
		}
		if _, ok := desired[sess.ip]; !ok {
			gone = append(gone, kv{sess.email, sess.ip})
			delete(s.sessions, sid)
		}
	}
	for ip, email := range desired {
		sid := localSessionKey(protocol, ip)
		if existing, ok := s.sessions[sid]; ok {
			if email != "" {
				existing.email = email
			}
			continue
		}
		s.sessions[sid] = &radiusSession{email: email, ip: ip, protocol: protocol, started: time.Now()}
		added = append(added, ip)
	}
	s.mu.Unlock()

	// Fold + remove counters for vanished IPs OFF the lock (slow nft/db work), same
	// as the Acct-Stop path.
	for _, g := range gone {
		up, down := s.nftService.ReadAndResetClientCounters(protocol, g.ip)
		foldClientTraffic(g.email, protocol, up, down)
		_ = s.nftService.RemoveClientAccounting(protocol, g.ip)
	}
	for _, ip := range added {
		_ = s.nftService.AddClientAccounting(protocol, ip)
	}
}

// DisabledEmails returns the set of accounts currently disabled: a quota/expiry hit or disabled in
// settings (client_traffics.enable = false). It is the rbridge.Sink counterpart of the per-service
// getDisabledEmails helpers.
func (s *RadiusService) DisabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := database.GetDB()
	if db == nil {
		return disabled
	}
	var emails []string
	db.Table("client_traffics").Where("enable = ?", false).Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// GetActiveSessionEmails returns a set of emails with active sessions (for online status).
func (s *RadiusService) GetActiveSessionEmails() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]bool)
	for _, sess := range s.sessions {
		result[sess.email] = true
	}
	return result
}

// lookupClient queries SQLite for the client password. Returns error if client not found,
// disabled, or traffic-limited.
func (s *RadiusService) lookupClient(protocol string, inboundId int, username string) (string, error) {
	db := database.GetDB()

	var inbound model.Inbound
	if inboundId > 0 {
		if err := db.First(&inbound, inboundId).Error; err != nil {
			return "", fmt.Errorf("inbound %d not found", inboundId)
		}
	} else {
		// Protocol-level NAS-Identifier: resolve the account to its inbound by name.
		ib, err := s.findClientInbound(protocol, username)
		if err != nil {
			return "", err
		}
		inbound = *ib
	}

	if !inbound.Enable {
		return "", fmt.Errorf("inbound %d disabled", inboundId)
	}

	if string(inbound.Protocol) != protocol {
		return "", fmt.Errorf("inbound %d protocol mismatch: expected %s got %s", inboundId, protocol, inbound.Protocol)
	}

	// Parse settings to find the client
	type clientEntry struct {
		ID       string `json:"id"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Enable   bool   `json:"enable"`
	}
	type settingsJSON struct {
		Clients []clientEntry `json:"clients"`
	}

	var settings settingsJSON
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return "", fmt.Errorf("failed to parse settings for inbound %d", inboundId)
	}

	for _, client := range settings.Clients {
		if client.ID == username || client.Email == username {
			if !client.Enable {
				return "", fmt.Errorf("client %s disabled in settings", username)
			}

			// Check client_traffics enable (traffic/expiry limits)
			if client.Email != "" {
				var traffic struct{ Enable bool }
				if err := db.Table("client_traffics").
					Select("enable").
					Where("email = ?", client.Email).
					First(&traffic).Error; err == nil && !traffic.Enable {
					return "", fmt.Errorf("client %s traffic limit reached (email=%s)", username, client.Email)
				}
			}

			return client.Password, nil
		}
	}

	return "", fmt.Errorf("client %s not found in inbound %d", username, inboundId)
}

// lookupEmail finds the email for a username across all inbounds of the given protocol.
func (s *RadiusService) lookupEmail(protocol string, username string) string {
	db := database.GetDB()
	var inbounds []*model.Inbound
	db.Where("protocol = ?", protocol).Find(&inbounds)

	type clientEntry struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Slot  *int   `json:"slot"` // address-pool slot; nil = fall back to list index
	}
	type settingsJSON struct {
		Clients []clientEntry `json:"clients"`
	}

	for _, inbound := range inbounds {
		var settings settingsJSON
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if client.ID == username || client.Email == username {
				return client.Email
			}
		}
	}
	return ""
}

// KillSessionsByEmail tears down every active session whose email is in the set. It
// is the teardown the L2TP/PPTP disable paths call, but the session map is SHARED
// across protocols, so it must dispatch by protocol family — SSTP and OpenConnect
// are HYBRID and must NOT be torn down with killPPPByIP:
//   - L2TP/PPTP: kill the owning pppd by pid file (clean Acct-Stop) then delete the
//     ppp interface — the same reliable link teardown the User Limit eviction uses.
//   - SSTP: accel-ppp is ONE daemon per inbound (no per-connection pppd, and deleting
//     its ppp iface would desync the daemon), so evict natively through accel-cmd —
//     the analogue of ocserv's occtl path — routing each IP to the inbound whose
//     daemon holds it (sstpInboundForIP).
//   - OpenConnect: skipped here entirely; ocserv sessions have no ppp interface and
//     their disable/eviction goes through occtl (OcservService.KillClient /
//     killOcservByIP).
func (s *RadiusService) KillSessionsByEmail(emails map[string]bool) {
	s.mu.Lock()
	var toKill []string
	var sstpKill []string
	var ikev2Kill []string
	for _, sess := range s.sessions {
		if sess.protocol == "openconnect" {
			continue
		}
		if emails[sess.email] {
			if sess.protocol == "sstp" {
				sstpKill = append(sstpKill, sess.ip)
			} else if sess.protocol == "ikev2" {
				ikev2Kill = append(ikev2Kill, sess.ip)
			} else {
				toKill = append(toKill, sess.ip)
			}
		}
	}
	s.mu.Unlock()

	for _, ip := range toKill {
		// Graceful first: kill the owning pppd by its pid file (clean shutdown + Acct-Stop).
		// Then force the link down by deleting the interface — belt-and-suspenders, since the
		// pid file may be absent/stale, and deleting the interface guarantees the tunnel drops
		// (this is the same reliable teardown the User Limit eviction uses).
		s.killPppdByIP(ip)
		killPPPByIP(ip)
	}
	// SSTP: native accel-cmd eviction, routed to the accel-pppd instance whose
	// inbound owns the IP's /24. accel-cmd terminate is idempotent, so a session that
	// KillDisabledSessions already reaped is a harmless no-op here.
	for _, ip := range sstpKill {
		if inbound := sstpInboundForIP(ip); inbound != nil {
			_ = (&SstpService{}).KillClientIP(inbound, ip)
		}
	}
	// IKEv2: a single shared charon serves every inbound, so eviction needs no inbound
	// routing — terminate the IKE SA holding this virtual IP via swanctl.
	for _, ip := range ikev2Kill {
		_ = (&Ikev2Service{}).KillClientIP(nil, ip)
	}
}

// sstpInboundForIP returns the SSTP inbound that owns tunnel IP `ip` — the inbound
// whose panel-managed /24 range covers it — so an accel-cmd eviction reaches that
// inbound's own accel-pppd control socket. It is the SSTP analogue of the inboundId
// the ocserv eviction path threads through (killOcservByIP): accel-ppp runs one
// daemon per inbound, so the IP alone can't say which daemon holds it — its /24
// does. nil when no SSTP inbound claims the IP.
func sstpInboundForIP(ip string) *model.Inbound {
	dot := strings.LastIndexByte(ip, '.')
	if dot < 0 {
		return nil
	}
	prefix := ip[:dot] // "10.5.3.7" -> "10.5.3"
	var sstp SstpService
	inbounds, err := sstp.GetSstpInbounds()
	if err != nil {
		return nil
	}
	for _, inbound := range inbounds {
		for _, sub := range sstp.GetSubnetsForInbound(inbound) {
			if sub == prefix {
				return inbound
			}
		}
	}
	return nil
}

// killPppdByIP finds and kills the pppd process that owns the given PPP client IP.
func (s *RadiusService) killPppdByIP(ip string) {
	// Check all ppp interfaces for matching IP
	output, err := exec.Command("ip", "-o", "addr", "show").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, ip) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface := fields[1]
		if !strings.HasPrefix(iface, "ppp") {
			continue
		}
		// Read PID file for this interface
		pidFile := fmt.Sprintf("/var/run/%s.pid", iface)
		pidData, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid := strings.TrimSpace(string(pidData))
		if pid != "" {
			exec.Command("kill", pid).Run()
			logger.Infof("RADIUS: killed pppd pid=%s iface=%s ip=%s", pid, iface, ip)
		}
	}
}

// CleanStaleSessions removes sessions whose PPP interface no longer exists.
//
// Skips "cp:"-keyed sessions: ReconcileLocalSessions owns those, and it already derives them
// each tick from the protocol's own liveness source (WireGuard handshake times, swanctl SAs),
// folding their bytes on the way out. isIPActive cannot judge them anyway: it looks for the
// address on a local interface, but a WireGuard peer's address is never local, and for the
// gateway model sess.ip is a block CIDR ("10.7.1.2/32") rather than a bare address. So every
// wg-c/awg session read as dead on every pass: the sweep re-added it seconds later, and the
// resulting remove/add churn was what let duplicate accounting rules accumulate.
func (s *RadiusService) CleanStaleSessions() {
	s.mu.Lock()
	now := time.Now()
	var stale []string
	for sid, sess := range s.sessions {
		if strings.HasPrefix(sid, "cp:") {
			continue
		}
		if sess.protocol == "openconnect" && !ocProbeReady(sess, now) {
			continue
		}
		if !s.sessionActive(sess) {
			stale = append(stale, sid)
		}
	}
	for _, sid := range stale {
		sess := s.sessions[sid]
		delete(s.sessions, sid)
		s.mu.Unlock()
		// Fold what the counters hold before deleting them, mirroring Acct-Stop:
		// otherwise every session that ends without one (which is every OpenConnect
		// session that did not report a stop) silently drops its last window of traffic.
		up, down := s.nftService.ReadAndResetClientCounters(sess.protocol, sess.ip)
		foldClientTraffic(sess.email, sess.protocol, up, down)
		s.nftService.RemoveClientAccounting(sess.protocol, sess.ip)
		logger.Infof("RADIUS: cleaned stale session=%s email=%s ip=%s", sid, sess.email, sess.ip)
		s.mu.Lock()
	}
	s.mu.Unlock()
}

// ocProbeReady reports whether an OpenConnect session may be judged by the route probe
// yet. Both gates exist because a false "stale" verdict does not merely lose the
// session: it frees the address, which the account's next device is then handed while
// the first one is still using it, and ocserv does not detect a duplicate explicitly
// assigned address (see the auth path). Two tunnels on one address means the kernel
// keeps one route and the other device's return traffic goes to the wrong tun: it stays
// connected and passes nothing, which is only cleared by reconnecting it, which then
// does the same to its twin.
//
//   - Just authenticated: the session is recorded at auth, but ocserv only creates the
//     tun (and thus the route) after the client comes back with its cookie, so the probe
//     reads a false negative until then. allocateBlockIP's own reclaim already waits out
//     this window; the 60s sweep did not, and it is a wall-clock tick that can land
//     anywhere, including inside it.
//   - Recently heard from: an Interim-Update is ocserv itself saying the tunnel is up,
//     which beats anything inferred from the routing table.
func ocProbeReady(sess *radiusSession, now time.Time) bool {
	if now.Sub(sess.started) < ocStaleReclaimGrace {
		return false
	}
	if !sess.heard.IsZero() && now.Sub(sess.heard) < ocHeartbeatGrace {
		return false
	}
	return true
}

// vpnProbeTimeout bounds the helper commands the RADIUS paths shell out to (the
// liveness probe, the occtl eviction). They run while a client's Access-Request is
// waiting and, for the eviction, while s.mu is held, so one that blocks stalls every
// other login on the box. occtl in particular talks to ocserv's MAIN process, which can
// itself be waiting on sec-mod, which is waiting for the very reply we have not written
// yet: the same circular wait the IKEv2 eviction had to be made asynchronous for. A
// missed probe just retries on the next sweep, so failing fast is the cheap side.
const vpnProbeTimeout = 3 * time.Second

// probeCmd runs a short-lived helper command under vpnProbeTimeout and returns its
// stdout.
func probeCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), vpnProbeTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// sessionActive reports whether a tracked session's tunnel is still up, routing
// OpenConnect through the injectable probe (ocActiveFn) so the sweep can be exercised
// without a real ocserv route table.
func (s *RadiusService) sessionActive(sess *radiusSession) bool {
	if sess.protocol == "openconnect" {
		return s.ocIsActive(sess.ip)
	}
	return s.isIPActive(sess.ip, sess.protocol)
}

// isIPActive checks if a VPN client IP is still reachable through its tunnel.
func (s *RadiusService) isIPActive(ip string, protocol string) bool {
	switch protocol {
	case "openvpn":
		// A route to the IP exists through OpenVPN's tun device.
		output, err := probeCmd("ip", "route", "get", ip)
		if err != nil {
			return false // no route = not active
		}
		return strings.Contains(string(output), "tun-ovpn")
	case "openconnect":
		// ocserv client IPs are peers on the ocserv tun (not local addrs), so check
		// for a route through an ocserv device rather than scanning `ip addr show`.
		output, err := probeCmd("ip", "route", "get", ip)
		if err != nil {
			return false
		}
		return strings.Contains(string(output), "ocserv")
	case "ikev2":
		// charon assigns the client's virtual IP as a remote vip (not a local addr),
		// so ask swanctl whether any live IKE SA still holds it.
		return ikev2IPActive(ip)
	default: // l2tp / pptp: the IP is assigned to a local PPP interface
		output, err := exec.Command("ip", "-o", "addr", "show").Output()
		if err != nil {
			return true // assume active on error
		}
		return strings.Contains(string(output), ip)
	}
}

// parseNASIdentifier extracts protocol and inbound ID from a NAS-Identifier.
// Two forms are accepted:
//   - protocol-level, e.g. "l2tp" / "pptp": inboundId is 0, meaning "resolve the
//     account to its owning inbound by username". This is what the shared daemon
//     configs now send — one xl2tpd/pptpd instance serves every inbound of a
//     protocol on its single fixed port, so it can carry only ONE NAS-Identifier.
//   - per-inbound, e.g. "l2tp-3" / "pptp-5": kept for backward compatibility.
func parseNASIdentifier(nasID string) (protocol string, inboundId int, err error) {
	if nasID == "l2tp" || nasID == "pptp" || nasID == "openvpn" || nasID == "openconnect" || nasID == "sstp" || nasID == "ikev2" {
		return nasID, 0, nil
	}

	parts := strings.SplitN(nasID, "-", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid NAS-Identifier format: %s", nasID)
	}

	protocol = parts[0]
	if protocol != "l2tp" && protocol != "pptp" && protocol != "openvpn" && protocol != "openconnect" && protocol != "sstp" && protocol != "ikev2" {
		return "", 0, fmt.Errorf("unknown protocol in NAS-Identifier: %s", protocol)
	}

	_, err = fmt.Sscanf(parts[1], "%d", &inboundId)
	if err != nil {
		return "", 0, fmt.Errorf("invalid inbound ID in NAS-Identifier: %s", nasID)
	}

	return protocol, inboundId, nil
}

// findClientInbound locates the enabled inbound of the given protocol whose
// settings contain a client with this username. Used when the RADIUS request
// carries a protocol-level NAS-Identifier (inboundId 0): a single shared
// xl2tpd/pptpd config serves all inbounds of a protocol, so the account is mapped
// to its owning inbound here rather than via the NAS-Identifier. Usernames are
// expected to be unique across a protocol's inbounds; the first match wins.
func (s *RadiusService) findClientInbound(protocol, username string) (*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ? AND enable = ?", protocol, true).Find(&inbounds).Error; err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		var settings struct {
			Clients []struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			} `json:"clients"`
		}
		if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
			continue
		}
		for _, c := range settings.Clients {
			if c.ID == username || c.Email == username {
				return inbound, nil
			}
		}
	}
	return nil, fmt.Errorf("client %s not found in any %s inbound", username, protocol)
}

// getClientIP computes the deterministic IP for a VPN client. Returns (nil,false)
// if the client is not found or the range is exhausted, and (nil,true) when the
// account is at its User Limit and the strategy is "reject" — the caller must then
// send an Access-Reject rather than a keyless Access-Accept.
func (s *RadiusService) getClientIP(protocol string, inboundId int, username, station string, nasPort uint32) (net.IP, bool) {
	db := database.GetDB()
	var inbound model.Inbound
	if inboundId > 0 {
		if err := db.First(&inbound, inboundId).Error; err != nil {
			return nil, false
		}
	} else {
		// Protocol-level NAS-Identifier: resolve the account to its inbound by name.
		ib, err := s.findClientInbound(protocol, username)
		if err != nil {
			return nil, false
		}
		inbound = *ib
	}

	type clientEntry struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Slot  *int   `json:"slot"` // address-pool slot; nil = fall back to list index
	}
	type settingsJSON struct {
		IpRanges          []string      `json:"ipRanges"`
		IpRange           string        `json:"ipRange"`
		LocalIp           string        `json:"localIp"`
		UserLimit         *int          `json:"userLimit"` // nil = absent (legacy => 1); 0 = no limit
		UserLimitStrategy string        `json:"userLimitStrategy"`
		Clients           []clientEntry `json:"clients"`
	}

	var settings settingsJSON
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return nil, false
	}

	// The account's SLOT, not its position in clients[]: a delete compacts the list, and
	// deriving the address from the position moved every later account (and orphaned the
	// device-lease keys below, which are built from this value).
	clientIndex := -1
	accountSlot := -1
	for i, c := range settings.Clients {
		if c.ID == username || c.Email == username {
			clientIndex, accountSlot = i, slotOr(c.Slot, i)
			break
		}
	}
	if clientIndex < 0 {
		return nil, false
	}

	ranges := settings.IpRanges
	if len(ranges) == 0 && settings.IpRange != "" {
		ranges = []string{settings.IpRange}
	}

	email := settings.Clients[clientIndex].Email

	// User Limit K>=2 (L2TP/PPTP/OpenConnect — OpenVPN ignores the RADIUS Framed-IP and
	// assigns from its own pool in the connect hook): hand out a FREE IP from the
	// account's block so K devices on one account each get a distinct IP. When the
	// block is full the strategy decides: "reject" denies the dial, "accept" evicts
	// the oldest device. K==1 (and OpenVPN) keeps the legacy per-index IP.
	k := effectiveUserLimit(settings.UserLimit)
	if protocol != "openvpn" {
		// Enforce the per-account device cap for EVERY K (>=1). blockIPs is the set of
		// addresses the account may use: K==1 is a ONE-IP block (the legacy deterministic
		// IP), so a 2nd device on the account is rejected/evicted instead of silently
		// sharing the first device's IP (which just breaks routing for one of them).
		// K>=2 is the account's K consecutive device IPs. (OpenVPN doesn't reach here —
		// it authenticates via PAP and enforces the cap in its own client-connect hook.)
		var blockIPs []string
		if k <= 1 {
			if ip := computeVpnClientIP(ranges, inbound.Id, accountSlot, protocol); ip != nil {
				blockIPs = []string{ip.String()}
			}
		} else {
			blockIPs = vpnAccountDeviceIPs(pppSubnetsOrDefault(ranges, protocol, inbound.Id), accountSlot, k)
		}
		if len(blockIPs) == 0 {
			return nil, false
		}
		strategy := normUserLimitStrategy(settings.UserLimitStrategy)
		return s.allocateBlockIP(inbound.Id, accountSlot, blockIPs, protocol, strategy, station, nasPort, email)
	}
	return computeVpnClientIP(ranges, inbound.Id, accountSlot, protocol), false
}

// allocateBlockIP assigns a stable IP inside account `clientIndex`'s K-block (User
// Limit) to the calling device. A device is keyed by (Calling-Station-Id, NAS-Port):
// the NAS-Port (pppd unit) separates distinct devices that share one public IP behind
// a NAT — without it they collapse to one slot and the K cap is bypassed — while a
// redial that reclaims the same freed unit keeps its key and the IP it already holds
// (idempotent), so an unstable/redialing client can't evict itself and reset its
// traffic counter, nor be handed another device's IP. A new device takes a free slot;
// when all K are held the strategy decides — "reject" returns (nil,true) so the caller
// denies, "accept" evicts the account's OLDEST live device. Returns (ip,false) on
// success, (nil,true) on deny.
func (s *RadiusService) allocateBlockIP(inboundId, accountSlot int, blockIPs []string, protocol, strategy, station string, nasPort uint32, email string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = make(map[string]time.Time)
	}
	if s.stationIP == nil {
		s.stationIP = make(map[string]string)
		s.stationSeen = make(map[string]time.Time)
	}
	now := time.Now()

	// This account's device IPs (K of them; K==1 is a single-IP block).
	isBlockIP := make(map[string]bool, len(blockIPs))
	for _, ip := range blockIPs {
		isBlockIP[ip] = true
	}

	// Device key: (protocol, inbound, account, Calling-Station-Id, NAS-Port). The
	// NAS-Port (pppd unit) is what distinguishes two distinct devices on one account
	// behind the same NAT; a redial reclaiming the same freed unit keeps this key.
	skey := ""
	if station != "" {
		skey = fmt.Sprintf("%s:%d:%d:%s:%d", protocol, inboundId, accountSlot, station, nasPort)
	}

	// recordOC records/refreshes an OpenConnect device's session at AUTH (see
	// ocSessionKey). ocserv's Acct-Start can't identify the device (it carries no
	// Framed-IP, and ocserv sends no NAS-Port at all), so this (not handleAcct) is
	// where an OpenConnect session enters s.sessions; handleOcservAcct then keeps it
	// alive and ends it. This is what User-Limit accept-eviction (oldestBlockSession) and
	// traffic attribution (GetSessions) rely on. The transient `pending` lease is the
	// gap between an Access-Accept and its confirming Acct-Start; OpenConnect has no
	// such gap (auth IS the confirmation), so it is cleared here — leaving it would let
	// the ghost-reclaim step below hand a live device's IP to a new one, bypassing the
	// strategy. No-op for l2tp/pptp (their sessions come from Acct-Start with a real
	// Framed-IP) and never reached by OpenVPN. Called under s.mu.
	recordOC := func(ip string) {
		if protocol != "openconnect" {
			return
		}
		delete(s.pending, ip)
		if existing, ok := s.sessions[ocSessionKey(ip)]; ok {
			if email != "" {
				existing.email = email // refresh; keep original `started` for stable evict order
			}
			return
		}
		s.sessions[ocSessionKey(ip)] = &radiusSession{email: email, ip: ip, protocol: protocol, started: now}
	}

	// assign claims ip for this station: it wins the slot, so drop any OTHER station's
	// stale claim on the same ip, record ours, and reserve it (pending) until Acct-Start
	// (OpenConnect confirms immediately via recordOC, which clears the pending lease).
	assign := func(ip string) (net.IP, bool) {
		if skey != "" {
			for key, oip := range s.stationIP {
				if oip == ip && key != skey {
					delete(s.stationIP, key)
					delete(s.stationSeen, key)
				}
			}
			s.stationIP[skey] = ip
			s.stationSeen[skey] = now
		}
		s.pending[ip] = now
		recordOC(ip)
		return net.ParseIP(ip).To4(), false
	}

	if protocol == "openconnect" {
		logger.Debugf("RADIUS: oc alloc idx=%d station=%q nasPort=%d skey=%q block=%v", accountSlot, station, nasPort, skey, blockIPs)
	}

	// IDEMPOTENT REDIAL: a client (by Calling-Station-Id) keeps the block IP it already
	// holds — no eviction, no counter churn. Without this, a device whose CHAP/tunnel
	// flaps re-authenticates every ~1s, is treated as a new device each time, evicts its
	// own prior session (resetting that IP's traffic counter -> "counted delta 0") and
	// can be handed the account's other device's IP (duplicate).
	//
	// OpenConnect is EXCLUDED: it is a PPP-only protection. ocserv sends no NAS-Port
	// (nasPort=0 always), so the skey is just protocol:inbound:idx:Calling-Station-Id —
	// and two devices on one account behind the SAME public IP (two phones on home wifi:
	// the common case) collapse to ONE skey. Idempotent-redial would then hand the 2nd
	// device the 1st's IP instead of a free one / an eviction, so it never gets a routable
	// address (no internet) and the 1st is never evicted — exactly the reported bug.
	// OpenConnect auths once per tunnel (no CHAP flapping), so a fresh free-IP-or-evict
	// allocation per auth is correct and safe.
	//
	// SSTP (accel-ppp) is EXCLUDED for the SAME reason: accel-ppp sends nasPort=0 for
	// every session (verified live — two devices on one account behind ONE NAT collapsed
	// to a single tunnel IP 10.5.2.2), and SSTP auths once per TLS tunnel (no CHAP flap),
	// so it takes the free-IP-or-evict path like OpenConnect, not idempotent-redial.
	if skey != "" && protocol != "openconnect" && protocol != "sstp" && protocol != "ikev2" {
		if ip, ok := s.stationIP[skey]; ok && isBlockIP[ip] {
			s.stationSeen[skey] = now
			s.pending[ip] = now
			recordOC(ip) // openconnect: refresh session, clear the transient pending lease
			return net.ParseIP(ip).To4(), false
		}
	}
	// Prune long-abandoned station claims (client gone for good) so the map can't grow
	// without bound; active clients refresh their timestamp above. Deliberately outside
	// the redial branch: the protocols excluded from it still WRITE these maps in assign,
	// so leaving the prune inside meant an openconnect/sstp/ikev2-only server accumulated
	// an entry per (device, account) forever.
	for key, ts := range s.stationSeen {
		if now.Sub(ts) > pendingLeaseTTL {
			delete(s.stationSeen, key)
			delete(s.stationIP, key)
		}
	}

	// OpenConnect reconcile against ocserv's ground truth. The panel never sees an
	// OpenConnect disconnect (Acct is ignored — the session is auth-managed), so a
	// dead device's oc: session lingers until the periodic CleanStaleSessions sweep.
	// Left in place it wrongly OCCUPIES a block slot: a genuine RE-DIAL of the same
	// device (same skey, now with idempotent-redial disabled) would be rejected as
	// "block full", and occupancy is inflated. So before deciding, drop this account's
	// block sessions whose IP no longer routes through an ocserv device — i.e. the
	// tunnel is gone. A truly-live device (a real 2nd device on the account) still
	// routes via ocserv, stays counted, and keeps the K cap honest. Only IPs that
	// actually hold a session are probed, so this is at most K-devices `ip route get`s.
	if protocol == "openconnect" {
		for _, ip := range blockIPs {
			sid := ocSessionKey(ip)
			sess, ok := s.sessions[sid]
			if !ok {
				continue
			}
			// Don't reclaim a session still establishing (its ocserv route may not be in
			// the kernel yet) or one ocserv has just reported alive: in both cases the
			// probe reads a false negative and we would free a live device's IP, which
			// hands the account's next device an address already in use. See
			// ocProbeReady. Only past those does "no ocserv route" mean the tunnel is
			// genuinely gone.
			if !ocProbeReady(sess, now) {
				continue
			}
			if !s.ocIsActive(ip) {
				delete(s.sessions, sid)
				s.nftService.RemoveClientAccounting("openconnect", ip)
				logger.Debugf("RADIUS: oc reclaimed stale block IP %s (ocserv tunnel gone)", ip)
			}
		}
	}

	// Real occupancy = live session IPs + still-valid pending allocations (a lingering
	// station claim with no session/pending does NOT block a new device). Expired
	// pending leases (auth without a following Acct-Start) are reclaimed here.
	used := make(map[string]bool, len(s.sessions)+len(s.pending))
	for _, sess := range s.sessions {
		used[sess.ip] = true
	}
	for ip, ts := range s.pending {
		if now.Sub(ts) > pendingLeaseTTL {
			delete(s.pending, ip)
			continue
		}
		used[ip] = true
	}

	// (1) A free slot for this new device.
	blockSet := make(map[string]bool, len(blockIPs))
	for _, ip := range blockIPs {
		blockSet[ip] = true
		if !used[ip] {
			return assign(ip)
		}
	}

	// (2) Reclaim the OLDEST abandoned gap-lease (pending older than the grace) before
	// evicting/denying. A fresh in-flight dial (younger than the grace) and a live
	// session (never in s.pending — cleared at Acct-Start) are both left untouched.
	var ghostIP string
	var ghostTS time.Time
	for _, ip := range blockIPs {
		if ts, ok := s.pending[ip]; ok && now.Sub(ts) > pendingReclaimGrace {
			if ghostIP == "" || ts.Before(ghostTS) {
				ghostIP, ghostTS = ip, ts
			}
		}
	}
	if ghostIP != "" {
		return assign(ghostIP)
	}

	// (3) Block full. "accept": evict the account's oldest live device and reuse its IP.
	if strategy == "accept" {
		if victimSID, victimIP := oldestBlockSession(s.sessions, blockSet); victimIP != "" {
			victim := s.sessions[victimSID]
			delete(s.sessions, victimSID)
			// Fold the evicted device's final counter bytes into its quota BEFORE deleting
			// the nft counters — same as the Acct-Stop path (see handleAcct) — otherwise
			// eviction silently drops the traffic accumulated since the last 10s collection.
			// Under a redial storm (pptp CHAP churn re-keys the same device to a new NAS-Port,
			// tripping this evict-and-readmit repeatedly) that lost traffic zeroes out real
			// usage — the pptp multi-user "counted 0" bug. Folding first can't over-count:
			// ReadAndResetClientCounters zeroes the counter, so the readmit starts from 0.
			if victim != nil && victim.email != "" {
				up, down := s.nftService.ReadAndResetClientCounters(protocol, victimIP)
				foldClientTraffic(victim.email, victim.protocol, up, down)
			}
			s.nftService.RemoveClientAccounting(protocol, victimIP)
			// Force the old device's link down. L2TP/PPTP delete the ppp interface;
			// ocserv has no ppp iface, so disconnect via occtl; SSTP is a single
			// accel-ppp daemon (no per-connection pppd), so disconnect via accel-cmd.
			// inboundId is this account's inbound — the one whose daemon holds victimIP.
			if protocol == "openconnect" {
				killOcservByIP(inboundId, victimIP)
			} else if protocol == "sstp" {
				_ = (&SstpService{}).KillClientIP(&model.Inbound{Id: inboundId}, victimIP)
			} else if protocol == "ikev2" {
				// A single shared charon serves every inbound — terminate by virtual IP,
				// ASYNCHRONOUSLY. The kill MUST NOT run inside this RADIUS auth handler:
				// killIkev2ByIP calls `swanctl --list-sas`, and while THIS device's own
				// IKE_SA is mid-authentication (its charon worker thread is blocked in
				// eap-radius waiting for the very Access-Accept we're about to return),
				// list-sas blocks on that checked-out SA until charon's RADIUS retransmit
				// gives up (~14s) — a circular wait through charon's SA-manager lock that
				// fails the new device. Returning first lets charon finish this handshake
				// and release the SA; the goroutine's list-sas is then instant. It targets
				// the OLDEST SA on the IP (killIkev2ByIP → lowest unique-id), so the just-
				// admitted new device (higher id, briefly sharing the reused vip) is safe.
				go (&Ikev2Service{}).KillClientIP(nil, victimIP)
			} else {
				killPPPByIP(victimIP)
			}
			logger.Infof("RADIUS: user-limit accept — evicted oldest device ip=%s proto=%s to admit new device", victimIP, protocol)
			return assign(victimIP)
		}
		// No live device to evict (all slots pending/mid-handshake) — deny for now.
	}

	// "reject" (default) or nothing evictable: deny the dial.
	return nil, true
}

// oldestBlockSession returns the (session id, IP) of the longest-connected live
// session whose IP falls inside blockIPs (one account's K device IPs), or ("","")
// when none do. Pure selection — the eviction side effects (nft/kill/pending) are
// the caller's.
func oldestBlockSession(sessions map[string]*radiusSession, blockIPs map[string]bool) (sid, ip string) {
	var started time.Time
	for id, sess := range sessions {
		if !blockIPs[sess.ip] {
			continue
		}
		if sid == "" || sess.started.Before(started) {
			sid, ip, started = id, sess.ip, sess.started
		}
	}
	return sid, ip
}

// killPPPByIP force-disconnects an L2TP/PPTP device by deleting the PPP interface
// whose peer address is ip (freeing the tunnel IP). The supervising daemon reaps
// the orphaned pppd. Best-effort: any lookup/exec error is ignored.
func killPPPByIP(ip string) {
	out, err := exec.Command("ip", "-o", "addr", "show").Output()
	if err != nil {
		return
	}
	needle := "peer " + ip + "/"
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface := strings.TrimSuffix(fields[1], ":") // "3: ppp0 ..." -> "ppp0"
		if !strings.HasPrefix(iface, "ppp") {
			continue
		}
		_ = exec.Command("ip", "link", "delete", iface).Run()
		return
	}
}

// computeVpnClientIP computes the deterministic IP for the L2TP/PPTP client at
// the given index by walking the inbound's ranges in order: the client lives in
// the range whose cumulative capacity first exceeds the index. Returns nil only
// when the index exceeds the total capacity of every range (the normalizer keeps
// capacity ahead of the client count so this should not happen in practice).
func computeVpnClientIP(ranges []string, inboundId, clientIndex int, protocol string) net.IP {
	if len(ranges) == 0 {
		ranges = []string{defaultRange(fmt.Sprintf("10.%d.%d", protocolBase(protocol), inboundId))}
	}

	remaining := clientIndex
	for _, r := range ranges {
		start, end, ok := parseRange(r)
		if !ok {
			continue
		}
		capacity := int(end[3]) - int(start[3]) + 1
		if remaining < capacity {
			ip := make(net.IP, 4)
			copy(ip, start)
			ip[3] += byte(remaining)
			return ip
		}
		remaining -= capacity
	}
	return nil
}

// ResetAllocations drops the RADIUS service's cached per-device IP assignments for
// a protocol (keys are "protocol:inboundId:..."). Call it when an inbound's
// settings change — User Limit, IP ranges, or strategy — because those shift the
// account block layout: an account's device IPs move, and the routing map is
// re-translated to the new IPs. A device that kept its OLD cached IP (via the
// idempotent-redial cache) would then land on an address the new source-IP routing
// rules don't cover, so its traffic isn't routed — the classic "the UI change
// wasn't honored" symptom. Clearing the cache makes each device re-allocate under
// the new layout on its next dial (l2tp/pptp restart the shared daemon here, so
// every device redials anyway). Only the IP caches are touched; live sessions and
// nft accounting counters are left intact.
func ResetAllocations(protocol string) {
	s := runningRadius
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := protocol + ":"
	for k := range s.stationIP {
		if strings.HasPrefix(k, prefix) {
			delete(s.stationIP, k)
		}
	}
	for k := range s.stationSeen {
		if strings.HasPrefix(k, prefix) {
			delete(s.stationSeen, k)
		}
	}
	// Pending leases are keyed by IP (not by protocol) and live only seconds; drop
	// them all so no stale pre-change lease pins an address under the old layout.
	s.pending = map[string]time.Time{}
}

// BuildVpnEmailToIPMap returns a map of email → deterministic tunnel IP(s) for all
// enabled L2TP/PPTP/OpenVPN clients. Used by the Xray config generator to translate
// email-based routing rules into source-IP rules. Values are slices: an OpenVPN
// client maps to one IP per enabled transport, and under User Limit K>=2 every
// account maps to its K device IPs (times the enabled transports for OpenVPN).
func BuildVpnEmailToIPMap() map[string][]string {
	result := make(map[string][]string)
	db := database.GetDB()
	if db == nil {
		return result
	}

	type clientEntry struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Slot  *int   `json:"slot"` // address-pool slot; nil = fall back to list index
	}

	// --- L2TP / PPTP / OpenConnect / SSTP: single-network block, one IP (or K device
	// IPs) per account. OpenConnect shares this model (contiguous 10.4 block, no
	// mirror); SSTP is PPP-family (10.5, arbitrary /24 list like pptp). Their
	// per-index/per-block IPs come out of computeVpnClientIP/vpnAccountDeviceIPs keyed
	// on protocolBase(protocol), identical to the ppp path. ---
	var pppInbounds []*model.Inbound
	db.Where("protocol IN ? AND enable = ?", []string{"l2tp", "pptp", "openconnect", "sstp", "ikev2", "wg-c", "awg", "gre"}, true).Find(&pppInbounds)

	type pppSettingsJSON struct {
		IpRanges  []string      `json:"ipRanges"`
		IpRange   string        `json:"ipRange"`
		UserLimit *int          `json:"userLimit"` // nil = absent (legacy => 1); 0 = no limit
		AuthMode  string        `json:"authMode"`  // ikev2 only: psk/eap-tls = one local-auth account
		Clients   []clientEntry `json:"clients"`
	}

	for _, inbound := range pppInbounds {
		var settings pppSettingsJSON
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		ranges := settings.IpRanges
		if len(ranges) == 0 && settings.IpRange != "" {
			ranges = []string{settings.IpRange}
		}
		k := effectiveUserLimit(settings.UserLimit)
		// K>=2: each account maps to its K device IPs, so one source rule (an
		// explicit IP list) covers every device. K==1 keeps the legacy single IP.
		subnets := pppSubnetsOrDefault(ranges, string(inbound.Protocol), inbound.Id)
		for i, client := range settings.Clients {
			if client.Email == "" {
				continue
			}
			slot := slotOr(client.Slot, i) // stored slot, not list position
			// ikev2 psk / eap-tls: one local-auth account whose devices lease from a
			// whole-block charon pool. Map it to the entire block CIDR so any pool
			// address routes through Xray instead of hitting the vpnAddrSpace
			// blackhole; the reconcile sweep enforces the real device count.
			if string(inbound.Protocol) == "ikev2" && (settings.AuthMode == "psk" || settings.AuthMode == "eap-tls") {
				if bn, prefix := vpnBlock(ranges, protocolBase("ikev2"), inbound.Id); bn != nil {
					result[client.Email] = append(result[client.Email], fmt.Sprintf("%s/%d", bn.String(), prefix))
				}
				continue
			}
			// WireGuard (C) gateway model: the account owns ONE aligned block (a /29-style
			// CIDR); route its whole CIDR (matches wgcAccountBlock) so every IP the router
			// hands out behind the single link flows through Xray.
			if string(inbound.Protocol) == "wg-c" || string(inbound.Protocol) == "awg" || string(inbound.Protocol) == "gre" {
				// WireGuard (C) / AmneziaWG size the account block with gateway semantics
				// (User Limit 0 = the full 64-device /26), which differs from the shared k above.
				wk := wgcEffectiveK(settings.UserLimit)
				if wk <= 1 {
					if ip := computeVpnClientIP(ranges, inbound.Id, slot, string(inbound.Protocol)); ip != nil {
						result[client.Email] = append(result[client.Email], ip.String()+"/32")
					}
				} else {
					bs := nextPow2(wk)
					if subnet, hostBase, ok := vpnAccountBlock(subnets, slot, bs); ok {
						result[client.Email] = append(result[client.Email], fmt.Sprintf("%s.%d/%d", subnet, hostBase, 32-log2i(bs)))
					}
				}
				continue
			}
			if k <= 1 {
				if ip := computeVpnClientIP(ranges, inbound.Id, slot, string(inbound.Protocol)); ip != nil {
					result[client.Email] = append(result[client.Email], ip.String())
				}
			} else {
				result[client.Email] = append(result[client.Email], vpnAccountDeviceIPs(subnets, slot, k)...)
			}
		}
	}

	// --- OpenVPN: one deterministic CCD IP per enabled transport block ---
	var ovpnInbounds []*model.Inbound
	db.Where("protocol = ? AND enable = ?", "openvpn", true).Find(&ovpnInbounds)

	for _, inbound := range ovpnInbounds {
		var settings openvpnSettings
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		udpOn := settings.udpEnabled()
		tcpOn := settings.tcpEnabled()
		k := effectiveUserLimit(settings.UserLimit)
		var udpNet, tcpNet net.IP
		var udpPrefix, tcpPrefix int
		if udpOn {
			udpNet, udpPrefix = ovpnBlockFor(inbound, &settings, "udp")
		}
		if tcpOn {
			tcpNet, tcpPrefix = ovpnBlockFor(inbound, &settings, "tcp")
		}
		// K>=2: per-account device IP lists (one block per enabled transport). K==1
		// keeps the legacy single continuous per-index IP per transport.
		udpSubnets := ovpnSubnetsOrDefault(&settings, "udp", inbound.Id)
		tcpSubnets := ovpnSubnetsOrDefault(&settings, "tcp", inbound.Id)
		for i, client := range settings.Clients {
			if client.Email == "" {
				continue
			}
			slot := slotOr(client.Slot, i) // stored slot, not list position
			if k <= 1 {
				if udpOn {
					if ip := ovpnBlockClientIP(udpNet, udpPrefix, slot); ip != "" {
						result[client.Email] = append(result[client.Email], ip)
					}
				}
				if tcpOn {
					if ip := ovpnBlockClientIP(tcpNet, tcpPrefix, slot); ip != "" {
						result[client.Email] = append(result[client.Email], ip)
					}
				}
				continue
			}
			if udpOn {
				result[client.Email] = append(result[client.Email], vpnAccountDeviceIPs(udpSubnets, slot, k)...)
			}
			if tcpOn {
				result[client.Email] = append(result[client.Email], vpnAccountDeviceIPs(tcpSubnets, slot, k)...)
			}
		}
	}

	return result
}

// pppSubnetsOrDefault returns the ordered /24 prefixes ("A.B.C") an L2TP/PPTP
// inbound owns, falling back to the legacy id-derived /24 when none are stored.
func pppSubnetsOrDefault(ranges []string, proto string, id int) []string {
	if subs := subnetsOf(ranges); len(subs) > 0 {
		return subs
	}
	return []string{fmt.Sprintf("10.%d.%d", protocolBase(proto), id)}
}

// ovpnSubnetsOrDefault returns the ordered /24 prefixes for an OpenVPN transport
// (udp => 10.2.x, tcp => 10.3.x mirror), falling back to the legacy id-derived
// /24 when no ranges are stored.
func ovpnSubnetsOrDefault(settings *openvpnSettings, proto string, id int) []string {
	subs := subnetsOf(settings.effectiveRanges())
	if len(subs) == 0 {
		second := 2
		if proto == "tcp" {
			second = 3
		}
		return []string{fmt.Sprintf("10.%d.%d", second, id)}
	}
	if proto == "tcp" {
		out := make([]string, len(subs))
		for i, s := range subs {
			out[i] = mirrorOvpnSubnet(s)
		}
		return out
	}
	return subs
}

// GenerateRadiusClientConfig writes the radcli config file for a protocol. One
// shared xl2tpd/pptpd instance serves EVERY inbound of a protocol on its single
// fixed port, so there is one radcli config per protocol (not per inbound), at
// /etc/ppp/radius/{protocol}.conf, carrying a protocol-level nas_identifier
// ({protocol}). The RADIUS server then resolves each account to its owning inbound
// by username (see findClientInbound). Also writes the shared servers file and a
// self-contained dictionary with Microsoft VSAs (pppd's static radiusclient parser
// uses INCLUDE not $INCLUDE, so we can't rely on /etc/radcli/dictionary).
func GenerateRadiusClientConfig(protocol string, secret string) error {
	dir := "/etc/ppp/radius"
	os.MkdirAll(dir, 0755)

	// Create empty mapfile (port-id-map) if it doesn't exist — required by libradcli
	mapFile := dir + "/port-id-map"
	if _, err := os.Stat(mapFile); os.IsNotExist(err) {
		os.WriteFile(mapFile, []byte(""), 0644)
	}

	// Generate self-contained dictionary (written once, same content every time)
	if err := generateRadiusDictionary(dir); err != nil {
		return fmt.Errorf("failed to write dictionary: %w", err)
	}

	// Per-protocol config (shared by all inbounds of that protocol).
	seqFile := fmt.Sprintf("/var/run/radius-%s.seq", protocol)
	config := fmt.Sprintf(`# Auto-generated by pro-ui RADIUS — do not edit
authserver	127.0.0.1:1812
acctserver	127.0.0.1:1813
servers		%s/servers
dictionary	%s/dictionary
mapfile		%s/port-id-map
nas_identifier	%s
radius_timeout	5
radius_retries	3
seqfile		%s
`, dir, dir, dir, protocol, seqFile)

	configPath := fmt.Sprintf("%s/%s.conf", dir, protocol)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	// Shared servers file
	servers := fmt.Sprintf("127.0.0.1\t%s\n", secret)
	return os.WriteFile(dir+"/servers", []byte(servers), 0600)
}

// cleanupLegacyPerInboundFiles removes stale per-inbound PPP options and radcli
// config files left by the previous layout (one set per inbound), now that a single
// shared set is used per protocol. Best-effort: unreferenced leftovers are harmless,
// but removing them keeps /etc/ppp tidy across an upgrade. optionsPrefix is the PPP
// options basename ("options.xl2tpd" or "pptpd-options"); the shared file (no "-N"
// suffix) is not matched by the "-*" globs, so it is preserved.
func cleanupLegacyPerInboundFiles(optionsPrefix, protocol string) {
	for _, pattern := range []string{
		"/etc/ppp/" + optionsPrefix + "-*",
		"/etc/ppp/radius/" + protocol + "-*.conf",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, f := range matches {
			_ = os.Remove(f)
		}
	}
}

// generateRadiusDictionary writes a self-contained RADIUS dictionary at dir/dictionary.
// Includes standard RFC 2865/2866 attributes + Microsoft VSAs for MS-CHAPv2 + MPPE.
// This avoids depending on /etc/radcli/dictionary which uses $INCLUDE syntax
// that pppd's statically linked radiusclient parser cannot parse.
func generateRadiusDictionary(dir string) error {
	dict := `# Auto-generated by pro-ui — RADIUS dictionary for pppd
# Standard RADIUS attributes (RFC 2865)
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	User-Password		2	string
ATTRIBUTE	CHAP-Password		3	string
ATTRIBUTE	NAS-IP-Address		4	ipaddr
ATTRIBUTE	NAS-Port		5	integer
ATTRIBUTE	Service-Type		6	integer
ATTRIBUTE	Framed-Protocol		7	integer
ATTRIBUTE	Framed-IP-Address	8	ipaddr
ATTRIBUTE	Framed-IP-Netmask	9	ipaddr
ATTRIBUTE	Framed-Routing		10	integer
ATTRIBUTE	Filter-Id		11	string
ATTRIBUTE	Framed-MTU		12	integer
ATTRIBUTE	Framed-Compression	13	integer
ATTRIBUTE	Reply-Message		18	string
ATTRIBUTE	State			24	string
ATTRIBUTE	Class			25	string
ATTRIBUTE	Session-Timeout		27	integer
ATTRIBUTE	Idle-Timeout		28	integer
ATTRIBUTE	Called-Station-Id	30	string
ATTRIBUTE	Calling-Station-Id	31	string
ATTRIBUTE	NAS-Identifier		32	string
ATTRIBUTE	Acct-Status-Type	40	integer
ATTRIBUTE	Acct-Delay-Time		41	integer
ATTRIBUTE	Acct-Input-Octets	42	integer
ATTRIBUTE	Acct-Output-Octets	43	integer
ATTRIBUTE	Acct-Session-Id		44	string
ATTRIBUTE	Acct-Authentic		45	integer
ATTRIBUTE	Acct-Session-Time	46	integer
ATTRIBUTE	Acct-Input-Packets	47	integer
ATTRIBUTE	Acct-Output-Packets	48	integer
ATTRIBUTE	Acct-Terminate-Cause	49	integer
ATTRIBUTE	Acct-Multi-Session-Id	50	string
ATTRIBUTE	Acct-Link-Count		51	integer
ATTRIBUTE	Acct-Input-Gigawords	52	integer
ATTRIBUTE	Acct-Output-Gigawords	53	integer
ATTRIBUTE	Event-Timestamp		55	integer
ATTRIBUTE	CHAP-Challenge		60	string
ATTRIBUTE	NAS-Port-Type		61	integer
# ocserv (radcli) builds its Access-Request with these attributes too. radcli's
# rc_avpair_new fails hard ("no attribute 0/N in dictionary") on any it can't find,
# so the request is never constructed or sent and every OpenConnect login 401s.
# Connect-Info (77, the client's user-agent) is the one ocserv ALWAYS adds — its
# absence here was the OpenConnect auth bug. Harmless extra defs for the pppd path.
ATTRIBUTE	Vendor-Specific		26	string
ATTRIBUTE	Tunnel-Client-Endpoint	66	string
ATTRIBUTE	Connect-Info		77	string
ATTRIBUTE	NAS-Port-Id		87	string
ATTRIBUTE	Acct-Interim-Interval	85	integer

# Microsoft vendor-specific attributes (RFC 2548)
VENDOR		Microsoft	311

ATTRIBUTE	MS-CHAP-Response	1	string	Microsoft
ATTRIBUTE	MS-CHAP-Error		2	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-1		3	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-2		4	string	Microsoft
ATTRIBUTE	MS-CHAP-LM-Enc-PW	5	string	Microsoft
ATTRIBUTE	MS-CHAP-NT-Enc-PW	6	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Policy 7	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Type	8	string	Microsoft
ATTRIBUTE	MS-CHAP-Challenge	11	string	Microsoft
ATTRIBUTE	MS-CHAP-MPPE-Keys	12	string	Microsoft
ATTRIBUTE	MS-MPPE-Send-Key	16	string	Microsoft
ATTRIBUTE	MS-MPPE-Recv-Key	17	string	Microsoft
ATTRIBUTE	MS-CHAP2-Response	25	string	Microsoft
ATTRIBUTE	MS-CHAP2-Success	26	string	Microsoft
`
	return os.WriteFile(dir+"/dictionary", []byte(dict), 0644)
}
