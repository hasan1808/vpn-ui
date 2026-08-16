package service

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"

	"github.com/op/go-logging"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// capRW captures the response packet handleAuth writes, so a test can assert on it
// without opening a real UDP socket.
type capRW struct{ resp *radius.Packet }

func (c *capRW) Write(p *radius.Packet) error { c.resp = p; return nil }

// TestHandleAuthOpenconnectPAP drives the panel's RADIUS auth handler with exactly
// the request ocserv/radcli is expected to send for an OpenConnect login: a PAP
// Access-Request (User-Name + User-Password) with NAS-Identifier "openconnect-<id>".
// It asserts the panel returns Access-Accept AND pins the tunnel IP via
// Framed-IP-Address — the reply ocserv needs (predictable-ips=false, RADIUS-
// authoritative). Reproduces the E2E "401 Authentication failed" on the panel side,
// with no VM/ocserv/client, so the reject reason is visible in seconds.
func TestHandleAuthOpenconnectPAP(t *testing.T) {
	logger.InitLogger(logging.DEBUG)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	// An OpenConnect inbound with one account, shaped exactly like the panel/E2E
	// store it (clients[] with id/password/email/enable; empty email skips the
	// client_traffics limit check).
	settings := `{"clients":[{"id":"ocuser","password":"ocpass","email":"","enable":true}],"ipRanges":[],"userLimit":1,"userLimitStrategy":"accept"}`
	ib := &model.Inbound{
		Enable:   true,
		Port:     4443,
		Protocol: model.OPENCONNECT,
		Settings: settings,
		Tag:      "inbound-openconnect-4443",
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	t.Logf("inbound id=%d protocol=%s", ib.Id, ib.Protocol)

	const secret = "testsecret"
	s := &RadiusService{
		sessions:    map[string]*radiusSession{},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		ocActiveFn:  func(string) bool { return true },
		secret:      []byte(secret),
	}

	// Craft the PAP Access-Request ocserv sends.
	pkt := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2865.UserName_SetString(pkt, "ocuser")
	rfc2865.UserPassword_SetString(pkt, "ocpass")
	rfc2865.NASIdentifier_SetString(pkt, "openconnect-"+itoa(ib.Id))
	rfc2865.CallingStationID_SetString(pkt, "203.0.113.50")

	w := &capRW{}
	s.handleAuth(w, &radius.Request{Packet: pkt})

	if w.resp == nil {
		t.Fatal("handler wrote no response")
	}
	framed := rfc2865.FramedIPAddress_Get(w.resp)
	t.Logf("RESULT: code=%v framed-ip=%v", w.resp.Code, framed)

	if w.resp.Code != radius.CodeAccessAccept {
		t.Fatalf("openconnect PAP got %v, want Access-Accept — panel is REJECTING a valid login", w.resp.Code)
	}
	if framed == nil {
		t.Fatalf("Access-Accept carries NO Framed-IP-Address — ocserv (predictable-ips=false) cannot assign a tunnel IP")
	}
}

// TestHandleAuthOpenconnectNoIPRejects asserts the panel never answers an OpenConnect
// login with a keyless Access-Accept.
//
// ocserv reads a reply with no Framed-IP-Address as "lease from your own pool", and that
// pool spans the same block the panel hands out by account slot while ocserv registers
// no lease for an explicitly assigned address at all: the address it picks can be one a
// live device is already using, and neither side detects it. The older tunnel then keeps
// its connection and loses its traffic (the kernel routes that address to the newer
// tun). Refusing the login is the only safe answer.
func TestHandleAuthOpenconnectNoIPRejects(t *testing.T) {
	logger.InitLogger(logging.DEBUG)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	// One account whose stored slot is past the inbound's address capacity (a single /24
	// holds 253), so the allocator can compute no tunnel IP for it.
	settings := `{"clients":[{"id":"ocuser","password":"ocpass","email":"","enable":true,"slot":300}],"ipRanges":[],"userLimit":1,"userLimitStrategy":"reject"}`
	ib := &model.Inbound{
		Enable:   true,
		Port:     4444,
		Protocol: model.OPENCONNECT,
		Settings: settings,
		Tag:      "inbound-openconnect-4444",
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	const secret = "testsecret"
	s := &RadiusService{
		sessions:    map[string]*radiusSession{},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		ocActiveFn:  func(string) bool { return true },
		secret:      []byte(secret),
	}

	pkt := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2865.UserName_SetString(pkt, "ocuser")
	rfc2865.UserPassword_SetString(pkt, "ocpass")
	rfc2865.NASIdentifier_SetString(pkt, "openconnect-"+itoa(ib.Id))
	rfc2865.CallingStationID_SetString(pkt, "203.0.113.50")

	w := &capRW{}
	s.handleAuth(w, &radius.Request{Packet: pkt})

	if w.resp == nil {
		t.Fatal("handler wrote no response")
	}
	if w.resp.Code == radius.CodeAccessAccept && rfc2865.FramedIPAddress_Get(w.resp) == nil {
		t.Fatal("keyless Access-Accept: ocserv will lease from its own pool and can duplicate a live device's tunnel IP")
	}
	if w.resp.Code != radius.CodeAccessReject {
		t.Fatalf("got %v, want Access-Reject when no tunnel IP can be assigned", w.resp.Code)
	}
}

// ocAcctPacket builds the Accounting-Request ocserv sends for a live session: its
// per-inbound NAS-Identifier, the username, ocserv's own session id, and the tunnel IP
// the worker reported (which Acct-Start lacks but Interim-Update and Stop carry).
func ocAcctPacket(secret, acctID, username, ip string, status rfc2866.AcctStatusType) *radius.Packet {
	pkt := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(pkt, status)
	rfc2866.AcctSessionID_SetString(pkt, acctID)
	rfc2865.UserName_SetString(pkt, username)
	rfc2865.NASIdentifier_SetString(pkt, "openconnect-1")
	rfc2865.FramedIPAddress_Set(pkt, net.ParseIP(ip).To4())
	return pkt
}

// TestOcservAcctStopEndsSession asserts an OpenConnect Acct-Stop retires the session it
// names, and that a stop naming an address that was just reassigned does not.
//
// Without the first half the panel learns of a disconnect only from the 60s route-probe
// sweep, so the device's address stays occupied: the account's own redial is refused as
// "block full" under the reject strategy. Without the second half, an evicted device's
// late stop deletes the session and accounting of the device that just took its address.
func TestOcservAcctStopEndsSession(t *testing.T) {
	const secret = "testsecret"
	s := &RadiusService{
		sessions: map[string]*radiusSession{
			ocSessionKey("10.4.1.2"): {email: "alice@t", ip: "10.4.1.2", protocol: "openconnect", started: time.Now().Add(-time.Hour), acctID: "ocsid-alice"},
			// Just took this address from an evicted device, and has not been heard from.
			ocSessionKey("10.4.1.3"): {email: "bob@t", ip: "10.4.1.3", protocol: "openconnect", started: time.Now()},
			// Long-lived, and ocserv has named it: a stop for any other session id on this
			// address is its predecessor's, however late it arrives.
			ocSessionKey("10.4.1.4"): {email: "dave@t", ip: "10.4.1.4", protocol: "openconnect", started: time.Now().Add(-time.Hour), acctID: "ocsid-dave"},
		},
		pending: map[string]time.Time{},
		secret:  []byte(secret),
	}

	s.handleAcct(&capRW{}, &radius.Request{Packet: ocAcctPacket(secret, "ocsid-alice", "alice", "10.4.1.2", rfc2866.AcctStatusType_Value_Stop)})
	if _, ok := s.sessions[ocSessionKey("10.4.1.2")]; ok {
		t.Fatal("acct-stop left the session in place: its address stays occupied until the route sweep notices")
	}

	s.handleAcct(&capRW{}, &radius.Request{Packet: ocAcctPacket(secret, "ocsid-old", "bob", "10.4.1.3", rfc2866.AcctStatusType_Value_Stop)})
	if sess := s.sessions[ocSessionKey("10.4.1.3")]; sess == nil || sess.email != "bob@t" {
		t.Fatalf("a stale acct-stop removed the live session that had just taken 10.4.1.3: %+v", sess)
	}

	s.handleAcct(&capRW{}, &radius.Request{Packet: ocAcctPacket(secret, "ocsid-predecessor", "dave", "10.4.1.4", rfc2866.AcctStatusType_Value_Stop)})
	if sess := s.sessions[ocSessionKey("10.4.1.4")]; sess == nil || sess.email != "dave@t" {
		t.Fatalf("a predecessor's acct-stop removed the live session holding 10.4.1.4: %+v", sess)
	}
}

// TestCleanStaleSessionsSparesLiveOcservSessions is the regression test for the sweep
// freeing an address that a device is still using.
//
// An OpenConnect session is recorded at AUTH, but ocserv only creates the tun (and so
// the route the probe looks for) once the client returns with its cookie, and the sweep
// is a wall-clock tick that can land inside that window. A session ocserv has just
// reported alive via Interim-Update must be spared for the same reason. Freeing either
// hands the account's next device an address already in use, which ocserv does not
// detect: the kernel keeps one route and the other device stops receiving without ever
// losing its connection.
func TestCleanStaleSessionsSparesLiveOcservSessions(t *testing.T) {
	now := time.Now()
	s := &RadiusService{
		sessions: map[string]*radiusSession{
			// Authenticated a moment ago; its tun does not exist yet.
			ocSessionKey("10.4.1.2"): {email: "alice@t", ip: "10.4.1.2", protocol: "openconnect", started: now},
			// Long-lived, and ocserv said it was alive one interim ago.
			ocSessionKey("10.4.1.3"): {email: "bob@t", ip: "10.4.1.3", protocol: "openconnect", started: now.Add(-time.Hour), heard: now.Add(-time.Minute)},
			// Long-lived and silent: genuinely gone, so it must be reclaimed.
			ocSessionKey("10.4.1.4"): {email: "carol@t", ip: "10.4.1.4", protocol: "openconnect", started: now.Add(-time.Hour), heard: now.Add(-time.Hour)},
		},
		pending: map[string]time.Time{},
		// No ocserv routes exist in a unit test, which is exactly the false negative the
		// grace and the heartbeat have to absorb.
		ocActiveFn: func(string) bool { return false },
	}

	s.CleanStaleSessions()

	if _, ok := s.sessions[ocSessionKey("10.4.1.2")]; !ok {
		t.Fatal("swept a session that had just authenticated; its address can now be handed to another device on the account")
	}
	if _, ok := s.sessions[ocSessionKey("10.4.1.3")]; !ok {
		t.Fatal("swept a session ocserv reported alive one interim update ago")
	}
	if _, ok := s.sessions[ocSessionKey("10.4.1.4")]; ok {
		t.Fatal("kept a session with no route and no heartbeat; a dead device would hold its User-Limit slot forever")
	}
}

// TestOcservInterimRefreshesHeartbeat asserts an Interim-Update is recorded as proof of
// life, which is what lets the sweep above spare the session.
func TestOcservInterimRefreshesHeartbeat(t *testing.T) {
	const secret = "testsecret"
	s := &RadiusService{
		sessions: map[string]*radiusSession{
			ocSessionKey("10.4.1.2"): {email: "alice@t", ip: "10.4.1.2", protocol: "openconnect", started: time.Now().Add(-time.Hour)},
		},
		pending: map[string]time.Time{},
		secret:  []byte(secret),
	}

	s.handleAcct(&capRW{}, &radius.Request{Packet: ocAcctPacket(secret, "ocsid-alice", "alice", "10.4.1.2", rfc2866.AcctStatusType_Value_InterimUpdate)})

	sess := s.sessions[ocSessionKey("10.4.1.2")]
	if sess == nil {
		t.Fatal("interim update removed the session")
	}
	if sess.heard.IsZero() {
		t.Fatal("interim update did not record the heartbeat, so the route probe still decides alone")
	}
	if sess.acctID != "ocsid-alice" {
		t.Fatalf("interim update did not record the daemon session id (%q); a predecessor's stop can then retire this session", sess.acctID)
	}
}
