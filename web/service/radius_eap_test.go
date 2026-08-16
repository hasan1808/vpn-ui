package service

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"

	"github.com/op/go-logging"
	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// getRadiusAttr returns the first attribute of the given type as raw bytes.
func getRadiusAttr(p *radius.Packet, typ radius.Type) []byte {
	for _, avp := range p.Attributes {
		if avp.Type == typ {
			return radius.Bytes(avp.Attribute)
		}
	}
	return nil
}

// assertEAPMsgAuth verifies the Message-Authenticator on a response the way a NAS
// would: HMAC-MD5(secret, packet-with-msgauth-zeroed). strongSwan drops replies that
// lack a valid one, so this is the load-bearing check for the EAP path.
func assertEAPMsgAuth(t *testing.T, p *radius.Packet, secret string) {
	t.Helper()
	got := getRadiusAttr(p, rfc2869.MessageAuthenticator_Type)
	if len(got) != 16 {
		t.Fatalf("response carries no Message-Authenticator (strongSwan would drop it)")
	}
	_ = rfc2869.MessageAuthenticator_Set(p, make([]byte, 16))
	raw, _ := p.MarshalBinary()
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(raw)
	want := mac.Sum(nil)
	_ = rfc2869.MessageAuthenticator_Set(p, got) // restore
	if !hmac.Equal(got, want) {
		t.Fatalf("Message-Authenticator mismatch: got %x want %x", got, want)
	}
}

// TestHandleAuthIKEv2EAPMSCHAPv2 drives the full 3-round EAP-MSCHAPv2 exchange that
// strongSwan's eap-radius plugin proxies for an IKEv2 login, simulating the client
// side, and asserts the server issues a correct Access-Accept (EAP-Success + MSK in
// MS-MPPE + Framed-IP-Address + Message-Authenticator). No VM/charon/client needed, so
// a framing/offset bug in the EAP state machine is caught in seconds.
func TestHandleAuthIKEv2EAPMSCHAPv2(t *testing.T) {
	logger.InitLogger(logging.DEBUG)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	settings := `{"clients":[{"id":"ikuser","password":"ikpass","email":"","enable":true}],"ipRanges":[],"userLimit":1,"userLimitStrategy":"accept"}`
	ib := &model.Inbound{Enable: true, Port: 500, Protocol: model.IKEV2, Settings: settings, Tag: "inbound-ikev2-500"}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	const secret = "testsecret"
	const user, pass = "ikuser", "ikpass"
	s := &RadiusService{
		sessions:    map[string]*radiusSession{},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		secret:      []byte(secret),
	}
	nasID := fmt.Sprintf("ikev2-%d", ib.Id)

	newReq := func(eap, state []byte) *radius.Request {
		pkt := radius.New(radius.CodeAccessRequest, []byte(secret))
		rfc2865.UserName_SetString(pkt, user)
		rfc2865.NASIdentifier_SetString(pkt, nasID)
		rfc2865.CallingStationID_SetString(pkt, "203.0.113.77")
		if state != nil {
			_ = rfc2865.State_Set(pkt, state)
		}
		_ = rfc2869.EAPMessage_Set(pkt, eap)
		return &radius.Request{Packet: pkt}
	}

	// --- RT1: EAP-Response/Identity -> Access-Challenge (MSCHAPv2 Challenge) ---
	w1 := &capRW{}
	s.handleAuth(w1, newReq(buildEAPPacket(eapCodeResponse, 1, eapTypeIdentity, []byte(user)), nil))
	if w1.resp == nil {
		t.Fatal("RT1: no response")
	}
	if w1.resp.Code != radius.CodeAccessChallenge {
		t.Fatalf("RT1: got %v, want Access-Challenge", w1.resp.Code)
	}
	chalEAP := getEAPMessage(w1.resp)
	if len(chalEAP) < 26 || chalEAP[0] != eapCodeRequest || chalEAP[4] != eapTypeMSCHAPv2 || chalEAP[5] != mschapOpChallenge {
		t.Fatalf("RT1: bad Challenge EAP: %x", chalEAP)
	}
	authChallenge := chalEAP[10:26]
	chapID := chalEAP[6]
	state1 := rfc2865.State_Get(w1.resp)
	if len(state1) == 0 {
		t.Fatal("RT1: Challenge carries no State")
	}
	assertEAPMsgAuth(t, w1.resp, secret)

	// --- client computes its NT-response over the server challenge ---
	peerChallenge := bytes.Repeat([]byte{0xAB}, 16)
	ntResp, err := rfc2759.GenerateNTResponse(authChallenge, peerChallenge, []byte(user), []byte(pass))
	if err != nil {
		t.Fatalf("client GenerateNTResponse: %v", err)
	}

	// --- RT2: EAP-Response/MSCHAPv2 (Response) -> Access-Challenge (Success) ---
	respVal := make([]byte, 0, 50)
	respVal = append(respVal, 49)                 // Value-Size
	respVal = append(respVal, peerChallenge...)   // Peer-Challenge (16)
	respVal = append(respVal, make([]byte, 8)...) // Reserved (8)
	respVal = append(respVal, ntResp...)          // NT-Response (24)
	respVal = append(respVal, 0)                  // Flags
	respVal = append(respVal, []byte(user)...)    // Name
	respMS := make([]byte, 4+len(respVal))
	respMS[0] = mschapOpResponse
	respMS[1] = chapID
	binary.BigEndian.PutUint16(respMS[2:4], uint16(4+len(respVal)))
	copy(respMS[4:], respVal)

	w2 := &capRW{}
	s.handleAuth(w2, newReq(buildEAPPacket(eapCodeResponse, 2, eapTypeMSCHAPv2, respMS), state1))
	if w2.resp == nil || w2.resp.Code != radius.CodeAccessChallenge {
		t.Fatalf("RT2: got %v, want Access-Challenge(Success) — server rejected a VALID NT-response (framing bug?)", codeOrNil(w2.resp))
	}
	succEAP := getEAPMessage(w2.resp)
	if len(succEAP) < 6 || succEAP[5] != mschapOpSuccess {
		t.Fatalf("RT2: expected MSCHAPv2 Success, got %x", succEAP)
	}
	state2 := rfc2865.State_Get(w2.resp)
	assertEAPMsgAuth(t, w2.resp, secret)

	// --- RT3: EAP-Response/MSCHAPv2 (Success ack) -> Access-Accept ---
	ackMS := []byte{mschapOpSuccess, chapID, 0, 4}
	w3 := &capRW{}
	s.handleAuth(w3, newReq(buildEAPPacket(eapCodeResponse, 3, eapTypeMSCHAPv2, ackMS), state2))
	if w3.resp == nil || w3.resp.Code != radius.CodeAccessAccept {
		t.Fatalf("RT3: got %v, want Access-Accept", codeOrNil(w3.resp))
	}
	if rfc2865.FramedIPAddress_Get(w3.resp) == nil {
		t.Fatal("RT3: Access-Accept has no Framed-IP-Address (strongSwan pools=radius needs it)")
	}
	finalEAP := getEAPMessage(w3.resp)
	if len(finalEAP) < 4 || finalEAP[0] != eapCodeSuccess {
		t.Fatalf("RT3: expected EAP-Success, got %x", finalEAP)
	}
	if getRadiusAttr(w3.resp, 26) == nil { // Vendor-Specific = MS-MPPE keys
		t.Fatal("RT3: Access-Accept carries no MS-MPPE keys (strongSwan needs the MSK)")
	}
	assertEAPMsgAuth(t, w3.resp, secret)
}

func codeOrNil(p *radius.Packet) any {
	if p == nil {
		return "nil"
	}
	return p.Code
}
