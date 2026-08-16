package service

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/hasan1808/pro-ui/logger"

	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3079"
	"layeh.com/radius/vendors/microsoft"
)

// EAP-MSCHAPv2 server support for the IKEv2 protocol.
//
// strongSwan's eap-radius plugin does not authenticate EAP itself — it transparently
// proxies the EAP conversation between the IKEv2 client and this RADIUS server. So to
// serve IKEv2 username/password logins the panel's in-process RADIUS server has to run
// the EAP-MSCHAPv2 state machine: a 3-round Identity -> Challenge -> Response ->
// Success exchange carried over RADIUS Access-Request/Access-Challenge, ending in an
// Access-Accept whose MS-MPPE keys carry the MSK strongSwan needs for the IKE keys.
//
// The MSCHAPv2 crypto (NT-response, authenticator response, MSK) reuses the exact same
// rfc2759/rfc3079 helpers as the native MS-CHAPv2 path in handleAuth — only the EAP +
// EAP-MSCHAPv2 framing and the Access-Challenge state machine are new here.

const (
	// EAP codes (RFC 3748 §4).
	eapCodeRequest  = 1
	eapCodeResponse = 2
	eapCodeSuccess  = 3
	eapCodeFailure  = 4

	// EAP method types.
	eapTypeIdentity = 1
	eapTypeMSCHAPv2 = 26

	// EAP-MSCHAPv2 opcodes (draft-kamath-pppext-eap-mschapv2).
	mschapOpChallenge = 1
	mschapOpResponse  = 2
	mschapOpSuccess   = 3
	mschapOpFailure   = 4

	// eapSessionTTL bounds how long a half-finished EAP exchange lingers.
	eapSessionTTL = 60 * time.Second
	// eapServerName is the server identity placed in the MSCHAPv2 Challenge.
	eapServerName = "vpn-ui"
)

// eapState carries one in-flight EAP-MSCHAPv2 conversation across its round trips,
// keyed by the RADIUS State attribute (which the client echoes each round).
type eapState struct {
	authChallenge []byte // 16-byte server (authenticator) challenge sent in the Challenge
	chapID        byte   // MS-CHAPv2 message id chosen in the Challenge
	stateToken    []byte // the RADIUS State value tying the rounds together
	ntResponse    []byte // stashed after a successful verify, reused for MSK derivation
	username      string
	password      string
	protocol      string
	inboundId     int
	station       string
	nasPort       uint32
	created       time.Time
}

// getEAPMessage reassembles the (possibly fragmented) EAP-Message attributes of a
// RADIUS packet into a single EAP packet. The layeh library only returns the first
// attribute via EAPMessage_Get, so every attr-79 is concatenated in order. Returns
// nil when the request carries no EAP-Message (i.e. it is a PAP / native-MS-CHAPv2
// request handled by the normal handleAuth path).
func getEAPMessage(p *radius.Packet) []byte {
	var eap []byte
	for _, avp := range p.Attributes {
		if avp.Type == rfc2869.EAPMessage_Type {
			eap = append(eap, radius.Bytes(avp.Attribute)...)
		}
	}
	return eap
}

// eapPut records an in-flight exchange (and opportunistically sweeps expired ones).
func (s *RadiusService) eapPut(st *eapState) {
	s.mu.Lock()
	if s.eapSessions == nil {
		s.eapSessions = make(map[string]*eapState)
	}
	for k, e := range s.eapSessions {
		if time.Since(e.created) > eapSessionTTL {
			delete(s.eapSessions, k)
		}
	}
	s.eapSessions[hex.EncodeToString(st.stateToken)] = st
	s.mu.Unlock()
}

// eapGet fetches the exchange for a State token (nil if absent or expired).
func (s *RadiusService) eapGet(state []byte) *eapState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eapSessions == nil {
		return nil
	}
	key := hex.EncodeToString(state)
	st := s.eapSessions[key]
	if st != nil && time.Since(st.created) > eapSessionTTL {
		delete(s.eapSessions, key)
		return nil
	}
	return st
}

// eapDel discards a finished/abandoned exchange.
func (s *RadiusService) eapDel(state []byte) {
	s.mu.Lock()
	if s.eapSessions != nil {
		delete(s.eapSessions, hex.EncodeToString(state))
	}
	s.mu.Unlock()
}

// buildEAPPacket frames an EAP packet (RFC 3748 §4). Success/Failure carry no Type
// and are always 4 bytes; Request/Response carry a Type byte plus type-data.
func buildEAPPacket(code, id, typ byte, data []byte) []byte {
	if code == eapCodeSuccess || code == eapCodeFailure {
		return []byte{code, id, 0, 4}
	}
	length := 5 + len(data)
	b := make([]byte, length)
	b[0] = code
	b[1] = id
	binary.BigEndian.PutUint16(b[2:4], uint16(length))
	b[4] = typ
	copy(b[5:], data)
	return b
}

// buildMSCHAPv2 frames the Type-Data of a Type=26 EAP packet: OpCode, MS-CHAPv2-ID,
// MS-Length (covers the whole MSCHAPv2 message), then the opcode-specific value.
func buildMSCHAPv2(opcode, chapID byte, value []byte) []byte {
	msgLen := 4 + len(value)
	b := make([]byte, msgLen)
	b[0] = opcode
	b[1] = chapID
	binary.BigEndian.PutUint16(b[2:4], uint16(msgLen))
	copy(b[4:], value)
	return b
}

// addMessageAuthenticator computes the RFC 3579 Message-Authenticator — HMAC-MD5 over
// the whole packet with the attribute zeroed and the Authenticator field holding the
// request authenticator — and sets it in place. strongSwan silently drops any
// Access-Challenge / Access-Accept that lacks a valid Message-Authenticator, so this
// is mandatory. Set() replaces the placeholder at the same position, so the bytes we
// hashed equal the final wire bytes; Encode() later overwrites only [4:20] with the
// Response Authenticator, which the NAS verifies separately.
func (s *RadiusService) addMessageAuthenticator(p *radius.Packet) {
	_ = rfc2869.MessageAuthenticator_Set(p, make([]byte, 16))
	raw, err := p.MarshalBinary()
	if err != nil {
		return
	}
	mac := hmac.New(md5.New, s.secret)
	mac.Write(raw)
	_ = rfc2869.MessageAuthenticator_Set(p, mac.Sum(nil))
}

// sendEAPChallenge writes an Access-Challenge carrying one EAP packet plus the State
// token that correlates the next round, signed with a Message-Authenticator.
func (s *RadiusService) sendEAPChallenge(w radius.ResponseWriter, r *radius.Request, eap, state []byte) {
	resp := r.Response(radius.CodeAccessChallenge)
	_ = rfc2869.EAPMessage_Set(resp, eap)
	_ = rfc2865.State_Set(resp, state)
	s.addMessageAuthenticator(resp)
	_ = w.Write(resp)
}

// sendEAPReject writes an Access-Reject carrying EAP-Failure (id echoes the last
// EAP-Response), signed with a Message-Authenticator.
func (s *RadiusService) sendEAPReject(w radius.ResponseWriter, r *radius.Request, eapID byte) {
	resp := r.Response(radius.CodeAccessReject)
	_ = rfc2869.EAPMessage_Set(resp, buildEAPPacket(eapCodeFailure, eapID, 0, nil))
	s.addMessageAuthenticator(resp)
	_ = w.Write(resp)
}

// handleEAPAuth dispatches an EAP-carrying Access-Request. Only client EAP Responses
// are expected: Identity (start a Challenge) or MSCHAPv2 (continue the exchange).
func (s *RadiusService) handleEAPAuth(w radius.ResponseWriter, r *radius.Request, protocol string, inboundId int, username, station string, nasPort uint32, eap []byte) {
	if len(eap) < 4 {
		s.sendEAPReject(w, r, 0)
		return
	}
	code, eapID := eap[0], eap[1]
	if code != eapCodeResponse || len(eap) < 5 {
		s.sendEAPReject(w, r, eapID)
		return
	}
	switch eap[4] { // EAP Type
	case eapTypeIdentity:
		s.eapStartChallenge(w, r, protocol, inboundId, username, station, nasPort, eapID)
	case eapTypeMSCHAPv2:
		s.eapContinue(w, r, eap, eapID)
	default:
		// The client is expected to NAK toward MSCHAPv2; anything else is unsupported.
		logger.Infof("RADIUS(EAP): unsupported EAP type %d user=%s", eap[4], username)
		s.sendEAPReject(w, r, eapID)
	}
}

// eapStartChallenge handles EAP-Response/Identity: confirm the account exists, then
// send an EAP-Request/MSCHAPv2 Challenge and remember the exchange by its State token.
func (s *RadiusService) eapStartChallenge(w radius.ResponseWriter, r *radius.Request, protocol string, inboundId int, username, station string, nasPort uint32, eapID byte) {
	password, err := s.lookupClient(protocol, inboundId, username)
	if err != nil {
		logger.Infof("RADIUS(EAP): auth rejected — %s user=%s", err, username)
		s.sendEAPReject(w, r, eapID)
		return
	}

	authChallenge := make([]byte, 16)
	stateToken := make([]byte, 16)
	chapIDbuf := make([]byte, 1)
	if _, err := rand.Read(authChallenge); err != nil {
		s.sendEAPReject(w, r, eapID)
		return
	}
	_, _ = rand.Read(stateToken)
	_, _ = rand.Read(chapIDbuf)
	chapID := chapIDbuf[0]

	// MSCHAPv2 Challenge value: Value-Size(1)=16, Challenge(16 bytes), Name.
	val := make([]byte, 0, 17+len(eapServerName))
	val = append(val, 16)
	val = append(val, authChallenge...)
	val = append(val, []byte(eapServerName)...)
	eapOut := buildEAPPacket(eapCodeRequest, eapID+1, eapTypeMSCHAPv2, buildMSCHAPv2(mschapOpChallenge, chapID, val))

	s.eapPut(&eapState{
		authChallenge: authChallenge,
		chapID:        chapID,
		stateToken:    stateToken,
		username:      username,
		password:      password,
		protocol:      protocol,
		inboundId:     inboundId,
		station:       station,
		nasPort:       nasPort,
		created:       time.Now(),
	})
	s.sendEAPChallenge(w, r, eapOut, stateToken)
}

// eapContinue handles EAP-Response/MSCHAPv2 for an in-flight exchange (found by its
// State token): opcode Response -> verify + Success; opcode Success -> Access-Accept.
func (s *RadiusService) eapContinue(w radius.ResponseWriter, r *radius.Request, eap []byte, eapID byte) {
	state := rfc2865.State_Get(r.Packet)
	st := s.eapGet(state)
	if st == nil {
		logger.Info("RADIUS(EAP): no in-flight session for State — rejecting")
		s.sendEAPReject(w, r, eapID)
		return
	}
	if len(eap) < 6 {
		s.eapDel(st.stateToken)
		s.sendEAPReject(w, r, eapID)
		return
	}
	switch eap[5] { // MSCHAPv2 OpCode
	case mschapOpResponse:
		s.eapVerify(w, r, st, eap, eapID)
	case mschapOpSuccess:
		s.eapAccept(w, r, st, eapID)
	default:
		s.eapDel(st.stateToken)
		s.sendEAPReject(w, r, eapID)
	}
}

// eapVerify handles the client's EAP-MSCHAPv2 Response: extract Peer-Challenge +
// NT-Response, verify against the account password, and reply with an EAP-MSCHAPv2
// Success request (or Access-Reject on mismatch).
func (s *RadiusService) eapVerify(w radius.ResponseWriter, r *radius.Request, st *eapState, eap []byte, eapID byte) {
	// From the MSCHAPv2 value (starts at eap[9]): Value-Size(1)=49, Peer-Challenge(16),
	// Reserved(8), NT-Response(24), Flags(1), Name. So peer-challenge = eap[10:26],
	// NT-response = eap[34:58].
	if len(eap) < 58 {
		s.eapDel(st.stateToken)
		s.sendEAPReject(w, r, eapID)
		return
	}
	peerChallenge := eap[10:26]
	peerNTResponse := eap[34:58]

	ntResponse, err := rfc2759.GenerateNTResponse(st.authChallenge, peerChallenge, []byte(st.username), []byte(st.password))
	if err != nil || !bytes.Equal(ntResponse, peerNTResponse) {
		logger.Infof("RADIUS(EAP): auth rejected — wrong password user=%s", st.username)
		s.eapDel(st.stateToken)
		s.sendEAPReject(w, r, eapID)
		return
	}
	st.ntResponse = ntResponse // reused for MSK derivation in the final Accept

	// The authenticator response ("S=<40hex>") lets the client verify the server.
	authResp, _ := rfc2759.GenerateAuthenticatorResponse(st.authChallenge, peerChallenge, ntResponse, []byte(st.username), []byte(st.password))
	eapOut := buildEAPPacket(eapCodeRequest, eapID+1, eapTypeMSCHAPv2, buildMSCHAPv2(mschapOpSuccess, st.chapID, []byte(authResp)))
	s.sendEAPChallenge(w, r, eapOut, st.stateToken)
}

// eapAccept handles the client's EAP-MSCHAPv2 Success acknowledgment: issue the
// Access-Accept with EAP-Success, the MSK in the MS-MPPE keys, and the pinned tunnel
// IP (subject to the User-Limit gate), then finish the exchange.
func (s *RadiusService) eapAccept(w radius.ResponseWriter, r *radius.Request, st *eapState, eapID byte) {
	defer s.eapDel(st.stateToken)

	// User-Limit gate + per-account source IP (Framed-IP-Address) — identical to the
	// native MS-CHAPv2 / OpenConnect paths. strongSwan honors Framed-IP via pools=radius.
	clientIP, deny := s.getClientIP(st.protocol, st.inboundId, st.username, st.station, st.nasPort)
	if deny {
		logger.Infof("RADIUS(EAP): auth rejected — user-limit reached (strategy=reject) user=%s", st.username)
		s.sendEAPReject(w, r, eapID)
		return
	}

	accept := r.Response(radius.CodeAccessAccept)
	// EAP-Success — its id echoes the client's final EAP-Response.
	_ = rfc2869.EAPMessage_Set(accept, buildEAPPacket(eapCodeSuccess, eapID, 0, nil))

	// MSK -> MS-MPPE keys. strongSwan reconstructs the IKEv2 MSK as Recv||Send, so the
	// same send/recv mapping the PPP path already uses is correct here — do not swap.
	if st.ntResponse != nil {
		recvKey, _ := rfc3079.MakeKey(st.ntResponse, []byte(st.password), false)
		sendKey, _ := rfc3079.MakeKey(st.ntResponse, []byte(st.password), true)
		microsoft.MSMPPERecvKey_Add(accept, recvKey)
		microsoft.MSMPPESendKey_Add(accept, sendKey)
	}

	if clientIP != nil {
		rfc2865.FramedIPAddress_Set(accept, clientIP)
	}
	rfc2869.AcctInterimInterval_Set(accept, rfc2869.AcctInterimInterval(60))

	s.addMessageAuthenticator(accept)
	_ = w.Write(accept)
	logger.Infof("RADIUS(EAP): auth accepted user=%s ip=%v", st.username, clientIP)
}
