package job

import (
	"encoding/json"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/web/service/rbridge"
	"github.com/hasan1808/pro-ui/web/websocket"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/valyala/fasthttp"
)

// XrayTrafficJob collects and processes traffic statistics from Xray, updating the database and optionally informing external APIs.
type XrayTrafficJob struct {
	adminService    service.AdminService
	settingService  service.SettingService
	xrayService     service.XrayService
	inboundService  service.InboundService
	outboundService service.OutboundService
	l2tpService     service.L2tpService
	pptpService     service.PptpService
	openvpnService  service.OpenVpnService
	ocservService   service.OcservService
	sstpService     service.SstpService
	ikev2Service    service.Ikev2Service
	wgcService      service.WgcService
	awgService      service.AwgService
	greService      service.GreService
	mtprotoService  service.MtprotoService
	sshService      service.SshService
	nftService      service.NftService
	radiusService   *service.RadiusService
	sweeper         *rbridge.Sweeper
}

// NewXrayTrafficJob creates a new traffic collection job instance.
func NewXrayTrafficJob(rs *service.RadiusService) *XrayTrafficJob {
	j := &XrayTrafficJob{radiusService: rs}
	// Wire the shared RADIUS server into THIS job's own l2tp/pptp/openvpn service
	// structs. They are zero-value copies (not the web server's wired instances), so
	// without this their radiusService is nil and every DisableClients / KillDisabled-
	// Sessions call silently no-ops (see the `s.radiusService != nil` guards) — which
	// is why over-quota and disabled l2tp/pptp tunnels were never torn down live and
	// only got refused at the next reconnect. The secret is irrelevant to the kill
	// paths (they read the in-memory session map), so pass empty; getRadiusSecret
	// falls back to the DB if anything else needs it.
	j.l2tpService.SetRadius(rs, "")
	j.pptpService.SetRadius(rs, "")
	j.openvpnService.SetRadius(rs, "")
	j.ocservService.SetRadius(rs, "")
	j.sstpService.SetRadius(rs, "")
	j.ikev2Service.SetRadius(rs, "")
	// The rbridge Sweeper drives the non-RADIUS (sweep-reconciled) protocols each tick: it polls
	// their live tunnels, enforces quota/disable + User Limit, and writes their sessions +
	// nft accounting through the RADIUS service (the rbridge.Sink). ikev2 psk/eap-tls is the
	// first such adapter; future non-RADIUS protocols (e.g. WireGuard) register here too.
	j.sweeper = rbridge.New(rs)
	j.sweeper.Register(&j.ikev2Service)
	j.sweeper.Register(&j.wgcService)
	j.sweeper.Register(&j.awgService)
	j.sweeper.Register(&j.greService)
	return j
}

// appendUnrecorded appends each fallback record whose email has no record in `existing`
// stampSourceInbound names the inbound each relay record's bytes came from, so
// the traffic multiplier bills them at that inbound's rate rather than at
// whichever inbound the account's single client_traffics row happens to name.
// An account missing from the map (or ambiguous, which the map reports as 0) is
// left at 0, which the billing reads as "unknown" and handles by taking the max
// across the account's memberships.
func stampSourceInbound(records []*xray.ClientTraffic, idByEmail map[string]int) []*xray.ClientTraffic {
	if len(records) == 0 || len(idByEmail) == 0 {
		return records
	}
	for _, record := range records {
		if record.InboundId != 0 {
			continue
		}
		record.InboundId = idByEmail[service.AccountKeyOf(record.Email)]
	}
	return records
}

// yet, and returns the extended slice. It is the de-duplication guard for the relay
// protocols: see the call site in Run for why presence, not byte count, is the predicate.
func appendUnrecorded(existing, fallback []*xray.ClientTraffic) []*xray.ClientTraffic {
	recorded := make(map[string]bool, len(existing))
	for _, t := range existing {
		recorded[t.Email] = true
	}
	for _, t := range fallback {
		if recorded[t.Email] {
			continue
		}
		// Mark as we go so two relays reporting the same account in one tick contribute
		// once, not twice.
		recorded[t.Email] = true
		existing = append(existing, t)
	}
	return existing
}

// Run collects traffic statistics from Xray and updates the database, triggering restart if needed.
func (j *XrayTrafficJob) Run() {
	var traffics []*xray.Traffic
	var clientTraffics []*xray.ClientTraffic

	if j.xrayService.IsXrayRunning() {
		var err error
		traffics, clientTraffics, err = j.xrayService.GetXrayTraffic()
		if err != nil {
			traffics = nil
			clientTraffics = nil
		}
	}

	// Collect L2TP, PPTP, and OpenVPN per-client traffic from nftables counters (atomic read+reset)
	// Session maps (IP→email) come from the embedded RADIUS server
	// This runs regardless of Xray status — VPN traffic is independent
	// Non-RADIUS protocols (ikev2 psk/eap-tls, ...) authenticate locally with no RADIUS
	// round-trip, so the rbridge Sweeper reconciles their live tunnels into the session store +
	// nft counters BEFORE reading sessions below, so this tick bills their traffic and enforces
	// their quota + User Limit.
	// WireGuard: reconcile the kernel peer set to DB state FIRST (before the sweep polls),
	// so the interface holds exactly the enabled, non-disabled devices. Because a removed
	// peer cannot complete a handshake, this makes disable/quota enforcement HARD (a
	// disabled account cannot reconnect at all) and re-adds re-enabled accounts within one
	// tick — no eventual-eviction window. Cheap: a few in-process wgctrl/netlink calls.
	if err := j.wgcService.GenerateAllConfigs(); err != nil {
		logger.Debug("wgc: peer reconcile failed:", err)
	}
	// AmneziaWG: identical hard-enforcement reconcile to wg-c, before the sweep polls.
	if err := j.awgService.GenerateAllConfigs(); err != nil {
		logger.Debug("awg: peer reconcile failed:", err)
	}
	// GRE: same contract, and it matters MORE here than for the WireGuard family. GRE has no
	// handshake to refuse, so this reconcile IS the enforcement: it deletes a disabled
	// account's point-to-point device and withdraws its route and learned neighbour entry,
	// leaving it with no reverse path at all.
	if err := j.greService.GenerateAllConfigs(); err != nil {
		logger.Debug("gre: peer reconcile failed:", err)
	}
	// IKEv2 psk/eap-tls: same hard-enforcement contract, for the same reason. Those two
	// modes authenticate locally at charon (no RADIUS round-trip that could re-check the
	// account), so the sweep below only terminates the SA and the client re-dials into the
	// next tick's gap -- disabled, but still browsing. This drops the disabled account's
	// swanctl connection so the eviction sticks, and restores it within a tick when the
	// account comes back. Cheap in the steady state: it reloads only when the admissible
	// set changed. eap-mschapv2 is untouched (its RADIUS re-auth already enforces).
	j.ikev2Service.ReconcileDisabled()

	if j.sweeper != nil {
		j.sweeper.Tick()
	}

	vpnSessions := map[string]map[string]string{
		"l2tp":        j.radiusService.GetSessions("l2tp"),
		"pptp":        j.radiusService.GetSessions("pptp"),
		"openvpn":     j.radiusService.GetSessions("openvpn"),
		"openconnect": j.radiusService.GetSessions("openconnect"),
		"sstp":        j.radiusService.GetSessions("sstp"),
		"ikev2":       j.radiusService.GetSessions("ikev2"),
		"wg-c":        j.radiusService.GetSessions("wg-c"),
		"awg":         j.radiusService.GetSessions("awg"),
		"gre":         j.radiusService.GetSessions("gre"),
	}
	// Which inbound each tunnel address belongs to, so every collected record names
	// the SOURCE of its bytes. The traffic multiplier bills at the rate of the
	// inbound the traffic actually came from, and one account can now be served on
	// several inbounds with different rates; without this it would fall back to the
	// max across the account's memberships and over-bill the cheaper ones.
	vpnInbounds := make(map[string]map[string]int, len(vpnSessions))
	for protocol, ipToEmail := range vpnSessions {
		if len(ipToEmail) == 0 {
			continue
		}
		idByEmail := j.inboundService.SingleInboundIdByEmail(protocol)
		if len(idByEmail) == 0 {
			continue
		}
		byIP := make(map[string]int, len(ipToEmail))
		for ip, email := range ipToEmail {
			if id := idByEmail[service.AccountKeyOf(email)]; id != 0 {
				byIP[ip] = id
			}
		}
		vpnInbounds[protocol] = byIP
	}
	clientTraffics = append(clientTraffics, j.nftService.CollectAndResetTraffic(vpnSessions, vpnInbounds)...)

	// MTProto and SSH are userspace relays: no client ever gets a tunnel IP, so neither
	// can use the nft per-IP path above. Each keeps its own per-account byte counters
	// (telemt's Prometheus metrics; the SSH gateway's io.Copy tallies).
	//
	// But both egress through a paired Xray socks inbound whose USERNAME is the account
	// email, so Xray has usually already billed those exact bytes as a user stat in this
	// same tick. Appending unconditionally therefore hands addClientTraffic two records
	// measuring one transfer. That used to be masked by a `break` in addClientTraffic
	// that silently applied only the first record per email, which made the outcome
	// correct purely by append order: reordering these two lines would have doubled
	// every relay account's bill. addClientTraffic now SUMS per email, so the
	// de-duplication has to be explicit and it belongs here, at the point where the two
	// sources meet.
	//
	// The predicate is "does this account already have a record this tick", NOT "did it
	// move bytes this tick". The two sources flush on different boundaries: Xray can
	// report zero for an account whose bytes the relay has already tallied, and report
	// those same bytes a tick or two later. Gating on a positive byte count therefore
	// admits the relay copy now and the Xray copy afterwards, billing the transfer twice
	// (measured: 1.67x on a 100MiB SSH pull). Presence alone is stable, and it is what
	// the old first-record-wins behaviour effectively tested.
	//
	// The relay counters remain a real fallback for an account Xray does not track at all
	// (no socks user, so no record in any tick), which is what those tallies exist for.
	//
	// Both relays report per account with no inbound, so their records are stamped
	// with the source inbound here for the traffic multiplier, the same way the nft
	// path is above. Neither can be ambiguous in practice (one account is served by
	// one relay inbound per protocol), and SingleInboundIdByEmail returns 0 if it
	// somehow is, which falls back to the max across memberships.
	clientTraffics = appendUnrecorded(clientTraffics, stampSourceInbound(
		j.mtprotoService.CollectTraffic(), j.inboundService.SingleInboundIdByEmail("mtproto")))
	clientTraffics = appendUnrecorded(clientTraffics, stampSourceInbound(
		j.sshService.CollectTraffic(), j.inboundService.SingleInboundIdByEmail("ssh")))

	// Level-triggered enforcement: disconnect any STILL-connected client that is no
	// longer allowed (quota/expiry hit, or disabled in settings). The edge-triggered
	// DisableClients calls below only fire on the exact tick a quota is first crossed;
	// if that one-shot kill missed, the live VPN tunnel would keep running until the
	// user reconnects (auth refuses them only then) — the reported "used their 1GB but
	// kept going" bug. This sweep re-derives the disabled set from the DB each run, so
	// it is idempotent and cheap when nothing is disabled. Runs before the early-return
	// so an idle-but-over-quota session is still torn down.
	j.l2tpService.KillDisabledSessions()
	j.pptpService.KillDisabledSessions()
	j.openvpnService.KillDisabledSessions()
	j.ocservService.KillDisabledSessions()
	j.sstpService.KillDisabledSessions()
	j.ikev2Service.KillDisabledSessions()
	// MTProto: re-renders [access.user_enabled] from client_traffics. telemt's config
	// watcher applies it and cancels the disabled accounts' live sessions itself, so
	// there is no separate kill path and no daemon restart.
	j.mtprotoService.KillDisabledSessions()
	// SSH: close the live sessions of any disabled account and trim every account to
	// its User Limit. The server owns every net.Conn, so this is an in-process close.
	j.sshService.KillDisabledSessions()

	// Skip DB update if no traffic to process
	if len(traffics) == 0 && len(clientTraffics) == 0 {
		return
	}

	err, needRestart0, l2tpDisabledEmails, pptpDisabledEmails, ovpnDisabledEmails := j.inboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add inbound traffic failed:", err)
	}
	// Republish the speed limit sidecar now that AddTraffic has committed: this is the
	// only point in the tick where every protocol's bytes have landed, so it is the
	// first moment a "Limit After" threshold crossing is visible. It is deliberately
	// independent of the needRestart flags below and never sets one: nothing in the
	// xray.Config graph changed, and a restart per threshold crossing (which is a
	// continuous event as users consume data) is the exact thing the sidecar exists to
	// avoid. Cheap on a no-op tick: it skips the write when the bytes are unchanged.
	// The idle-tick early return above correctly skips this, since no bytes means no
	// threshold can have crossed.
	service.WriteSpeedLimits()
	// AddTraffic is where THIS tick's bytes land and a crossed quota flips the account
	// to disabled, so the sweep above (which ran before it) could only ever see the
	// PREVIOUS tick's verdict: an account that blew its quota kept relaying for one
	// more full interval. Re-run it here so the same tick that detects the overage
	// also ends the session, halving worst-case overshoot. Idempotent and cheap: it
	// re-renders the config and generateServerConfig now skips writing when the bytes
	// are unchanged, so a no-op tick costs a read and no reload.
	j.mtprotoService.KillDisabledSessions()
	// Enforce limits on L2TP clients (kill sessions, regenerate chap-secrets)
	if len(l2tpDisabledEmails) > 0 {
		j.l2tpService.DisableClients(l2tpDisabledEmails)
	}
	// Enforce limits on PPTP clients
	if len(pptpDisabledEmails) > 0 {
		j.pptpService.DisableClients(pptpDisabledEmails)
	}
	// Enforce limits on OpenVPN clients
	if len(ovpnDisabledEmails) > 0 {
		j.openvpnService.DisableClients(ovpnDisabledEmails)
	}
	err, needRestart1 := j.outboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add outbound traffic failed:", err)
	}
	if ExternalTrafficInformEnable, err := j.settingService.GetExternalTrafficInformEnable(); ExternalTrafficInformEnable {
		j.informTrafficToExternalAPI(traffics, clientTraffics)
	} else if err != nil {
		logger.Warning("get ExternalTrafficInformEnable failed:", err)
	}
	if needRestart0 || needRestart1 {
		j.xrayService.SetToNeedRestart()
	}

	// If no frontend client is connected, skip all WebSocket broadcasting routines,
	// including expensive DB queries for online clients and JSON marshaling.
	if !websocket.HasClients() {
		return
	}

	// Update online clients list and map
	onlineClients := j.inboundService.GetOnlineClients()
	lastOnlineMap, err := j.inboundService.GetClientsLastOnline()
	if err != nil {
		logger.Warning("get clients last online failed:", err)
		lastOnlineMap = make(map[string]int64)
	}

	// Traffic names clients, so it is per-admin data and cannot go out panel-wide:
	// broadcasting it whole put every admin's client emails and usage in every other
	// admin's browser. Each connected admin gets only their own slice.
	j.broadcastTrafficScoped(traffics, clientTraffics, onlineClients, lastOnlineMap)

	// Inbounds are per-admin, so this job cannot push a payload: it has no single
	// correct audience. It used to broadcast GetAllInbounds() to every browser every
	// tick, which handed each admin every other admin's inbounds and overwrote their
	// table with them. Sending the lightweight invalidate instead makes each browser
	// re-fetch through /panel/api/inbounds/list, which is scoped to the caller and
	// permission-gated. The frontend already debounces this signal.
	websocket.BroadcastInvalidate(websocket.MessageTypeInbounds)

	updatedOutbounds, err := j.outboundService.GetOutboundsTraffic()
	if err != nil {
		logger.Warning("get all outbounds for websocket failed:", err)
	}

	if updatedOutbounds != nil {
		websocket.BroadcastOutbounds(updatedOutbounds)
	}
}

func (j *XrayTrafficJob) informTrafficToExternalAPI(inboundTraffics []*xray.Traffic, clientTraffics []*xray.ClientTraffic) {
	informURL, err := j.settingService.GetExternalTrafficInformURI()
	if err != nil {
		logger.Warning("get ExternalTrafficInformURI failed:", err)
		return
	}
	requestBody, err := json.Marshal(map[string]any{"clientTraffics": clientTraffics, "inboundTraffics": inboundTraffics})
	if err != nil {
		logger.Warning("parse client/inbound traffic failed:", err)
		return
	}
	request := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(request)
	request.Header.SetMethod("POST")
	request.Header.SetContentType("application/json; charset=UTF-8")
	request.SetBody([]byte(requestBody))
	request.SetRequestURI(informURL)
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(response)
	if err := fasthttp.Do(request, response); err != nil {
		logger.Warning("POST ExternalTrafficInformURI failed:", err)
	}
}

// broadcastTrafficScoped delivers the traffic tick to each connected admin,
// filtered to the clients they own. Super admins get the unfiltered payload.
func (j *XrayTrafficJob) broadcastTrafficScoped(
	traffics []*xray.Traffic,
	clientTraffics []*xray.ClientTraffic,
	onlineClients []string,
	lastOnlineMap map[string]int64,
) {
	hub := websocket.GetHub()
	if hub == nil {
		return
	}
	userIds := hub.ConnectedUserIds()
	if len(userIds) == 0 {
		return
	}

	supers, err := j.adminService.SuperAdminIds()
	if err != nil {
		logger.Warning("traffic broadcast: cannot load super admins, skipping:", err)
		return
	}
	// Only pay for the access map if a non-super admin is actually watching.
	var access map[string]map[int]bool
	for _, id := range userIds {
		if !supers[id] {
			access, err = j.adminService.ClientEmailAccess()
			if err != nil {
				logger.Warning("traffic broadcast: cannot load client access, skipping:", err)
				return
			}
			break
		}
	}

	for _, userId := range userIds {
		if supers[userId] {
			websocket.BroadcastTrafficToUser(userId, map[string]any{
				"traffics":       traffics,
				"clientTraffics": clientTraffics,
				"onlineClients":  onlineClients,
				"lastOnlineMap":  lastOnlineMap,
			})
			continue
		}
		mine := make([]*xray.ClientTraffic, 0, len(clientTraffics))
		for _, ct := range clientTraffics {
			if access[ct.Email][userId] {
				mine = append(mine, ct)
			}
		}
		myOnline := make([]string, 0, len(onlineClients))
		for _, email := range onlineClients {
			if access[email][userId] {
				myOnline = append(myOnline, email)
			}
		}
		myLastOnline := make(map[string]int64, len(lastOnlineMap))
		for email, t := range lastOnlineMap {
			if access[email][userId] {
				myLastOnline[email] = t
			}
		}
		// traffics is inbound-level and keyed by Xray tag rather than email, so it is
		// omitted for non-super admins rather than shipped unfiltered. The per-client
		// figures above are what the inbounds table renders.
		websocket.BroadcastTrafficToUser(userId, map[string]any{
			"clientTraffics": mine,
			"onlineClients":  myOnline,
			"lastOnlineMap":  myLastOnline,
		})
	}
}
