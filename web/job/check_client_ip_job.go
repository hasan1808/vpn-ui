package job

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"
)

// IPWithTimestamp tracks an IP address with its last seen timestamp
type IPWithTimestamp struct {
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

// CheckClientIpJob records which source addresses Xray's access log attributed to each
// client, for DISPLAY ONLY: the panel's per-client IP log reads the rows it writes
// (POST /panel/api/inbounds/clientIps/:email, rendered by inbound_info_modal.html).
//
// It no longer ENFORCES the IP limit. That moved into the patched core, which refuses a
// connection at admission from the per-account cap the panel publishes in the
// speedlimits.json sidecar (web/service/speedlimit.go). What used to live here was a log
// scrape that wrote a [LIMIT_IP] line for a fail2ban jail to act on, and it was wrong in
// two ways no amount of tuning fixes: it banned by ADDRESS, so on carrier-grade NAT it
// took out unrelated paying customers who merely shared an egress, and it could not
// disconnect anyone anyway (RemoveUser -> validator.Del, but the VLESS validator is
// consulted exactly once per connection, at handshake, so live connections were untouched
// and the user was re-added 100ms later).
//
// So everything below is telemetry: it may be late, empty (the shipped access log default
// is "none"), or plain absent without any effect on the limit that is actually applied.
type CheckClientIpJob struct {
	lastClear int64
}

var job *CheckClientIpJob

// ipStaleAfterSeconds is how long an address stays listed for a client after the access
// log stops mentioning it.
//
// It is a display retention window, not a limiter input: the core counts live connections
// by refcount and needs no such guess. 30 minutes keeps an actively-streaming client (xray
// emits a fresh `accepted` line whenever it opens a TCP connection, so its timestamp
// refreshes well inside the window) listed continuously, while an address that has really
// stopped connecting drops off in bounded time instead of accumulating forever.
const ipStaleAfterSeconds = int64(30 * 60)

// NewCheckClientIpJob creates a new client IP monitoring job instance.
func NewCheckClientIpJob() *CheckClientIpJob {
	job = new(CheckClientIpJob)
	return job
}

func (j *CheckClientIpJob) Run() {
	if j.lastClear == 0 {
		j.lastClear = time.Now().Unix()
	}

	if !j.accessLogAvailable() {
		return
	}

	// Gated on some client somewhere having a cap because that is exactly when the panel
	// renders the IP log (the modal's row is gated on limitIp > 0). With no cap set
	// anywhere, parsing the log every 10s would produce rows nothing displays.
	if j.hasLimitIp() {
		j.processLogFile()
	}

	// Hourly only. The scrape no longer truncates the log to force a re-read (there is no
	// ban to re-trigger), so this is purely the access log's own rotation into the
	// persistent copy, which is what it was for whenever nothing was over its limit.
	if time.Now().Unix()-j.lastClear > 3600 {
		j.clearAccessLog()
	}
}

func (j *CheckClientIpJob) clearAccessLog() {
	logAccessP, err := os.OpenFile(xray.GetAccessPersistentLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	j.checkError(err)
	defer logAccessP.Close()

	accessLogPath, err := xray.GetAccessLogPath()
	j.checkError(err)

	file, err := os.Open(accessLogPath)
	j.checkError(err)
	defer file.Close()

	_, err = io.Copy(logAccessP, file)
	j.checkError(err)

	err = os.Truncate(accessLogPath, 0)
	j.checkError(err)

	j.lastClear = time.Now().Unix()
}

func (j *CheckClientIpJob) hasLimitIp() bool {
	db := database.GetDB()
	var inbounds []*model.Inbound

	err := db.Model(model.Inbound{}).Find(&inbounds).Error
	if err != nil {
		return false
	}

	for _, inbound := range inbounds {
		if inbound.Settings == "" {
			continue
		}

		settings := map[string][]model.Client{}
		json.Unmarshal([]byte(inbound.Settings), &settings)
		clients := settings["clients"]

		for _, client := range clients {
			limitIp := client.LimitIP
			if limitIp > 0 {
				return true
			}
		}
	}

	return false
}

func (j *CheckClientIpJob) processLogFile() {

	ipRegex := regexp.MustCompile(`from (?:tcp:|udp:)?\[?([0-9a-fA-F\.:]+)\]?:\d+ accepted`)
	emailRegex := regexp.MustCompile(`email: (.+)$`)
	timestampRegex := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)

	accessLogPath, _ := xray.GetAccessLogPath()
	file, _ := os.Open(accessLogPath)
	defer file.Close()

	// Track IPs with their last seen timestamp
	inboundClientIps := make(map[string]map[string]int64, 100)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		ipMatches := ipRegex.FindStringSubmatch(line)
		if len(ipMatches) < 2 {
			continue
		}

		ip := ipMatches[1]

		if ip == "127.0.0.1" || ip == "::1" {
			continue
		}

		emailMatches := emailRegex.FindStringSubmatch(line)
		if len(emailMatches) < 2 {
			continue
		}
		email := emailMatches[1]

		// Extract timestamp from log line
		var timestamp int64
		timestampMatches := timestampRegex.FindStringSubmatch(line)
		if len(timestampMatches) >= 2 {
			t, err := time.Parse("2006/01/02 15:04:05", timestampMatches[1])
			if err == nil {
				timestamp = t.Unix()
			} else {
				timestamp = time.Now().Unix()
			}
		} else {
			timestamp = time.Now().Unix()
		}

		if _, exists := inboundClientIps[email]; !exists {
			inboundClientIps[email] = make(map[string]int64)
		}
		// Update timestamp - keep the latest
		if existingTime, ok := inboundClientIps[email][ip]; !ok || timestamp > existingTime {
			inboundClientIps[email][ip] = timestamp
		}
	}

	for email, ipTimestamps := range inboundClientIps {

		// Convert to IPWithTimestamp slice
		ipsWithTime := make([]IPWithTimestamp, 0, len(ipTimestamps))
		for ip, timestamp := range ipTimestamps {
			ipsWithTime = append(ipsWithTime, IPWithTimestamp{IP: ip, Timestamp: timestamp})
		}

		clientIpsRecord, err := j.getInboundClientIps(email)
		if err != nil {
			j.addInboundClientIps(email, ipsWithTime)
			continue
		}

		j.updateInboundClientIps(clientIpsRecord, email, ipsWithTime)
	}
}

// mergeClientIps combines the persisted (old) and freshly observed (new)
// IP-with-timestamp lists for a single client into a map. An entry is
// dropped if its last-seen timestamp is older than staleCutoff.
//
// Extracted as a helper so updateInboundClientIps can stay DB-oriented
// and the merge policy can be exercised by a unit test.
func mergeClientIps(old, new []IPWithTimestamp, staleCutoff int64) map[string]int64 {
	ipMap := make(map[string]int64, len(old)+len(new))
	for _, ipTime := range old {
		if ipTime.Timestamp < staleCutoff {
			continue
		}
		ipMap[ipTime.IP] = ipTime.Timestamp
	}
	for _, ipTime := range new {
		if ipTime.Timestamp < staleCutoff {
			continue
		}
		if existingTime, ok := ipMap[ipTime.IP]; !ok || ipTime.Timestamp > existingTime {
			ipMap[ipTime.IP] = ipTime.Timestamp
		}
	}
	return ipMap
}

// accessLogAvailable reports whether Xray is writing an access log to read.
//
// Silent when it is not. The shipped template disables the access log ("access": "none"),
// and now that a cap is enforced without it, a client with a cap and no access log is a
// perfectly working limit with no IP list to show, not a misconfiguration: warning on
// every 10s tick would be pure noise about a feature that is doing its job.
func (j *CheckClientIpJob) accessLogAvailable() bool {
	accessLogPath, err := xray.GetAccessLogPath()
	if err != nil {
		return false
	}
	return accessLogPath != "none" && accessLogPath != ""
}

func (j *CheckClientIpJob) checkError(e error) {
	if e != nil {
		logger.Warning("client ip job err:", e)
	}
}

func (j *CheckClientIpJob) getInboundClientIps(clientEmail string) (*model.InboundClientIps, error) {
	db := database.GetDB()
	InboundClientIps := &model.InboundClientIps{}
	err := db.Model(model.InboundClientIps{}).Where("client_email = ?", clientEmail).First(InboundClientIps).Error
	if err != nil {
		return nil, err
	}
	return InboundClientIps, nil
}

func (j *CheckClientIpJob) addInboundClientIps(clientEmail string, ipsWithTime []IPWithTimestamp) error {
	inboundClientIps := &model.InboundClientIps{}
	jsonIps, err := json.Marshal(ipsWithTime)
	j.checkError(err)

	inboundClientIps.ClientEmail = clientEmail
	inboundClientIps.Ips = string(jsonIps)

	db := database.GetDB()
	tx := db.Begin()

	defer func() {
		if err == nil {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()

	err = tx.Save(inboundClientIps).Error
	if err != nil {
		return err
	}
	return nil
}

// updateInboundClientIps folds this scan's addresses into the client's stored list.
//
// The client's own cap is deliberately not read here, and neither is its inbound: this
// records what was seen, and the core decides what to do about it. Every address is
// recorded, including one the core is refusing, because a view that hid it would answer
// "which addresses is this account being used from" with a lie, and that is the only
// question the list is asked.
func (j *CheckClientIpJob) updateInboundClientIps(inboundClientIps *model.InboundClientIps, clientEmail string, newIpsWithTime []IPWithTimestamp) {
	var oldIpsWithTime []IPWithTimestamp
	if inboundClientIps.Ips != "" {
		json.Unmarshal([]byte(inboundClientIps.Ips), &oldIpsWithTime)
	}

	// Merged rather than overwritten so an address stays listed while it is quiet and
	// across the hourly access log rotation, and expired at the cutoff so the list cannot
	// grow without bound. See ipStaleAfterSeconds.
	ipMap := mergeClientIps(oldIpsWithTime, newIpsWithTime, time.Now().Unix()-ipStaleAfterSeconds)

	dbIps := make([]IPWithTimestamp, 0, len(ipMap))
	for ip, ts := range ipMap {
		dbIps = append(dbIps, IPWithTimestamp{IP: ip, Timestamp: ts})
	}
	// Sorted oldest first, and by address for equal timestamps, because map order is
	// randomized per run: without this the blob's bytes churn on every tick and the panel
	// reorders the list under the operator's cursor for no reason.
	sort.Slice(dbIps, func(a, b int) bool {
		if dbIps[a].Timestamp != dbIps[b].Timestamp {
			return dbIps[a].Timestamp < dbIps[b].Timestamp
		}
		return dbIps[a].IP < dbIps[b].IP
	})

	jsonIps, _ := json.Marshal(dbIps)
	inboundClientIps.Ips = string(jsonIps)

	if err := database.GetDB().Save(inboundClientIps).Error; err != nil {
		logger.Error("failed to save inboundClientIps:", err)
	}
}
