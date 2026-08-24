package xray

import (
	"strconv"
	"strings"
	"sync"
)

// OnlineMark names the inbound an online event was actually observed on.
//
// The panel-wide online list is keyed by email alone, which lights up every
// inbound sharing that account the moment one of them moves a byte. A mark
// carries the missing half of that fact: which inbound the traffic really
// came through. Sources, best first:
//
//   - the VPN daemons and the two relays stamp a source inbound id on every
//     record they hand the traffic job;
//   - Xray-native protocols have no such dimension in their stats counters,
//     so the access log's `[inboundTag -> email]` tail supplies it (see
//     RecentOnlineSources);
//   - when neither is available the account's home inbound stands in, which
//     degrades to today's behaviour rather than inventing a worse answer.
type OnlineMark struct {
	InboundId int    `json:"inboundId"`
	Email     string `json:"email"`
}

// onlineSourceTTL is how long an access-log observation stays fresh enough to
// attribute with. The access job scans every 10s and Xray emits an `accepted`
// line per connection, so a live protocol keeps refreshing well inside this;
// two minutes absorbs a quiet connection that is still open but no longer
// logging.
const OnlineSourceTTL = int64(120)

var (
	onlineSourcesMu sync.Mutex
	// email -> tag -> last-seen unix seconds
	onlineSources = make(map[string]map[string]int64)
	// Cheap amortised pruning: sweep once per this many notes instead of on
	// every call. The map holds only recently-active accounts, so it stays
	// small either way.
	onlineSourceNotes int
)

// NoteOnlineSource records that email was seen entering through tag at time
// now (unix seconds). Safe for concurrent callers; the access job is the only
// writer in practice, but the traffic job reads across goroutines.
func NoteOnlineSource(email, tag string, now int64) {
	if email == "" || tag == "" {
		return
	}
	onlineSourcesMu.Lock()
	defer onlineSourcesMu.Unlock()

	entry, ok := onlineSources[email]
	if !ok {
		entry = make(map[string]int64)
		onlineSources[email] = entry
	}
	entry[tag] = now

	onlineSourceNotes++
	if onlineSourceNotes >= 256 {
		onlineSourceNotes = 0
		pruneOnlineSourcesLocked(now - OnlineSourceTTL)
	}
}

// RecentOnlineSources returns the inbound tags email was seen on within ttl
// seconds of now, freshest last. Empty when nothing was noted (the usual case
// when the access log is disabled).
func RecentOnlineSources(email string, now, ttl int64) []string {
	if email == "" {
		return nil
	}
	onlineSourcesMu.Lock()
	defer onlineSourcesMu.Unlock()

	entry, ok := onlineSources[email]
	if !ok {
		return nil
	}
	cutoff := now - ttl
	tags := make([]string, 0, len(entry))
	for tag, seen := range entry {
		if seen < cutoff {
			continue
		}
		tags = append(tags, tag)
	}
	return tags
}

func pruneOnlineSourcesLocked(cutoff int64) {
	for email, entry := range onlineSources {
		live := false
		for tag, seen := range entry {
			if seen < cutoff {
				delete(entry, tag)
			} else {
				live = true
			}
		}
		if !live {
			delete(onlineSources, email)
		}
	}
}

// DedupMarks collapses repeated marks (a tick can legitimately produce the
// same inbound/email pair several times) while keeping a stable order.
func DedupMarks(marks []OnlineMark) []OnlineMark {
	if len(marks) == 0 {
		return marks
	}
	seen := make(map[string]bool, len(marks))
	out := make([]OnlineMark, 0, len(marks))
	for _, m := range marks {
		key := strings.ToLower(m.Email) + "::" + strconv.Itoa(m.InboundId)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}
