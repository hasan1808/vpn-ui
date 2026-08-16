package service

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// ocservConfValue returns the value of a single `key = value` line of a generated
// ocserv.conf, or "" when the key is absent.
func ocservConfValue(conf, key string) string {
	for _, line := range strings.Split(conf, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// TestOcservConfigKeepsNatMappingsAlive pins the three timers that decide whether an
// idle OpenConnect tunnel survives NAT.
//
// This is the regression test for "connections die after a few minutes and only a
// client reconnect fixes it". keepalive is advertised to the CLIENT (X-CSTP-Keepalive /
// X-DTLS-Keepalive) as how often to send on an idle tunnel, and ocserv swaps dpd for
// mobile-dpd on any android/apple-ios client, so ocserv's own sample values (32400 / 90
// / 1800) told every phone to send nothing for 30 minutes. Carrier-grade NAT drops an
// idle mapping in well under two minutes, and with the next probe half an hour away
// neither end noticed: the tunnel stayed "connected" and passed no traffic.
//
// The bounds, not the exact numbers, are what matter: anything above them re-opens the
// hole. 60s for the keepalive is already generous against a 120s NAT timeout, and the
// DPD ceilings keep the teardown (DPD_MAX_TRIES = 3 intervals) inside minutes rather
// than hours so a dead device also frees its User-Limit slot.
func TestOcservConfigKeepsNatMappingsAlive(t *testing.T) {
	s := &OcservService{}
	inbound := &model.Inbound{Id: 7, Port: 4443, Protocol: model.OPENCONNECT}
	conf := s.buildServerConfig(inbound, &ocservSettings{})

	for _, c := range []struct {
		key string
		max int
		why string
	}{
		{"keepalive", 60, "the client is told to send nothing for this long, so a NAT mapping expires and the tunnel goes silent both ways"},
		{"dpd", 120, "a dead peer is only detected after 3x this, so the address stays occupied and the client is never told to reconnect"},
		{"mobile-dpd", 600, "ocserv uses this INSTEAD of dpd for every android/ios client, which is most of them"},
	} {
		raw := ocservConfValue(conf, c.key)
		if raw == "" {
			t.Fatalf("ocserv.conf has no %s: %s", c.key, c.why)
		}
		secs, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("ocserv.conf %s = %q, not a number", c.key, raw)
		}
		if secs <= 0 {
			t.Fatalf("ocserv.conf %s = %d disables it: %s", c.key, secs, c.why)
		}
		if secs > c.max {
			t.Fatalf("ocserv.conf %s = %ds exceeds %ds: %s", c.key, secs, c.max, c.why)
		}
	}

	// An idle-timeout would disconnect a paying user who left the tunnel up, and the
	// panel has no UI for one, so it must stay unset (ocserv reads absent as disabled).
	if v := ocservConfValue(conf, "idle-timeout"); v != "" {
		t.Fatalf("ocserv.conf sets idle-timeout = %s; an idle tunnel must not be torn down", v)
	}
}
