package service

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin/binding"
	"github.com/goccy/go-json"
)

// An SSH tunnel can name a carrier the same way a VPN tunnel can, and for this kind
// the whole feature is plumbing: the steer is a destination-based ip rule installed by
// the routing side, so nothing in sshoutbound.go dials differently. What IS this file's
// concern is that the field survives storage untouched, that it reaches the struct off
// a form-urlencoded POST, and that a blank one means "no carrier" rather than "keep the
// one you had". No database, no network, no kernel.

// ---- storage compatibility ----------------------------------------------------------

// Every stored tunnel predates this field, the whole list lives in one settings row, and
// that row is re-marshalled in full on every save, every delete and every learned host
// key. Without omitempty the first such write would stamp `"via":""` onto tunnels nobody
// touched, and the same list is what the synthesized socks outbounds are built from.
func TestSshOutboundConfigWithNoViaReMarshalsByteIdentically(t *testing.T) {
	const stored = `[{"tag":"ssh-out-1","remark":"jump","address":"203.0.113.10","port":22,` +
		`"username":"root","authType":"password","password":"s3cret","privateKey":"","passphrase":"",` +
		`"knownHost":"SHA256:abc","socksPort":10810}]`

	var list []SshOutboundConfig
	if err := json.Unmarshal([]byte(stored), &list); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != stored {
		t.Errorf("a stored tunnel did not survive a load/save round trip unchanged:\n got %s\nwant %s", out, stored)
	}
}

func TestSshOutboundConfigCarriesViaWhenSet(t *testing.T) {
	out, err := json.Marshal([]SshOutboundConfig{{
		Tag: "ssh-out-1", Address: "203.0.113.10", Port: 22, Username: "root",
		AuthType: "password", SocksPort: 10810, Via: "gre-b",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"via":"gre-b"`) {
		t.Errorf("via was dropped from the stored form: %s", out)
	}

	// And it comes back out. List() strips the secrets but not this: the panel re-seeds
	// the row's Dialer Proxy from it while the Xray config has not been saved yet, so a
	// field that did not round-trip would show an empty box over a live carrier and
	// clear it on the next save.
	var back []SshOutboundConfig
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 || back[0].Via != "gre-b" {
		t.Errorf("via did not survive the round trip: %+v", back)
	}
}

// ---- the form binding, which is the whole controller change ---------------------------

// The save handler binds a form-urlencoded POST straight onto SshOutboundConfig with
// c.ShouldBind, so the `form:"via"` tag is all that stands between the browser and the
// field. Pinned here because a missing tag fails silently: the save succeeds, the tunnel
// comes up, and the carrier is simply never stored.
func TestSshOutboundConfigBindsViaFromAFormPost(t *testing.T) {
	form := url.Values{
		"tag": {"ssh-out-1"}, "address": {"203.0.113.10"}, "port": {"22"},
		"username": {"root"}, "authType": {"password"}, "socksPort": {"10810"},
		"via": {"gre-b"},
	}
	req := httptest.NewRequest("POST", "/panel/xray/sshoutbound/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var cfg SshOutboundConfig
	if err := binding.Form.Bind(req, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Via != "gre-b" {
		t.Errorf("via = %q, want the posted carrier: the form tag is not carrying it", cfg.Via)
	}

	// An older panel, or a row whose Dialer Proxy was never touched, posts no `via` key
	// at all. That has to bind as blank rather than fail the whole save.
	form.Del("via")
	req = httptest.NewRequest("POST", "/panel/xray/sshoutbound/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var absent SshOutboundConfig
	if err := binding.Form.Bind(req, &absent); err != nil {
		t.Fatalf("a POST with no via field was refused: %v", err)
	}
	if absent.Via != "" {
		t.Errorf("via = %q, want blank", absent.Via)
	}
}

// ---- blank means clear, not keep -------------------------------------------------------

// The secrets are stripped before the panel sees them, so an edit posts them blank and
// the stored ones have to be kept. The carrier is the opposite case and shares the same
// code path, which is why it gets its own test: the browser sends it on EVERY save, so
// blank is the operator clearing the box, and keeping the stored value would leave the
// routing rules steering this tunnel into a carrier no screen still shows.
func TestSshOutKeepStoredClearsViaAndKeepsSecrets(t *testing.T) {
	prev := SshOutboundConfig{
		Tag: "ssh-out-1", Address: "203.0.113.10", Port: 22, Username: "root",
		AuthType: "privateKey", Password: "s3cret", PrivateKey: "PEM", Passphrase: "phrase",
		KnownHost: "SHA256:abc", SocksPort: 10810, Via: "gre-b",
	}
	// What an edit that cleared the Dialer Proxy posts: no secrets, no port, no carrier.
	posted := SshOutboundConfig{
		Tag: "ssh-out-1", Address: "203.0.113.10", Port: 22, Username: "root",
		AuthType: "privateKey", KnownHost: "SHA256:abc",
	}

	got := sshOutKeepStored(posted, prev)
	if got.Via != "" {
		t.Errorf("via = %q; a cleared carrier was restored from the stored tunnel, so the steer rules would outlive it", got.Via)
	}
	if got.Password != "s3cret" || got.PrivateKey != "PEM" || got.Passphrase != "phrase" {
		t.Errorf("a blank secret did not keep the stored one: %+v", got)
	}
	if got.SocksPort != 10810 {
		t.Errorf("socksPort = %d, want the port the saved outbound already names", got.SocksPort)
	}
}

// A carrier that IS posted replaces whatever was stored, including replacing one carrier
// with another. Same field, same rule, stated so a future merge cannot quietly special
// case it.
func TestSshOutKeepStoredTakesThePostedVia(t *testing.T) {
	prev := SshOutboundConfig{Tag: "ssh-out-1", SocksPort: 10810, Via: "gre-b"}
	got := sshOutKeepStored(SshOutboundConfig{Tag: "ssh-out-1", Via: "wg-a"}, prev)
	if got.Via != "wg-a" {
		t.Errorf("via = %q, want the newly posted carrier", got.Via)
	}
}

// Save trims it, because the carrier is resolved by exact tag match: a stray space would
// resolve to nothing and the tunnel would dial straight out of the host's WAN while the
// panel showed a carrier on it.
func TestSshOutboundSaveTrimsVia(t *testing.T) {
	// The trim happens before anything touches storage or the network, so the refusal
	// that follows is what makes this callable in a unit test at all.
	var svc SshOutboundService
	cfg, err := svc.Save(SshOutboundConfig{Tag: "ssh-out-1", Via: "  gre-b  "})
	if err == nil {
		t.Fatal("a tunnel with no address was accepted")
	}
	if cfg.Via != "gre-b" {
		t.Errorf("via = %q, want it trimmed", cfg.Via)
	}
}
