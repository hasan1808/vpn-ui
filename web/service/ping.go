package service

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// InternetPingTarget is one named service the Manage tile's connectivity check
// probes. Name is what the dashboard shows; Host is what gets resolved and
// pinged.
type InternetPingTarget struct {
	Name string
	Host string
}

// InternetTarget is a single probe result, straight over the wire to the
// dashboard. Status is "ok" or "fail"; Via says which transport answered
// ("icmp" or "tcp"); RttMs stays -1 while that transport never answered.
type InternetTarget struct {
	Name   string  `json:"name"`
	Host   string  `json:"host"`
	IP     string  `json:"ip"`
	Status string  `json:"status"`
	RttMs  float64 `json:"rttMs"`
	Via    string  `json:"via"`
	Detail string  `json:"detail"`
}

// InternetPingResult is the whole answer for the Manage tile's connectivity
// check. Overall is one of "online", "partial", "offline".
type InternetPingResult struct {
	CheckedAt string           `json:"checkedAt"`
	Overall   string           `json:"overall"`
	Targets   []InternetTarget `json:"targets"`
}

// internetPingTargets are the services the operator asked the server to prove
// it can reach. Ordered, so the dashboard rows are stable.
var internetPingTargets = []InternetPingTarget{
	{Name: "Google", Host: "google.com"},
	{Name: "Cloudflare", Host: "cloudflare.com"},
	{Name: "YouTube", Host: "youtube.com"},
}

// Time budgets for one probe.
const (
	pingResolveTimeout = 3 * time.Second
	pingICMPTimeout    = 1500 * time.Millisecond
	pingTCPTimeout     = 2 * time.Second
)

// PingInternet checks whether the server can reach the well-known services the
// dashboard lists. Each target is resolved, pinged over ICMP (an unprivileged
// kernel echo socket on Linux), and, only if ICMP stayed silent, probed over a
// connect to port 443 so a box whose firewall drops echo traffic is not
// reported as offline. All targets are gathered concurrently.
func (s *ServerService) PingInternet(ctx context.Context) *InternetPingResult {
	res := &InternetPingResult{
		CheckedAt: time.Now().Format(time.RFC3339),
		Targets:   make([]InternetTarget, len(internetPingTargets)),
	}
	for i, t := range internetPingTargets {
		res.Targets[i] = InternetTarget{
			Name: t.Name, Host: t.Host, Status: "fail", RttMs: -1,
		}
	}

	resolveCtx, cancelResolve := context.WithTimeout(ctx, pingResolveTimeout)
	defer cancelResolve()
	var wg sync.WaitGroup
	for i, t := range internetPingTargets {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			addrs, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip4", host)
			if err != nil || len(addrs) == 0 {
				res.Targets[i].Via = "dns"
				res.Targets[i].Detail = "resolve failed"
				return
			}
			res.Targets[i].IP = addrs[0].String()
		}(i, t.Host)
	}
	wg.Wait()

	// Unprivileged ICMP echo socket (kernel ping socket on Linux, no root
	// needed). One socket shared by every target: the kernel fixes the echo
	// identifier, and our per-target seq attributes each reply to its row.
	sentAt := make([]time.Time, len(res.Targets))
	pending := make(map[int]bool)
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err == nil {
		defer conn.Close()
		echo := &icmp.Echo{ID: pingSocketID(), Data: []byte("vpn-ui-ping")}
		for i := range res.Targets {
			if res.Targets[i].Detail != "" {
				continue
			}
			if _, perr := netip.ParseAddr(res.Targets[i].IP); perr != nil {
				continue
			}
			// Seq identifies the target, so each echo is marshalled fresh with
			// its own Seq: the shared socket returns all replies to us and the
			// seq is the only thing that says which row they answer.
			echo.Seq = i
			wb, merr := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: echo}).Marshal(nil)
			if merr != nil {
				continue
			}
			if _, werr := conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(res.Targets[i].IP)}); werr != nil {
				continue
			}
			sentAt[i] = time.Now()
			pending[i] = true
		}
	}

	if err == nil && len(pending) > 0 {
		if derr := conn.SetReadDeadline(time.Now().Add(pingICMPTimeout)); derr == nil {
			buf := make([]byte, 1280)
			for {
				n, _, rerr := conn.ReadFrom(buf)
				if rerr != nil {
					break
				}
				replyMsg, perr := icmp.ParseMessage(1, buf[:n])
				if perr != nil || replyMsg.Type != ipv4.ICMPTypeEchoReply {
					continue
				}
				reply, ok := replyMsg.Body.(*icmp.Echo)
				if !ok || reply.Seq < 0 || reply.Seq >= len(res.Targets) {
					continue
				}
				idx := reply.Seq
				if !pending[idx] || res.Targets[idx].Status == "ok" {
					continue
				}
				res.Targets[idx].Status = "ok"
				res.Targets[idx].RttMs = msSince(sentAt[idx])
				res.Targets[idx].Via = "icmp"
				res.Targets[idx].Detail = ""
				delete(pending, idx)
				if len(pending) == 0 {
					break
				}
			}
		}
	}

	// ICMP stayed silent or is unavailable: give the unreached targets a
	// TCP-443 chance so echo-filtered hosts still read as reachable.
	tcpCtx, cancelTCP := context.WithTimeout(ctx, pingTCPTimeout+time.Second)
	defer cancelTCP()
	for i := range res.Targets {
		if res.Targets[i].Status == "ok" || res.Targets[i].Via == "dns" {
			continue
		}
		ip := res.Targets[i].IP
		if ip == "" {
			continue
		}
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			dialer := net.Dialer{Timeout: pingTCPTimeout}
			start := time.Now()
			c, derr := dialer.DialContext(tcpCtx, "tcp4", net.JoinHostPort(ip, "443"))
			if derr != nil {
				res.Targets[i].Detail = "unreachable"
				return
			}
			c.Close()
			res.Targets[i].Status = "ok"
			res.Targets[i].RttMs = msSince(start)
			res.Targets[i].Via = "tcp"
			res.Targets[i].Detail = ""
		}(i, ip)
	}
	wg.Wait()
	cancelTCP()

	ok := 0
	for _, t := range res.Targets {
		if t.Status == "ok" {
			ok++
		}
	}
	switch {
	case ok == len(res.Targets):
		res.Overall = "online"
	case ok == 0:
		res.Overall = "offline"
	default:
		res.Overall = "partial"
	}
	return res
}

// pingSocketID is a per-process identifier for the echo requests, distinct
// from other pings running on the box. The kernel's datagram socket normally
// stamps its own, but the field has to be a valid echo body either way.
func pingSocketID() int {
	return os.Getpid()&0xffff | rand.Intn(0x10000)
}

// msSince reports how many milliseconds passed since start, as the dashboard
// wants to show them (one decimal, negative only on -1 sentinel paths that
// never call it).
func msSince(start time.Time) float64 {
	return round1(time.Since(start).Seconds() * 1000)
}

func round1(f float64) float64 {
	return float64(int(f*10)) / 10
}
