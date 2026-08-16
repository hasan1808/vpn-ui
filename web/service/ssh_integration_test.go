package service

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"

	"github.com/op/go-logging"
	"golang.org/x/crypto/ssh"
)

// TestMain initializes the logger so service code paths that log (e.g. the SSH server
// binding a listener) do not panic on a nil logger under test.
func TestMain(m *testing.M) {
	logger.InitLogger(logging.WARNING)
	os.Exit(m.Run())
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := portOf(t, ln.Addr().String())
	ln.Close()
	return p
}

func startTCPEcho(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return portOf(t, ln.Addr().String())
}

// startMockSocksConnectOnPort binds the CONNECT mock socks on a fixed port (the
// panel's 12300+id egress port for the inbound under test).
func startMockSocksConnectOnPort(t *testing.T, port int, wantUser string) func() {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("bind mock socks on %d: %v", port, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMockSocksConnect(c, wantUser)
		}
	}()
	return func() { ln.Close() }
}

// readWithTimeout reads exactly len(buf) bytes or fails the test after the deadline.
func readWithTimeout(t *testing.T, conn net.Conn, buf []byte, d time.Duration) {
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(conn, buf); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(d):
		t.Fatal("read timed out")
	}
}

func TestSshServerTCPPath(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	port := freePort(t)
	settings := `{"userLimit":2,"userLimitStrategy":"reject","clients":[{"id":"alice","password":"secret1","email":"alice@t","enable":true}]}`
	ib := &model.Inbound{UserId: 1, Enable: true, Port: port, Protocol: model.SSH, Settings: settings, Tag: "inbound-ssh"}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	svc := &SshService{}
	if err := svc.ReconcileHostKeys(); err != nil {
		t.Fatalf("host keys: %v", err)
	}

	echoPort := startTCPEcho(t)
	stopSocks := startMockSocksConnectOnPort(t, 12300+ib.Id, "alice@t")
	defer stopSocks()

	if err := svc.RestartServices(); err != nil {
		t.Fatalf("RestartServices: %v", err)
	}
	defer svc.StopServices()

	if !svc.AnyRunning() {
		t.Fatal("no SSH listener bound after RestartServices")
	}

	cfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("secret1")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	// direct-tcpip through the socks handoff to the echo server
	conn, err := client.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		t.Fatalf("channel dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello-ssh-tcp-path")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	readWithTimeout(t, conn, got, 5*time.Second)
	if string(got) != string(msg) {
		t.Errorf("echo mismatch: got %q want %q", got, msg)
	}

	// accounting: bytes should have been counted for alice@t
	var up, down int64
	for _, tr := range svc.CollectTraffic() {
		if tr.Email == "alice@t" {
			up, down = tr.Up, tr.Down
		}
	}
	if up == 0 || down == 0 {
		t.Errorf("expected non-zero accounting, got up=%d down=%d", up, down)
	}

	// wrong password must be rejected
	badCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if bad, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), badCfg); err == nil {
		bad.Close()
		t.Error("ssh dial with wrong password should have failed")
	}
}

// TestSshServerOpenSSHClient drives the server with the REAL OpenSSH client + sshpass
// (exactly what the incus E2E does: sshpass -p PW ssh -N -D), so it catches any
// OpenSSH-vs-Go-client auth or forwarding difference locally. Skips if the tools are
// absent.
func TestSshServerOpenSSHClient(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not on PATH")
	}
	if _, err := exec.LookPath("sshpass"); err != nil {
		t.Skip("sshpass not on PATH")
	}

	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()
	port := freePort(t)
	settings := `{"clients":[{"id":"dave","password":"pw-dave-42","email":"dave@t","enable":true}]}`
	ib := &model.Inbound{UserId: 1, Enable: true, Port: port, Protocol: model.SSH, Settings: settings, Tag: "inbound-ssh-openssh"}
	if err := db.Create(ib).Error; err != nil {
		t.Fatal(err)
	}
	svc := &SshService{}
	if err := svc.ReconcileHostKeys(); err != nil {
		t.Fatal(err)
	}
	echoPort := startTCPEcho(t)
	stopSocks := startMockSocksConnectOnPort(t, 12300+ib.Id, "dave@t")
	defer stopSocks()
	if err := svc.RestartServices(); err != nil {
		t.Fatal(err)
	}
	defer svc.StopServices()

	socksPort := freePort(t)
	cmd := exec.Command("sshpass", "-p", "pw-dave-42", sshBin, "-N",
		"-D", fmt.Sprintf("127.0.0.1:%d", socksPort),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=10",
		"-p", strconv.Itoa(port), "dave@127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ssh: %v", err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	// Wait for the ssh -D SOCKS proxy to come up (proof OpenSSH+sshpass auth succeeded).
	up := false
	for i := 0; i < 40; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 200*time.Millisecond)
		if err == nil {
			c.Close()
			up = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !up {
		t.Fatal("ssh -D SOCKS proxy never came up (OpenSSH+sshpass auth failed)")
	}

	// Connect through the ssh -D SOCKS (no auth) to the echo: proves the full path
	// OpenSSH client -> SSH channel -> our server -> Xray socks -> echo.
	conn, err := dialSocksConnect(socksPort, "unused", "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("connect through ssh -D socks: %v", err)
	}
	defer conn.Close()
	msg := []byte("openssh-client-path")
	conn.Write(msg)
	got := make([]byte, len(msg))
	readWithTimeout(t, conn, got, 5*time.Second)
	if string(got) != string(msg) {
		t.Errorf("echo mismatch through OpenSSH path: got %q", got)
	}
}

func TestSshServerRejectsShell(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()
	port := freePort(t)
	settings := `{"clients":[{"id":"bob","password":"pw","email":"bob@t","enable":true}]}`
	ib := &model.Inbound{UserId: 1, Enable: true, Port: port, Protocol: model.SSH, Settings: settings, Tag: "inbound-ssh2"}
	if err := db.Create(ib).Error; err != nil {
		t.Fatal(err)
	}
	svc := &SshService{}
	svc.ReconcileHostKeys()
	if err := svc.RestartServices(); err != nil {
		t.Fatal(err)
	}
	defer svc.StopServices()

	cfg := &ssh.ClientConfig{
		User:            "bob",
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	// A session (shell/exec) channel must be rejected: this is a proxy-only gateway.
	if _, _, err := client.OpenChannel("session", nil); err == nil {
		t.Error("session channel should be rejected (no shell/exec allowed)")
	}
}

func startUDPEcho(t *testing.T) int {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// startMockSocksFullOnPort serves CONNECT and UDP ASSOCIATE (a real UDP relay).
func startMockSocksFullOnPort(t *testing.T, port int, wantUser string) func() {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("bind mock socks on %d: %v", port, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMockSocksFull(c, wantUser)
		}
	}()
	return func() { ln.Close() }
}

func serveMockSocksFull(c net.Conn, wantUser string) {
	defer c.Close()
	br := bufio.NewReader(c)
	if !mockSocksAuth(c, br, wantUser) {
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	host, err := socksReadAddr(br, head[3])
	if err != nil {
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	dport := int(binary.BigEndian.Uint16(pb))

	switch head[1] {
	case 0x01: // CONNECT
		up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(dport)), 3*time.Second)
		if err != nil {
			c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
		go io.Copy(up, br)
		io.Copy(c, up)
	case 0x03: // UDP ASSOCIATE
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer relay.Close()
		rep := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1}
		rep = binary.BigEndian.AppendUint16(rep, uint16(relay.LocalAddr().(*net.UDPAddr).Port))
		c.Write(rep)
		go mockSocksUDPRelay(relay)
		io.Copy(io.Discard, br) // block until the control connection closes
	}
}

// mockSocksUDPRelay forwards each SOCKS-wrapped datagram to its real destination and
// relays the reply back, wrapped with the destination as the source address.
func mockSocksUDPRelay(relay *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		host, port, payload, ok := socksDecodeUDP(buf[:n])
		if !ok {
			continue
		}
		dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		us, err := net.DialUDP("udp", nil, dst)
		if err != nil {
			continue
		}
		us.SetDeadline(time.Now().Add(3 * time.Second))
		us.Write(payload)
		rbuf := make([]byte, 65535)
		rn, err := us.Read(rbuf)
		us.Close()
		if err != nil {
			continue
		}
		relay.WriteToUDP(socksEncodeUDP(host, port, rbuf[:rn]), from)
	}
}

func TestSshServerUDPPath(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	port := freePort(t)
	settings := `{"clients":[{"id":"carol","password":"pw3","email":"carol@t","enable":true}]}`
	ib := &model.Inbound{UserId: 1, Enable: true, Port: port, Protocol: model.SSH, Settings: settings, Tag: "inbound-ssh-udp"}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	svc := &SshService{}
	if err := svc.ReconcileHostKeys(); err != nil {
		t.Fatal(err)
	}

	udpEchoPort := startUDPEcho(t)
	stopSocks := startMockSocksFullOnPort(t, 12300+ib.Id, "carol@t")
	defer stopSocks()

	if err := svc.RestartServices(); err != nil {
		t.Fatal(err)
	}
	defer svc.StopServices()

	cfg := &ssh.ClientConfig{
		User:            "carol",
		Auth:            []ssh.AuthMethod{ssh.Password("pw3")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	// The udpgw channel: a direct-tcpip channel to the loopback udpgw port.
	conn, err := client.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshUdpgwPort))
	if err != nil {
		t.Fatalf("udpgw channel dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("udp-echo-over-ssh")
	pkt := buildUdpgwPacket(7, net.IPv4(127, 0, 0, 1), udpEchoPort, payload)
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}

	conid, gotPayload := readUdpgwReply(t, conn, 5*time.Second)
	if conid != 7 {
		t.Errorf("conid = %d, want 7 (must be echoed)", conid)
	}
	if string(gotPayload) != string(payload) {
		t.Errorf("udp payload mismatch: got %q want %q", gotPayload, payload)
	}

	var up, down int64
	for _, tr := range svc.CollectTraffic() {
		if tr.Email == "carol@t" {
			up, down = tr.Up, tr.Down
		}
	}
	if up == 0 || down == 0 {
		t.Errorf("expected UDP accounting, got up=%d down=%d", up, down)
	}
}

// readUdpgwReply reads one framed udpgw reply and returns its conid + payload.
func readUdpgwReply(t *testing.T, conn net.Conn, d time.Duration) (uint16, []byte) {
	type res struct {
		conid   uint16
		payload []byte
	}
	ch := make(chan res, 1)
	errc := make(chan error, 1)
	go func() {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			errc <- err
			return
		}
		msg := make([]byte, int(binary.LittleEndian.Uint16(lenBuf)))
		if _, err := io.ReadFull(conn, msg); err != nil {
			errc <- err
			return
		}
		if len(msg) < 3 {
			errc <- fmt.Errorf("short reply")
			return
		}
		flags := msg[0]
		conid := binary.LittleEndian.Uint16(msg[1:3])
		rest := msg[3:]
		alen := 4
		if flags&udpgwFlagIPv6 != 0 {
			alen = 16
		}
		if len(rest) < alen+2 {
			errc <- fmt.Errorf("short addr")
			return
		}
		ch <- res{conid: conid, payload: rest[alen+2:]}
	}()
	select {
	case r := <-ch:
		return r.conid, r.payload
	case err := <-errc:
		t.Fatalf("read udpgw reply: %v", err)
	case <-time.After(d):
		t.Fatal("udpgw reply timed out")
	}
	return 0, nil
}

// buildUdpgwPacket frames a client->server udpgw message for the UDP path test.
func buildUdpgwPacket(conid uint16, destIP net.IP, destPort int, payload []byte) []byte {
	v4 := destIP.To4()
	var msg []byte
	msg = append(msg, 0x00) // flags: IPv4, plain
	var cid [2]byte
	binary.LittleEndian.PutUint16(cid[:], conid)
	msg = append(msg, cid[0], cid[1])
	msg = append(msg, v4...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(destPort))
	msg = append(msg, payload...)
	out := make([]byte, 2)
	binary.LittleEndian.PutUint16(out, uint16(len(msg)))
	return append(out, msg...)
}
