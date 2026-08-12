package service

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	gonet "net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// panelStartedAt is when this panel process began. Captured at package init so
// Panel Uptime measures the process, not the first status poll.
var panelStartedAt = time.Now()

// ProcessState represents the current state of a system process.
type ProcessState string

// Process state constants
const (
	Running ProcessState = "running" // Process is running normally
	Stop    ProcessState = "stop"    // Process is stopped
	Error   ProcessState = "error"   // Process is in error state
)

// Status represents comprehensive system and application status information.
// It includes CPU, memory, disk, network statistics, and Xray process status.
type Status struct {
	T           time.Time `json:"-"`
	Cpu         float64   `json:"cpu"`
	CpuCores    int       `json:"cpuCores"`
	LogicalPro  int       `json:"logicalPro"`
	CpuSpeedMhz float64   `json:"cpuSpeedMhz"`
	CpuModel    string    `json:"cpuModel"`
	OsName      string    `json:"osName"`
	OsVersion   string    `json:"osVersion"`
	Kernel      string    `json:"kernel"`
	Hostname    string    `json:"hostname"`
	Virt        VirtInfo  `json:"virt"`
	// MemHW is the memory FITTED to the machine (capacity, DDR generation,
	// clock), read once from SMBIOS. Mem below is the live usage and moves every
	// poll; these are two different numbers on purpose and the overview labels
	// them as such.
	MemHW MemHardware `json:"memHW"`
	Mem   struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"mem"`
	Swap struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"swap"`
	Disk struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"disk"`
	Xray struct {
		State    ProcessState `json:"state"`
		ErrorMsg string       `json:"errorMsg"`
		Version  string       `json:"version"`
	} `json:"xray"`
	// Uptime is the HOST's, AppUptime is this panel process's. The overview shows
	// both: a panel that restarted an hour ago on a box up for months is a fact
	// worth seeing, and one number cannot carry it.
	Uptime    uint64    `json:"uptime"`
	AppUptime uint64    `json:"appUptime"`
	Loads     []float64 `json:"loads"`
	TcpCount  int       `json:"tcpCount"`
	UdpCount  int       `json:"udpCount"`
	NetIO     struct {
		Up   uint64 `json:"up"`
		Down uint64 `json:"down"`
	} `json:"netIO"`
	// Swap and disk THROUGHPUT, as rates in bytes/sec, derived exactly like
	// NetIO below. The dashboard graphs these rather than the usage percentages
	// above: how full a disk is barely moves between two-second polls, so a
	// usage sparkline is a flat line by construction, while read+write is the
	// signal an operator actually wants from those two rows.
	SwapIO struct {
		In  uint64 `json:"in"`
		Out uint64 `json:"out"`
	} `json:"swapIO"`
	DiskIO struct {
		Read  uint64 `json:"read"`
		Write uint64 `json:"write"`
	} `json:"diskIO"`
	// The cumulative counters those two rates are differenced against. Off the
	// wire for the same reason netIfaceTotals is: the dashboard wants rates, and
	// shipping both only invites the two to be confused.
	swapTotals struct{ in, out uint64 }
	diskTotals struct{ read, write uint64 }

	NetIOByIface []NetIOIface `json:"netIOByIface"`
	// netIfaceTotals is the previous poll's CUMULATIVE per-interface counters. It
	// rides along on the Status because that is where the delta partner already
	// lives (see NetTraffic below), but it stays off the wire: the dashboard wants
	// rates, and shipping both would only invite the two to be confused.
	netIfaceTotals map[string]netIfaceTotal
	NetTraffic     struct {
		Sent uint64 `json:"sent"`
		Recv uint64 `json:"recv"`
	} `json:"netTraffic"`
	PublicIP struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
		// LocalIP4 lists every public IPv4 address assigned to the machine's
		// up, non-loopback interfaces. The dashboard renders these as
		// "IPv4 +n" rows so a server with several bound public addresses
		// shows them all, not just the public exit IP in IPv4 above. Private
		// LAN/Docker/APIPA/CGNAT addresses are excluded on purpose.
		LocalIP4 []string `json:"localIp4"`
	} `json:"publicIP"`
	AppStats struct {
		Threads uint32 `json:"threads"`
		Mem     uint64 `json:"mem"`
		Uptime  uint64 `json:"uptime"`
	} `json:"appStats"`
}

// NetIOIface is one network interface's throughput. Up and Down are RATES in
// bytes per second, matching the aggregate NetIO, so the dashboard's interface
// picker can swap between them without rescaling anything.
type NetIOIface struct {
	Name string `json:"name"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// netIfaceTotal holds one interface's cumulative byte counters between polls.
type netIfaceTotal struct {
	sent uint64
	recv uint64
}

// Release represents information about a software release from GitHub.
type Release struct {
	TagName string `json:"tag_name"` // The tag name of the release
	Name    string `json:"name"`     // The release title, usually just the version
	// Body is the release notes, as Markdown. The panel's own releases keep to a
	// short "## Added / ## Fixed" shape, which is what the overview's update
	// dialog renders before the operator commits to installing.
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
}

// ServerService provides business logic for server monitoring and management.
// It handles system status collection, IP detection, and application statistics.
type ServerService struct {
	xrayService        XrayService
	inboundService     InboundService
	l2tpService        L2tpService
	pptpService        PptpService
	cachedIPv4         string
	cachedIPv6         string
	noIPv6             bool
	mu                 sync.Mutex
	lastCPUTimes       cpu.TimesStat
	hasLastCPUSample   bool
	hasNativeCPUSample bool
	// Baseline for the native /proc/stat sampler, owned by THIS service so two
	// ServerService instances polling on different schedules cannot consume each
	// other's measurement interval (see sampleCPUUtilization).
	lastCPUIdleAll     uint64
	lastCPUTotal       uint64
	emaCPU             float64
	cpuHistory         []CPUSample
	cachedCpuSpeedMhz  float64
	cachedCpuModel     string
	lastCpuInfoAttempt time.Time
	// Host identity: distro name/version and kernel release. None of them change
	// while the panel runs, so they are read once instead of on every 2s poll.
	hostInfoLoaded  bool
	cachedOsName    string
	cachedOsVersion string
	cachedKernel    string
	cachedHostname  string
	cachedVirt      VirtInfo
	cachedMemHW     MemHardware
}

// AggregateCpuHistory returns up to maxPoints averaged buckets of size bucketSeconds over recent data.
func (s *ServerService) AggregateCpuHistory(bucketSeconds int, maxPoints int) []map[string]any {
	if bucketSeconds <= 0 || maxPoints <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-time.Duration(bucketSeconds*maxPoints) * time.Second).Unix()
	s.mu.Lock()
	// find start index (history sorted ascending)
	hist := s.cpuHistory
	// binary-ish scan (simple linear from end since size capped ~10800 is fine)
	startIdx := 0
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i].T < cutoff {
			startIdx = i + 1
			break
		}
	}
	if startIdx >= len(hist) {
		s.mu.Unlock()
		return []map[string]any{}
	}
	slice := hist[startIdx:]
	// copy for unlock
	tmp := make([]CPUSample, len(slice))
	copy(tmp, slice)
	s.mu.Unlock()
	if len(tmp) == 0 {
		return []map[string]any{}
	}
	var out []map[string]any
	var acc []float64
	bSize := int64(bucketSeconds)
	curBucket := (tmp[0].T / bSize) * bSize
	flush := func(ts int64) {
		if len(acc) == 0 {
			return
		}
		sum := 0.0
		for _, v := range acc {
			sum += v
		}
		avg := sum / float64(len(acc))
		out = append(out, map[string]any{"t": ts, "cpu": avg})
		acc = acc[:0]
	}
	for _, p := range tmp {
		b := (p.T / bSize) * bSize
		if b != curBucket {
			flush(curBucket)
			curBucket = b
		}
		acc = append(acc, p.Cpu)
	}
	flush(curBucket)
	if len(out) > maxPoints {
		out = out[len(out)-maxPoints:]
	}
	return out
}

// CPUSample single CPU utilization sample
type CPUSample struct {
	T   int64   `json:"t"`   // unix seconds
	Cpu float64 `json:"cpu"` // percent 0..100
}

type LogEntry struct {
	DateTime    time.Time
	FromAddress string
	ToAddress   string
	Inbound     string
	Outbound    string
	Email       string
	Event       int
}

// publicIPv4Services are the endpoints tried in order to discover the server's
// public IPv4 (first non-"N/A" wins). Shared by the dashboard status poll and
// the CLI URL printout so both resolve the IP the same way.
var publicIPv4Services = []string{
	"https://api4.ipify.org",
	"https://ipv4.icanhazip.com",
	"https://v4.api.ipinfo.io/ip",
	"https://ipv4.myexternalip.com/raw",
	"https://4.ident.me",
	"https://check-host.net/ip",
}

// GetServerIPv4 returns the server's public IPv4 using the same probe list the
// dashboard status uses, or "N/A" if none respond. Uncached — intended for
// one-shot CLI use (e.g. printing the panel URL after `--random`).
func GetServerIPv4() string {
	for _, url := range publicIPv4Services {
		if ip := getPublicIP(url); ip != "N/A" {
			return ip
		}
	}
	return "N/A"
}

func getPublicIP(url string) string {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "N/A"
	}
	defer resp.Body.Close()

	// Don't retry if access is blocked or region-restricted
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnavailableForLegalReasons {
		return "N/A"
	}
	if resp.StatusCode != http.StatusOK {
		return "N/A"
	}

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "N/A"
	}

	ipString := strings.TrimSpace(string(ip))
	if ipString == "" {
		return "N/A"
	}

	return ipString
}

// wholeDiskRe matches whole block devices and deliberately NOT their partitions:
// sda but not sda1, nvme0n1 but not nvme0n1p1, mmcblk0 but not mmcblk0p1. loop,
// ram, device-mapper and md nodes are excluded entirely because their bytes are
// already counted on the physical device underneath.
var wholeDiskRe = regexp.MustCompile(`^(?:(?:[shvx]|xv)d[a-z]+|nvme\d+n\d+|mmcblk\d+)$`)

func isWholeDisk(name string) bool { return wholeDiskRe.MatchString(name) }

// pollSeconds is the interval between two status samples, in seconds.
func pollSeconds(now time.Time, prev time.Time) float64 {
	if prev.IsZero() {
		return 0
	}
	return float64(now.Sub(prev)) / float64(time.Second)
}

// perSecond turns two readings of a cumulative counter into a rate. A counter
// that went BACKWARDS means it was reset (a device reappeared, or the panel was
// restarted); report 0 for that poll rather than an unsigned underflow, which
// would render as an exabyte-per-second spike and wreck the chart's scale.
func perSecond(current, previous uint64, seconds float64) uint64 {
	if current < previous || seconds <= 0 {
		return 0
	}
	return uint64(float64(current-previous) / seconds)
}

func (s *ServerService) GetStatus(lastStatus *Status) *Status {
	now := time.Now()
	status := &Status{
		T: now,
	}

	// CPU stats
	util, err := s.sampleCPUUtilization()
	if err != nil {
		logger.Warning("get cpu percent failed:", err)
	} else {
		status.Cpu = util
	}

	status.CpuCores, err = cpu.Counts(false)
	if err != nil {
		logger.Warning("get cpu cores count failed:", err)
	}

	status.LogicalPro = runtime.NumCPU()

	if status.CpuSpeedMhz = s.cachedCpuSpeedMhz; s.cachedCpuSpeedMhz == 0 && time.Since(s.lastCpuInfoAttempt) > 5*time.Minute {
		s.lastCpuInfoAttempt = time.Now()
		done := make(chan struct{})
		go func() {
			defer close(done)
			cpuInfos, err := cpu.Info()
			if err != nil {
				logger.Warning("get cpu info failed:", err)
				return
			}
			if len(cpuInfos) > 0 {
				s.cachedCpuSpeedMhz = cpuInfos[0].Mhz
				// The model name comes out of the SAME query, so it is cached here rather
				// than costing a second cpu.Info() on a poll that runs every 2 seconds.
				s.cachedCpuModel = strings.TrimSpace(cpuInfos[0].ModelName)
				status.CpuSpeedMhz = s.cachedCpuSpeedMhz
			} else {
				logger.Warning("could not find cpu info")
			}
		}()
		select {
		case <-done:
		case <-time.After(1500 * time.Millisecond):
			logger.Warning("cpu info query timed out; will retry later")
		}
	} else if s.cachedCpuSpeedMhz != 0 {
		status.CpuSpeedMhz = s.cachedCpuSpeedMhz
	}
	status.CpuModel = s.cachedCpuModel

	// Uptime
	// This process's own uptime, alongside the host's below.
	status.AppUptime = uint64(time.Since(panelStartedAt).Seconds())

	upTime, err := host.Uptime()
	if err != nil {
		logger.Warning("get uptime failed:", err)
	} else {
		status.Uptime = upTime
	}

	// Host identity, read once. osReleaseField is the same /etc/os-release reader the
	// distro-support check uses (pkgmgr.go), so the dashboard and the unsupported-distro
	// warning cannot disagree about what this host is.
	if !s.hostInfoLoaded {
		s.hostInfoLoaded = true
		// NAME is the plain distro name ("Ubuntu", "Debian GNU/Linux"); ID is the
		// lowercase fallback for the rare image that ships no NAME.
		if s.cachedOsName = osReleaseField("NAME"); s.cachedOsName == "" {
			s.cachedOsName = osReleaseField("ID")
		}
		s.cachedOsVersion = osReleaseField("VERSION_ID")
		kernel, err := host.KernelVersion()
		if err != nil {
			logger.Warning("get kernel version failed:", err)
		} else {
			s.cachedKernel = kernel
		}
		// The machine's own hostname. Distinct from the browser Host header the
		// templates expose as {{ .host }}, which is whatever address the admin
		// typed and is often an IP.
		if hn, err := os.Hostname(); err != nil {
			logger.Warning("get hostname failed:", err)
		} else {
			s.cachedHostname = hn
		}
		s.cachedVirt = DetectVirtualization()
		// SMBIOS describes the DIMMs in the physical machine. Inside a container
		// those are the HOST's, while this guest's memory is a cgroup limit that
		// has nothing to do with them, so the read is skipped and the overview
		// falls back to MemTotal.
		if s.cachedVirt.Kind != "container" {
			s.cachedMemHW = DetectMemHardware()
		}
	}
	status.OsName = s.cachedOsName
	status.OsVersion = s.cachedOsVersion
	status.Kernel = s.cachedKernel
	status.Hostname = s.cachedHostname
	status.Virt = s.cachedVirt
	status.MemHW = s.cachedMemHW

	// Memory stats
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		logger.Warning("get virtual memory failed:", err)
	} else {
		status.Mem.Current = memInfo.Used
		status.Mem.Total = memInfo.Total
	}

	swapInfo, err := mem.SwapMemory()
	if err != nil {
		logger.Warning("get swap memory failed:", err)
	} else {
		status.Swap.Current = swapInfo.Used
		status.Swap.Total = swapInfo.Total
		// Sin/Sout are cumulative bytes paged in/out since boot (Linux reads them
		// from /proc/vmstat), so the rate is their delta over the poll interval.
		status.swapTotals.in, status.swapTotals.out = swapInfo.Sin, swapInfo.Sout
		if lastStatus != nil {
			if seconds := pollSeconds(now, lastStatus.T); seconds > 0 {
				status.SwapIO.In = perSecond(swapInfo.Sin, lastStatus.swapTotals.in, seconds)
				status.SwapIO.Out = perSecond(swapInfo.Sout, lastStatus.swapTotals.out, seconds)
			}
		}
	}

	// Disk stats
	diskInfo, err := disk.Usage("/")
	if err != nil {
		logger.Warning("get disk usage failed:", err)
	} else {
		status.Disk.Current = diskInfo.Used
		status.Disk.Total = diskInfo.Total
	}

	// Disk THROUGHPUT, summed over whole disks only. /proc/diskstats lists
	// partitions and device-mapper nodes alongside the disks they live on, so
	// adding every row up would count the same bytes two or three times.
	if ioCounters, err := disk.IOCounters(); err != nil {
		logger.Warning("get disk io counters failed:", err)
	} else {
		var read, write uint64
		for name, c := range ioCounters {
			if !isWholeDisk(name) {
				continue
			}
			read += c.ReadBytes
			write += c.WriteBytes
		}
		status.diskTotals.read, status.diskTotals.write = read, write
		if lastStatus != nil {
			if seconds := pollSeconds(now, lastStatus.T); seconds > 0 {
				status.DiskIO.Read = perSecond(read, lastStatus.diskTotals.read, seconds)
				status.DiskIO.Write = perSecond(write, lastStatus.diskTotals.write, seconds)
			}
		}
	}

	// Load averages
	avgState, err := load.Avg()
	if err != nil {
		logger.Warning("get load avg failed:", err)
	} else {
		status.Loads = []float64{avgState.Load1, avgState.Load5, avgState.Load15}
	}

	// Network stats
	ioStats, err := net.IOCounters(false)
	if err != nil {
		logger.Warning("get io counters failed:", err)
	} else if len(ioStats) > 0 {
		ioStat := ioStats[0]
		status.NetTraffic.Sent = ioStat.BytesSent
		status.NetTraffic.Recv = ioStat.BytesRecv

		if lastStatus != nil {
			duration := now.Sub(lastStatus.T)
			seconds := float64(duration) / float64(time.Second)
			up := uint64(float64(status.NetTraffic.Sent-lastStatus.NetTraffic.Sent) / seconds)
			down := uint64(float64(status.NetTraffic.Recv-lastStatus.NetTraffic.Recv) / seconds)
			status.NetIO.Up = up
			status.NetIO.Down = down
		}
	} else {
		logger.Warning("can not find io counters")
	}

	// Per-interface network stats, for the dashboard's interface picker. Derived from
	// the delta against the previous poll exactly like the aggregate above, so these
	// are rates and not the cumulative counters gopsutil hands back.
	ifaceStats, err := net.IOCounters(true)
	if err != nil {
		logger.Warning("get per-interface io counters failed:", err)
	} else {
		selectable := s.selectableInterfaces()
		status.netIfaceTotals = make(map[string]netIfaceTotal, len(ifaceStats))
		status.NetIOByIface = make([]NetIOIface, 0, len(ifaceStats))
		seconds := 0.0
		if lastStatus != nil {
			seconds = float64(now.Sub(lastStatus.T)) / float64(time.Second)
		}
		for _, ifaceStat := range ifaceStats {
			if !selectable[ifaceStat.Name] {
				continue
			}
			status.netIfaceTotals[ifaceStat.Name] = netIfaceTotal{sent: ifaceStat.BytesSent, recv: ifaceStat.BytesRecv}
			row := NetIOIface{Name: ifaceStat.Name}
			if prev, ok := lastStatus.netIfaceTotal(ifaceStat.Name); ok && seconds > 0 {
				// A counter that went BACKWARDS means the interface was torn down and
				// recreated between polls (routine here: every VPN protocol brings its own
				// up and down). Report 0 for that poll instead of an unsigned underflow
				// that would render as an exabyte-per-second spike.
				if ifaceStat.BytesSent >= prev.sent {
					row.Up = uint64(float64(ifaceStat.BytesSent-prev.sent) / seconds)
				}
				if ifaceStat.BytesRecv >= prev.recv {
					row.Down = uint64(float64(ifaceStat.BytesRecv-prev.recv) / seconds)
				}
			}
			status.NetIOByIface = append(status.NetIOByIface, row)
		}
		// /proc/net/dev order is not stable across polls, and a picker that reshuffles
		// itself under the cursor is unusable.
		sort.Slice(status.NetIOByIface, func(i, j int) bool {
			return status.NetIOByIface[i].Name < status.NetIOByIface[j].Name
		})
	}

	// TCP/UDP connections
	status.TcpCount, err = sys.GetTCPCount()
	if err != nil {
		logger.Warning("get tcp connections failed:", err)
	}

	status.UdpCount, err = sys.GetUDPCount()
	if err != nil {
		logger.Warning("get udp connections failed:", err)
	}

	// 1) Collect public IPs from local interfaces (NICs). If the server has a
	// public IP directly on an interface, use that as the primary address — it's
	// authoritative and doesn't depend on external services.
	localPubIPs := localIPv4Addresses()

	// 2) IP fetching with caching (external services) — only used if no local
	// public IP is present.
	showIp4ServiceLists := publicIPv4Services
	showIp6ServiceLists := []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.api.ipinfo.io/ip",
		"https://ipv6.myexternalip.com/raw",
		"https://6.ident.me",
	}

	if s.cachedIPv4 == "" {
		for _, ip4Service := range showIp4ServiceLists {
			s.cachedIPv4 = getPublicIP(ip4Service)
			if s.cachedIPv4 != "N/A" {
				break
			}
		}
	}

	if s.cachedIPv6 == "" && !s.noIPv6 {
		for _, ip6Service := range showIp6ServiceLists {
			s.cachedIPv6 = getPublicIP(ip6Service)
			if s.cachedIPv6 != "N/A" {
				break
			}
		}
	}

	if s.cachedIPv6 == "N/A" {
		s.noIPv6 = true
	}

	// Prefer a public IP from the local NIC; fall back to external detection.
	if len(localPubIPs) > 0 {
		status.PublicIP.IPv4 = localPubIPs[0]
	} else {
		status.PublicIP.IPv4 = s.cachedIPv4
	}
	status.PublicIP.IPv6 = s.cachedIPv6
	status.PublicIP.LocalIP4 = localPubIPs

	// Xray status
	if s.xrayService.IsXrayRunning() {
		status.Xray.State = Running
		status.Xray.ErrorMsg = ""
	} else {
		err := s.xrayService.GetXrayErr()
		if err != nil {
			status.Xray.State = Error
		} else {
			status.Xray.State = Stop
		}
		status.Xray.ErrorMsg = s.xrayService.GetXrayResult()
	}
	status.Xray.Version = s.xrayService.GetXrayVersion()

	// Application stats
	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)
	status.AppStats.Mem = rtm.Sys
	status.AppStats.Threads = uint32(runtime.NumGoroutine())
	if p != nil && p.IsRunning() {
		status.AppStats.Uptime = p.GetUptime()
	} else {
		status.AppStats.Uptime = 0
	}

	return status
}

// netIfaceTotal looks up an interface's previous cumulative counters. It is
// nil-safe on the receiver so the first poll, which has no predecessor, reads the
// same as an interface that has only just appeared.
func (s *Status) netIfaceTotal(name string) (netIfaceTotal, bool) {
	if s == nil {
		return netIfaceTotal{}, false
	}
	prev, ok := s.netIfaceTotals[name]
	return prev, ok
}

// selectableInterfaces is the set of interface names worth offering in the
// dashboard's picker: up, and not loopback. Loopback traffic is the panel talking
// to itself, and a down interface only pads the list.
func (s *ServerService) selectableInterfaces() map[string]bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Warning("get network interfaces failed:", err)
		return nil
	}
	selectable := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		isUp, isLoopback := false, false
		for _, flag := range iface.Flags {
			switch flag {
			case "up":
				isUp = true
			case "loopback":
				isLoopback = true
			}
		}
		if isUp && !isLoopback {
			selectable[iface.Name] = true
		}
	}
	return selectable
}

// localIPv4Addresses returns every IPv4 address on an up, non-loopback
// interface, deduplicated and sorted. This covers the secondary addresses a
// hosting provider binds next to the main one, which the public-IP probe can
// never report; the dashboard shows them as the "IPv4 +n" rows.
func localIPv4Addresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Warning("get network interfaces failed:", err)
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, iface := range ifaces {
		isUp, isLoopback := false, false
		for _, flag := range iface.Flags {
			switch flag {
			case "up":
				isUp = true
			case "loopback":
				isLoopback = true
			}
		}
		if !isUp || isLoopback {
			continue
		}
		for _, a := range iface.Addrs {
			addr, _, err := gonet.ParseCIDR(a.Addr)
			if err != nil {
				addr = gonet.ParseIP(a.Addr)
			}
			ip4 := addr.To4()
			if ip4 == nil {
				continue
			}
			// Only surface public addresses. The dashboard's "IPv4 +n" rows
			// exist to reveal extra public addresses a host binds, never the
			// LAN, Docker bridge, APIPA or CGNAT addresses that sit on the
			// same machine (e.g. 10.x, 172.16/12, 192.168.x, 169.254.x,
			// 100.64/10). Those should stay internal.
			if ip4.IsPrivate() {
				continue
			}
			s := ip4.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *ServerService) AppendCpuSample(t time.Time, v float64) {
	const capacity = 9000 // ~5 hours @ 2s interval
	s.mu.Lock()
	defer s.mu.Unlock()
	p := CPUSample{T: t.Unix(), Cpu: v}
	if n := len(s.cpuHistory); n > 0 && s.cpuHistory[n-1].T == p.T {
		s.cpuHistory[n-1] = p
	} else {
		s.cpuHistory = append(s.cpuHistory, p)
	}
	if len(s.cpuHistory) > capacity {
		s.cpuHistory = s.cpuHistory[len(s.cpuHistory)-capacity:]
	}
}

func (s *ServerService) sampleCPUUtilization() (float64, error) {
	// Try native platform-specific CPU implementation first (Linux, macOS).
	//
	// The baseline is per-ServerService. It used to live in the sys package as a
	// package-level pair of counters, which meant the dashboard's 2s poll and the
	// Telegram bot's usage report (a SEPARATE ServerService, web/service/tgbot.go)
	// consumed each other's intervals: whichever ran second measured a window that
	// started at the other one's read, and fed that bogus percentage into its own EMA.
	if idleAll, total, err := sys.CPUTimesRaw(); err == nil {
		s.mu.Lock()
		prevIdle, prevTotal := s.lastCPUIdleAll, s.lastCPUTotal
		s.lastCPUIdleAll, s.lastCPUTotal = idleAll, total
		// First call establishes the baseline; there is no interval to measure yet.
		if !s.hasNativeCPUSample {
			s.hasNativeCPUSample = true
			s.mu.Unlock()
			return 0, nil
		}
		// A counter that went backwards (or stood still) has no usable delta; keep
		// the last smoothed value rather than reporting a spurious 0%.
		if total <= prevTotal || idleAll < prevIdle {
			val := s.emaCPU
			s.mu.Unlock()
			return val, nil
		}
		totald := total - prevTotal
		busy := totald - (idleAll - prevIdle)
		pct := float64(busy) / float64(totald) * 100.0
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		// Smooth with EMA
		const alpha = 0.3
		if s.emaCPU == 0 {
			s.emaCPU = pct
		} else {
			s.emaCPU = alpha*pct + (1-alpha)*s.emaCPU
		}
		val := s.emaCPU
		s.mu.Unlock()
		return val, nil
	}
	// If native call fails, fall back to gopsutil times
	// Read aggregate CPU times (all CPUs combined)
	times, err := cpu.Times(false)
	if err != nil {
		return 0, err
	}
	if len(times) == 0 {
		return 0, fmt.Errorf("no cpu times available")
	}

	cur := times[0]

	s.mu.Lock()
	defer s.mu.Unlock()

	// If this is the first sample, initialize and return current EMA (0 by default)
	if !s.hasLastCPUSample {
		s.lastCPUTimes = cur
		s.hasLastCPUSample = true
		return s.emaCPU, nil
	}

	// Compute busy and total deltas
	// Note: Guest and GuestNice times are already included in User and Nice respectively,
	// so we exclude them to avoid double-counting (Linux kernel accounting)
	idleDelta := cur.Idle - s.lastCPUTimes.Idle
	busyDelta := (cur.User - s.lastCPUTimes.User) +
		(cur.System - s.lastCPUTimes.System) +
		(cur.Nice - s.lastCPUTimes.Nice) +
		(cur.Iowait - s.lastCPUTimes.Iowait) +
		(cur.Irq - s.lastCPUTimes.Irq) +
		(cur.Softirq - s.lastCPUTimes.Softirq) +
		(cur.Steal - s.lastCPUTimes.Steal)

	totalDelta := busyDelta + idleDelta

	// Update last sample for next time
	s.lastCPUTimes = cur

	// Guard against division by zero or negative deltas (e.g., counter resets)
	if totalDelta <= 0 {
		return s.emaCPU, nil
	}

	raw := 100.0 * (busyDelta / totalDelta)
	if raw < 0 {
		raw = 0
	}
	if raw > 100 {
		raw = 100
	}

	// Exponential moving average to smooth spikes
	const alpha = 0.3 // smoothing factor (0<alpha<=1). Higher = more responsive, lower = smoother
	if s.emaCPU == 0 {
		// Initialize EMA with the first real reading to avoid long warm-up from zero
		s.emaCPU = raw
	} else {
		s.emaCPU = alpha*raw + (1-alpha)*s.emaCPU
	}

	return s.emaCPU, nil
}

func (s *ServerService) GetXrayVersions() ([]string, error) {
	const (
		XrayURL    = "https://api.github.com/repos/XTLS/Xray-core/releases"
		bufferSize = 8192
		maxBody    = 10 << 20 // 10 MiB limit for releases listing
	)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(XrayURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP status code - GitHub API returns object instead of array on error
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errorResponse struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(bodyBytes, &errorResponse) == nil && errorResponse.Message != "" {
			return nil, fmt.Errorf("GitHub API error: %s", errorResponse.Message)
		}
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	buffer := bytes.NewBuffer(make([]byte, bufferSize))
	buffer.Reset()
	if _, err := buffer.ReadFrom(io.LimitReader(resp.Body, maxBody)); err != nil {
		return nil, err
	}

	var releases []Release
	if err := json.Unmarshal(buffer.Bytes(), &releases); err != nil {
		return nil, err
	}

	var versions []string
	for _, release := range releases {
		tagVersion := strings.TrimPrefix(release.TagName, "v")
		tagParts := strings.Split(tagVersion, ".")
		if len(tagParts) != 3 {
			continue
		}

		major, err1 := strconv.Atoi(tagParts[0])
		minor, err2 := strconv.Atoi(tagParts[1])
		patch, err3 := strconv.Atoi(tagParts[2])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}

		if major > 26 || (major == 26 && minor > 3) || (major == 26 && minor == 3 && patch >= 10) {
			versions = append(versions, release.TagName)
		}
	}
	return versions, nil
}

func (s *ServerService) StopXrayService() error {
	err := s.xrayService.StopXray()
	if err != nil {
		logger.Error("stop xray failed:", err)
		return err
	}
	return nil
}

func (s *ServerService) RestartXrayService() error {
	err := s.xrayService.RestartXray(true)
	if err != nil {
		logger.Error("start xray failed:", err)
		return err
	}
	return nil
}

func (s *ServerService) downloadXRay(version string) (string, error) {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	switch osName {
	case "darwin":
		osName = "macos"
	case "windows":
		osName = "windows"
	}

	switch arch {
	case "amd64":
		arch = "64"
	case "arm64":
		arch = "arm64-v8a"
	case "armv7":
		arch = "arm32-v7a"
	case "armv6":
		arch = "arm32-v6"
	case "armv5":
		arch = "arm32-v5"
	case "386":
		arch = "32"
	case "s390x":
		arch = "s390x"
	}

	fileName := fmt.Sprintf("Xray-%s-%s.zip", osName, arch)
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/%s", version, fileName)

	const maxDownload = 200 << 20 // 200 MiB limit for Xray binary
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	os.Remove(fileName)
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = io.Copy(file, io.LimitReader(resp.Body, maxDownload))
	if err != nil {
		os.Remove(fileName)
		return "", err
	}

	return fileName, nil
}

// UpdateXray is intentionally disabled. This panel ships a SPECIFIC pinned Xray
// core — a patched fork baked into the binary (see the corebundle package) whose
// Shadowsocks method-fallback fix the whole product depends on. That exact core
// is extracted and made authoritative on every startup, so switching or updating
// it from the dashboard is forbidden: it would replace the vetted core with an
// arbitrary upstream release. The dashboard hides the switch UI; this is the
// server-side guard so the API can't be driven directly either.
func (s *ServerService) UpdateXray(version string) error {
	return fmt.Errorf("the Xray core is bundled and locked to the panel's pinned build; changing or updating the core version is not allowed")
}

func (s *ServerService) GetLogs(count string, level string, syslog string) []string {
	c, _ := strconv.Atoi(count)
	var lines []string

	if syslog == "true" {
		// Validate and sanitize count parameter
		countInt, err := strconv.Atoi(count)
		if err != nil || countInt < 1 || countInt > 10000 {
			return []string{"Invalid count parameter - must be a number between 1 and 10000"}
		}

		// Validate level parameter - only allow valid syslog levels
		validLevels := map[string]bool{
			"0": true, "emerg": true,
			"1": true, "alert": true,
			"2": true, "crit": true,
			"3": true, "err": true,
			"4": true, "warning": true,
			"5": true, "notice": true,
			"6": true, "info": true,
			"7": true, "debug": true,
		}
		if !validLevels[level] {
			return []string{"Invalid level parameter - must be a valid syslog level"}
		}

		// Use hardcoded command with validated parameters
		cmd := exec.Command("journalctl", "-u", "vpn-ui", "--no-pager", "-n", strconv.Itoa(countInt), "-p", level)
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			return []string{"Failed to run journalctl command! Make sure systemd is available and vpn-ui service is registered."}
		}
		lines = strings.Split(out.String(), "\n")
	} else {
		lines = logger.GetLogs(c, level)
	}

	return lines
}

func (s *ServerService) GetXrayLogs(
	count string,
	filter string,
	showDirect string,
	showBlocked string,
	showProxy string,
	freedoms []string,
	blackholes []string) []LogEntry {

	const (
		Direct = iota
		Blocked
		Proxied
	)

	countInt, _ := strconv.Atoi(count)
	var entries []LogEntry

	pathToAccessLog, err := xray.GetAccessLogPath()
	if err != nil {
		return nil
	}

	file, err := os.Open(pathToAccessLog)
	if err != nil {
		// The IP-limit job drains the live access log into this archive every hour
		// (clearAccessLog in web/job/check_client_ip_job.go), so on a quiet box the
		// live file is regularly empty or absent while the recent history is here.
		// Without this the viewer reads as broken for most of every hour.
		file, err = os.Open(xray.GetAccessPersistentLogPath())
		if err != nil {
			return nil
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.Contains(line, "api -> api") {
			//skipping empty lines and api calls
			continue
		}

		if filter != "" && !strings.Contains(line, filter) {
			//applying filter if it's not empty
			continue
		}

		var entry LogEntry
		parts := strings.Fields(line)

		for i, part := range parts {

			if i == 0 {
				dateTime, err := time.ParseInLocation("2006/01/02 15:04:05.999999", parts[0]+" "+parts[1], time.Local)
				if err != nil {
					continue
				}
				entry.DateTime = dateTime.UTC()
			}

			if part == "from" {
				entry.FromAddress = strings.TrimLeft(parts[i+1], "/")
			} else if part == "accepted" {
				entry.ToAddress = strings.TrimLeft(parts[i+1], "/")
			} else if strings.HasPrefix(part, "[") {
				entry.Inbound = part[1:]
			} else if strings.HasSuffix(part, "]") {
				entry.Outbound = part[:len(part)-1]
			} else if part == "email:" {
				entry.Email = parts[i+1]
			}
		}

		if logEntryContains(line, freedoms) {
			if showDirect == "false" {
				continue
			}
			entry.Event = Direct
		} else if logEntryContains(line, blackholes) {
			if showBlocked == "false" {
				continue
			}
			entry.Event = Blocked
		} else {
			if showProxy == "false" {
				continue
			}
			entry.Event = Proxied
		}

		entries = append(entries, entry)
	}

	if len(entries) > countInt {
		entries = entries[len(entries)-countInt:]
	}

	return entries
}

func logEntryContains(line string, suffixes []string) bool {
	for _, sfx := range suffixes {
		if strings.Contains(line, sfx+"]") {
			return true
		}
	}
	return false
}

func (s *ServerService) GetConfigJson() (any, error) {
	config, err := s.xrayService.GetXrayConfig()
	if err != nil {
		return nil, err
	}
	contents, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}

	var jsonData any
	err = json.Unmarshal(contents, &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func (s *ServerService) GetDb() ([]byte, error) {
	// Update by manually trigger a checkpoint operation
	err := database.Checkpoint()
	if err != nil {
		return nil, err
	}
	// Open the file for reading
	file, err := os.Open(config.GetDBPath())
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read the file contents
	fileContents, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return fileContents, nil
}

// LocalBackupInfo describes one database backup stored on the panel.
type LocalBackupInfo struct {
	FileName string `json:"fileName"`
	Size     int64  `json:"size"`
	Created  int64  `json:"created"` // unix seconds
}

// GetBackupFolder ensures the local backup folder exists and returns its path.
func (s *ServerService) GetBackupFolder() (string, error) {
	dir := config.GetBackupFolderPath()
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", err
	}
	return dir, nil
}

// CreateLocalBackup checkpoints the live DB and copies it into the backup folder
// with a timestamped name, returning the created backup. The panel keeps on
// working while the copy is made; this is the on-panel twin of the browser
// download (getDb), so an operator can restore a known-good state later without
// having a copy on their own machine.
func (s *ServerService) CreateLocalBackup() (*LocalBackupInfo, error) {
	if err := database.Checkpoint(); err != nil {
		return nil, err
	}
	dir, err := s.GetBackupFolder()
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("vpn-ui_%s.db", time.Now().Format("20060102_150405"))
	dst := filepath.Join(dir, name)
	src, err := os.Open(config.GetDBPath())
	if err != nil {
		return nil, err
	}
	defer src.Close()
	out, err := os.Create(dst)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		os.Remove(dst)
		return nil, err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return nil, err
	}
	st, err := os.Stat(dst)
	if err != nil {
		return nil, err
	}
	return &LocalBackupInfo{FileName: name, Size: st.Size(), Created: st.ModTime().Unix()}, nil
}

// ListLocalBackups returns the database backups stored on the panel, newest first.
func (s *ServerService) ListLocalBackups() ([]LocalBackupInfo, error) {
	dir, err := s.GetBackupFolder()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []LocalBackupInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, LocalBackupInfo{FileName: e.Name(), Size: info.Size(), Created: info.ModTime().Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out, nil
}

// RestoreLocalBackup restores the named on-panel backup over the current
// database. It reuses ImportDB wholesale, so the backup is validated, migrated
// to the current schema, and Xray is restarted exactly as an uploaded file would
// be. The name is strictly validated to stop path traversal.
func (s *ServerService) RestoreLocalBackup(fileName string) error {
	if fileName == "" || strings.Contains(fileName, "/") || strings.Contains(fileName, "\\") ||
		strings.Contains(fileName, "..") {
		return common.NewErrorf("Invalid backup name: %q", fileName)
	}
	dir, err := s.GetBackupFolder()
	if err != nil {
		return err
	}
	src, err := os.Open(filepath.Join(dir, fileName))
	if err != nil {
		return common.NewErrorf("Backup not found: %v", err)
	}
	defer src.Close()
	return s.ImportDB(src)
}

func (s *ServerService) ImportDB(file multipart.File) error {
	// Check if the file is a SQLite database
	isValidDb, err := database.IsSQLiteDB(file)
	if err != nil {
		return common.NewErrorf("Error checking db file format: %v", err)
	}
	if !isValidDb {
		return common.NewError("Invalid db file format")
	}

	// Reset the file reader to the beginning
	_, err = file.Seek(0, 0)
	if err != nil {
		return common.NewErrorf("Error resetting file reader: %v", err)
	}

	// Save the file as a temporary file
	tempPath := fmt.Sprintf("%s.temp", config.GetDBPath())

	// Remove the existing temporary file (if any)
	if _, err := os.Stat(tempPath); err == nil {
		if errRemove := os.Remove(tempPath); errRemove != nil {
			return common.NewErrorf("Error removing existing temporary db file: %v", errRemove)
		}
	}

	// Create the temporary file
	tempFile, err := os.Create(tempPath)
	if err != nil {
		return common.NewErrorf("Error creating temporary db file: %v", err)
	}

	// Robust deferred cleanup for the temporary file
	defer func() {
		if tempFile != nil {
			if cerr := tempFile.Close(); cerr != nil {
				logger.Warningf("Warning: failed to close temp file: %v", cerr)
			}
		}
		if _, err := os.Stat(tempPath); err == nil {
			if rerr := os.Remove(tempPath); rerr != nil {
				logger.Warningf("Warning: failed to remove temp file: %v", rerr)
			}
		}
	}()

	// Save uploaded file to temporary file
	if _, err = io.Copy(tempFile, file); err != nil {
		return common.NewErrorf("Error saving db: %v", err)
	}

	// Close temp file before opening via sqlite
	if err = tempFile.Close(); err != nil {
		return common.NewErrorf("Error closing temporary db file: %v", err)
	}
	tempFile = nil

	// Validate integrity (no migrations / side effects)
	if err = database.ValidateSQLiteDB(tempPath); err != nil {
		return common.NewErrorf("Invalid or corrupt db file: %v", err)
	}

	// Snapshot the settings that must survive the swap, from the live DB, while it
	// is still the current one. Restoring a backup (even another panel's) must not
	// move this panel's own reachability/identity: its port, path, listen address,
	// TLS certs, session secret and session lifetime describe the running install,
	// and importing a backup's copies would change the cookie secret / base path /
	// secure flag under a logged-in session and silently log everyone out. This is
	// the same preservation ImportForeignDB applies; for a like-for-like restore of
	// this panel's own backup it writes the same values back and is a no-op.
	preserved := s.snapshotPreservedSettings()

	// Stop Xray (ignore error but log)
	if errStop := s.StopXrayService(); errStop != nil {
		logger.Warningf("Failed to stop Xray before DB import: %v", errStop)
	}

	// Close existing DB to release file locks (especially on Windows)
	if errClose := database.CloseDB(); errClose != nil {
		logger.Warningf("Failed to close existing DB before replacement: %v", errClose)
	}

	// Backup the current database for fallback
	fallbackPath := fmt.Sprintf("%s.backup", config.GetDBPath())

	// Remove the existing fallback file (if any)
	if _, err := os.Stat(fallbackPath); err == nil {
		if errRemove := os.Remove(fallbackPath); errRemove != nil {
			return common.NewErrorf("Error removing existing fallback db file: %v", errRemove)
		}
	}

	// Move the current database to the fallback location
	if err = os.Rename(config.GetDBPath(), fallbackPath); err != nil {
		return common.NewErrorf("Error backing up current db file: %v", err)
	}
	// The -wal/-shm sidecars are named after the PATH, so they do not travel with
	// the rename above and would end up paired with the IMPORTED database. A WAL
	// from a different database is a corruption path. CloseDB normally removes
	// them, but its error is only logged, so this is the belt to that braces.
	database.RemoveSidecars(config.GetDBPath())

	// Defer fallback cleanup ONLY if everything goes well
	defer func() {
		if _, err := os.Stat(fallbackPath); err == nil {
			if rerr := os.Remove(fallbackPath); rerr != nil {
				logger.Warningf("Warning: failed to remove fallback file: %v", rerr)
			}
		}
	}()

	// Move temp to DB path
	if err = os.Rename(tempPath, config.GetDBPath()); err != nil {
		// Restore from fallback
		if errRename := os.Rename(fallbackPath, config.GetDBPath()); errRename != nil {
			return common.NewErrorf("Error moving db file and restoring fallback: %v", errRename)
		}
		return common.NewErrorf("Error moving db file: %v", err)
	}

	// Open & migrate new DB
	if err = database.InitDB(config.GetDBPath()); err != nil {
		if errRename := os.Rename(fallbackPath, config.GetDBPath()); errRename != nil {
			return common.NewErrorf("Error migrating db and restoring fallback: %v", errRename)
		}
		return common.NewErrorf("Error migrating db: %v", err)
	}

	// Put this panel's reachability/identity settings back over the backup's.
	if err = s.restorePreservedSettings(preserved); err != nil {
		return common.NewErrorf("Imported DB but failed to preserve panel settings: %v", err)
	}

	s.inboundService.MigrateDB()

	// Regenerate L2TP/PPTP on-disk configs from the imported DB and restart services
	s.l2tpService.InitL2tp()
	s.pptpService.InitPptp()

	// Start Xray
	if err = s.RestartXrayService(); err != nil {
		return common.NewErrorf("Imported DB but failed to start Xray: %v", err)
	}

	return nil
}

// IsValidGeofileName validates that the filename is safe for geofile operations.
// It checks for path traversal attempts and ensures the filename contains only safe characters.
func (s *ServerService) IsValidGeofileName(filename string) bool {
	return isSafeGeofileName(filename)
}

// UpdateGeofile downloads one built-in geo data file into bin/, or all of them
// when fileName is empty, then restarts Xray so the new data takes effect. The
// download itself lives in downloadGeofile (geofile.go), which EnsureGeofiles
// also uses. That one must not restart Xray, since it runs from inside the
// restart path.
func (s *ServerService) UpdateGeofile(fileName string) error {
	// Strict allowlist check to avoid writing uncontrolled files
	if fileName != "" {
		if _, ok := builtinGeofiles[fileName]; !ok {
			return common.NewErrorf("Invalid geofile name: %q not in allowlist", fileName)
		}
	}

	var errorMessages []string

	if fileName == "" {
		// Download all geofiles
		for _, entry := range builtinGeofiles {
			if err := downloadGeofile(entry, geofileManualMaxTime); err != nil {
				errorMessages = append(errorMessages, fmt.Sprintf("Error downloading Geofile '%s': %v", entry.FileName, err))
			}
		}
	} else {
		if err := downloadGeofile(builtinGeofiles[fileName], geofileManualMaxTime); err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf("Error downloading Geofile '%s': %v", fileName, err))
		}
	}

	err := s.RestartXrayService()
	if err != nil {
		errorMessages = append(errorMessages, fmt.Sprintf("Updated Geofile '%s' but Failed to start Xray: %v", fileName, err))
	}

	if len(errorMessages) > 0 {
		return common.NewErrorf("%s", strings.Join(errorMessages, "\r\n"))
	}

	return nil
}

func (s *ServerService) GetNewX25519Cert() (any, error) {
	// Run the command
	cmd := exec.Command(xray.GetBinaryPath(), "x25519")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out.String(), "\n")

	privateKeyLine := strings.Split(lines[0], ":")
	publicKeyLine := strings.Split(lines[1], ":")

	privateKey := strings.TrimSpace(privateKeyLine[1])
	publicKey := strings.TrimSpace(publicKeyLine[1])

	keyPair := map[string]any{
		"privateKey": privateKey,
		"publicKey":  publicKey,
	}

	return keyPair, nil
}

func (s *ServerService) GetNewmldsa65() (any, error) {
	// Run the command
	cmd := exec.Command(xray.GetBinaryPath(), "mldsa65")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out.String(), "\n")

	SeedLine := strings.Split(lines[0], ":")
	VerifyLine := strings.Split(lines[1], ":")

	seed := strings.TrimSpace(SeedLine[1])
	verify := strings.TrimSpace(VerifyLine[1])

	keyPair := map[string]any{
		"seed":   seed,
		"verify": verify,
	}

	return keyPair, nil
}

func (s *ServerService) GetNewEchCert(sni string) (any, error) {
	// Run the command
	cmd := exec.Command(xray.GetBinaryPath(), "tls", "ech", "--serverName", sni)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out.String(), "\n")
	if len(lines) < 4 {
		return nil, common.NewError("invalid ech cert")
	}

	configList := lines[1]
	serverKeys := lines[3]

	return map[string]any{
		"echServerKeys": serverKeys,
		"echConfigList": configList,
	}, nil
}

func (s *ServerService) GetNewVlessEnc() (any, error) {
	cmd := exec.Command(xray.GetBinaryPath(), "vlessenc")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	lines := strings.Split(out.String(), "\n")
	var auths []map[string]string
	var current map[string]string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Authentication:") {
			if current != nil {
				auths = append(auths, current)
			}
			current = map[string]string{
				"label": strings.TrimSpace(strings.TrimPrefix(line, "Authentication:")),
			}
		} else if strings.HasPrefix(line, `"decryption"`) || strings.HasPrefix(line, `"encryption"`) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && current != nil {
				key := strings.Trim(parts[0], `" `)
				val := strings.Trim(parts[1], `" `)
				current[key] = val
			}
		}
	}

	if current != nil {
		auths = append(auths, current)
	}

	return map[string]any{
		"auths": auths,
	}, nil
}

func (s *ServerService) GetNewUUID() (map[string]string, error) {
	newUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	return map[string]string{
		"uuid": newUUID.String(),
	}, nil
}

func (s *ServerService) GetNewmlkem768() (any, error) {
	// Run the command
	cmd := exec.Command(xray.GetBinaryPath(), "mlkem768")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out.String(), "\n")

	SeedLine := strings.Split(lines[0], ":")
	ClientLine := strings.Split(lines[1], ":")

	seed := strings.TrimSpace(SeedLine[1])
	client := strings.TrimSpace(ClientLine[1])

	keyPair := map[string]any{
		"seed":   seed,
		"client": client,
	}

	return keyPair, nil
}
