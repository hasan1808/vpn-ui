// Package web provides the main web server implementation for the vpn-ui panel,
// including HTTP/HTTPS serving, routing, templates, and background job scheduling.
package web

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/web/controller"
	"github.com/hasan1808/pro-ui/web/job"
	"github.com/hasan1808/pro-ui/web/locale"
	"github.com/hasan1808/pro-ui/web/middleware"
	"github.com/hasan1808/pro-ui/web/network"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/web/websocket"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
)

//go:embed assets
var assetsFS embed.FS

//go:embed html/*
var htmlFS embed.FS

//go:embed translation/*
var i18nFS embed.FS

var startTime = time.Now()

type wrapAssetsFS struct {
	embed.FS
}

func (f *wrapAssetsFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open("assets/" + name)
	if err != nil {
		return nil, err
	}
	return &wrapAssetsFile{
		File: file,
	}, nil
}

type wrapAssetsFile struct {
	fs.File
}

func (f *wrapAssetsFile) Stat() (fs.FileInfo, error) {
	info, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return &wrapAssetsFileInfo{
		FileInfo: info,
	}, nil
}

type wrapAssetsFileInfo struct {
	fs.FileInfo
}

func (f *wrapAssetsFileInfo) ModTime() time.Time {
	return startTime
}

// EmbeddedHTML returns the embedded HTML templates filesystem for reuse by other servers.
func EmbeddedHTML() embed.FS {
	return htmlFS
}

// EmbeddedAssets returns the embedded assets filesystem for reuse by other servers.
func EmbeddedAssets() embed.FS {
	return assetsFS
}

// Server represents the main web server for the vpn-ui panel with controllers, services, and scheduled jobs.
type Server struct {
	httpServer *http.Server
	listener   net.Listener

	index *controller.IndexController
	panel *controller.XUIController
	api   *controller.APIController
	ws    *controller.WebSocketController

	xrayService        service.XrayService
	settingService     service.SettingService
	radiusService      service.RadiusService
	l2tpService        service.L2tpService
	pptpService        service.PptpService
	openvpnService     service.OpenVpnService
	ocservService      service.OcservService
	sstpService        service.SstpService
	ikev2Service       service.Ikev2Service
	wgcService         service.WgcService
	awgService         service.AwgService
	greService         service.GreService
	mtprotoService     service.MtprotoService
	sshService         service.SshService
	sshOutboundService service.SshOutboundService
	vpnOutboundService service.VpnOutboundService
	tgbotService       service.Tgbot
	customGeoService   *service.CustomGeoService

	wsHub *websocket.Hub

	cron *cron.Cron

	ctx    context.Context
	cancel context.CancelFunc
}

// NewServer creates a new web server instance with a cancellable context.
func NewServer() *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		ctx:    ctx,
		cancel: cancel,
	}
}

// getHtmlFiles walks the local `web/html` directory and returns a list of
// template file paths. Used only in debug/development mode.
func (s *Server) getHtmlFiles() ([]string, error) {
	files := make([]string, 0)
	dir, _ := os.Getwd()
	err := fs.WalkDir(os.DirFS(dir), "web/html", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// getHtmlTemplate parses embedded HTML templates from the bundled `htmlFS`
// using the provided template function map and returns the resulting
// template set for production usage.
func (s *Server) getHtmlTemplate(funcMap template.FuncMap) (*template.Template, error) {
	t := template.New("").Funcs(funcMap)
	err := fs.WalkDir(htmlFS, "html", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			newT, err := t.ParseFS(htmlFS, path+"/*.html")
			if err != nil {
				// ignore
				return nil
			}
			t = newT
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// initRouter initializes Gin, registers middleware, templates, static
// assets, controllers and returns the configured engine.
func (s *Server) initRouter() (*gin.Engine, error) {
	if config.IsDebug() {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.DefaultWriter = io.Discard
		gin.DefaultErrorWriter = io.Discard
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.Default()

	webDomain, err := s.settingService.GetWebDomain()
	if err != nil {
		return nil, err
	}

	if webDomain != "" {
		engine.Use(middleware.DomainValidatorMiddleware(webDomain))
	}

	secret, err := s.settingService.GetSecret()
	if err != nil {
		return nil, err
	}

	basePath, err := s.settingService.GetBasePath()
	if err != nil {
		return nil, err
	}
	engine.Use(gzip.Gzip(gzip.DefaultCompression))
	assetsBasePath := basePath + "assets/"

	store := cookie.NewStore(secret)
	// Configure default session cookie options, including expiration (MaxAge)
	sessionOptions := sessions.Options{
		Path:     basePath,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if sessionMaxAge, err := s.settingService.GetSessionMaxAge(); err == nil && sessionMaxAge > 0 {
		sessionOptions.MaxAge = sessionMaxAge * 60 // minutes -> seconds
	}
	store.Options(sessionOptions)
	engine.Use(sessions.Sessions("vpn-ui", store))
	engine.Use(func(c *gin.Context) {
		c.Set("base_path", basePath)
	})
	// A year is only safe because the URL carries a token derived from the asset
	// bytes (see assetFingerprint): a changed file means a changed URL, so nothing
	// cached under the old one is ever wanted again.
	//
	// Debug mode is the exception. There the assets are read from the working tree
	// on every request so an edit shows up without a restart, but the token is
	// fixed at start and cannot follow those edits, so a long max-age would freeze
	// the browser on whatever it loaded first. That is the shape of bug this whole
	// mechanism exists to prevent, so debug does not cache at all.
	assetCacheControl := "max-age=31536000"
	if config.IsDebug() {
		assetCacheControl = "no-store"
	}
	engine.Use(func(c *gin.Context) {
		uri := c.Request.RequestURI
		if strings.HasPrefix(uri, assetsBasePath) {
			c.Header("Cache-Control", assetCacheControl)
		}
	})

	// init i18n
	err = locale.InitLocalizer(i18nFS, &s.settingService)
	if err != nil {
		return nil, err
	}

	// Apply locale middleware for i18n
	i18nWebFunc := func(key string, params ...string) string {
		return locale.I18n(locale.Web, key, params...)
	}
	// Register template functions before loading templates
	funcMap := template.FuncMap{
		"i18n": i18nWebFunc,
	}
	engine.SetFuncMap(funcMap)
	engine.Use(locale.LocalizerMiddleware())

	// Publish the token the templates stamp on every asset URL. Done before the
	// templates are registered so the first page served already carries it.
	config.SetAssetVersion(assetFingerprint())

	// set static files and template
	if config.IsDebug() {
		// for development
		files, err := s.getHtmlFiles()
		if err != nil {
			return nil, err
		}
		// Use the registered func map with the loaded templates
		engine.LoadHTMLFiles(files...)
		engine.StaticFS(basePath+"assets", http.FS(os.DirFS("web/assets")))
	} else {
		// for production
		template, err := s.getHtmlTemplate(funcMap)
		if err != nil {
			return nil, err
		}
		engine.SetHTMLTemplate(template)
		engine.StaticFS(basePath+"assets", http.FS(&wrapAssetsFS{FS: assetsFS}))
	}

	// Apply the redirect middleware (`/xui` to `/panel`)
	engine.Use(middleware.RedirectMiddleware(basePath))

	g := engine.Group(basePath)

	s.index = controller.NewIndexController(g)
	s.panel = controller.NewXUIController(g)
	s.api = controller.NewAPIController(g, s.customGeoService)

	// Initialize WebSocket hub
	s.wsHub = websocket.NewHub()
	go s.wsHub.Run()

	// Initialize WebSocket controller
	s.ws = controller.NewWebSocketController(s.wsHub)
	// Register WebSocket route with basePath (g already has basePath prefix)
	g.GET("/ws", s.ws.HandleWebSocket)

	// Chrome DevTools endpoint for debugging web apps
	engine.GET("/.well-known/appspecific/com.chrome.devtools.json", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	// Add a catch-all route to handle undefined paths and return 404
	engine.NoRoute(func(c *gin.Context) {
		c.AbortWithStatus(http.StatusNotFound)
	})

	return engine, nil
}

// startTask schedules background jobs (Xray checks, traffic jobs, cron
// jobs) which the panel relies on for periodic maintenance and monitoring.
func (s *Server) startTask() {
	// Before ANY Init* below touches the host: work out what on this box was already
	// here and what vpn-ui put here, and write it down. The Init* calls create netdevs
	// and rewrite shared config files, and the reconcilers that follow delete whatever
	// they believe is theirs, so the ownership record has to exist first. See
	// service/ownership.go.
	service.OwnSynthesize()

	// Generate or load RADIUS shared secret and start embedded RADIUS server
	radiusSecret := s.getOrCreateRadiusSecret()
	if radiusSecret != "" {
		if err := s.radiusService.Start(radiusSecret); err != nil {
			logger.Warning("RADIUS: failed to start:", err)
		}
		// Pass the RADIUS service (by pointer, so all three share the one instance
		// whose mutex/session map the running RADIUS servers use) and secret to the
		// L2TP/PPTP/OpenVPN services.
		s.l2tpService.SetRadius(&s.radiusService, radiusSecret)
		s.pptpService.SetRadius(&s.radiusService, radiusSecret)
		s.openvpnService.SetRadius(&s.radiusService, radiusSecret)
		s.ocservService.SetRadius(&s.radiusService, radiusSecret)
		s.sstpService.SetRadius(&s.radiusService, radiusSecret)
		s.ikev2Service.SetRadius(&s.radiusService, radiusSecret)
	}

	// Initialize L2TP/PPTP/OpenVPN/OpenConnect/SSTP services before Xray so TPROXY/NAT rules are in place
	s.l2tpService.InitL2tp()
	s.pptpService.InitPptp()
	s.openvpnService.InitOpenVpn()
	s.ocservService.InitOcserv()
	s.sstpService.InitSstp()
	s.ikev2Service.InitIkev2()
	s.wgcService.InitWgc()
	s.awgService.InitAwg()
	s.greService.InitGre()
	s.mtprotoService.InitMtproto()
	s.sshService.InitSsh()
	// BEFORE anything dials, which is why it is here and not beside InitVpnOutbound
	// below. A carrier is a device plus a routing table, and whatever rides on it sends
	// its first packet the moment it starts: the SSH manager dials as soon as its
	// listener binds, and a WireGuard client hands its handshake to the kernel the
	// instant its peer is configured. A carrier made afterwards would arrive after the
	// packet it was meant to carry had already left in the clear.
	service.InitVpnOutCarriers()
	s.sshOutboundService.InitSshOutbound()
	// Before RestartXray below, like every Init above it: the synthesized freedom
	// outbound binds to the netdev the client tunnel brings up, so the tunnel has to
	// exist by the time the core reads the config.
	s.vpnOutboundService.InitVpnOutbound()

	s.customGeoService.EnsureOnStartup()
	// Same crash-safety idea as the orphan reap below: a panel that died between an
	// upload and its confirmation left a whole binary staged next to itself, and the
	// token that made it installable died with the process.
	service.CleanStagedPanelUpload()
	// Reap an orphaned Xray from a previous instance BEFORE starting ours — a panel
	// self-update re-execs in place (same PID), leaving the old Xray alive and holding
	// its ports; without this the fresh Xray fails to bind and loops in the error
	// state. Mirrors the daemon reap the Init* calls above already do via procmgr.
	s.xrayService.ReapOrphanXray()
	err := s.xrayService.RestartXray(true)
	if err != nil {
		logger.Warning("start xray failed:", err)
	}
	// Check whether xray is running every second
	s.cron.AddJob("@every 1s", job.NewCheckXrayRunningJob())

	// Apply a requested Xray restart once the change that asked for it has settled.
	// Ticks every second because the wait is user-visible: mtproto/ssh clients cannot
	// use the proxy until their account reaches Xray's socks inbound, which only a
	// restart applies. IsRestartDueAndSetFalse holds the actual debounce, so a burst of
	// edits is still one restart.
	s.cron.AddFunc("@every 1s", func() {
		if s.xrayService.IsRestartDueAndSetFalse() {
			err := s.xrayService.RestartXray(false)
			if err != nil {
				logger.Error("restart xray failed:", err)
			}
		}
	})

	// Republish the speed limit sidecar when the CONFIG changed, as opposed to when
	// traffic flowed. The traffic job publishes it too, but only on a tick that carried
	// bytes (it early-returns otherwise), so on an idle box a limit set in the panel
	// reached the core only once somebody happened to generate traffic: measured as the
	// core still enforcing the old IP limit minutes after the panel reported success.
	//
	// Deliberately NOT folded into the restart cron above, and it must never grow into
	// it: a rate change touches nothing in the xray.Config graph, and restarting would
	// drop every live connection on the box, which is the whole reason the limits travel
	// in a sidecar. One second because the wait is user-visible (an operator watching the
	// UI), and it is affordable only because the writer is gated on a dirty flag armed
	// from the inbounds table itself, so an idle second costs one atomic load.
	service.RegisterSpeedLimitInvalidation()
	s.cron.AddFunc("@every 1s", service.WriteSpeedLimitsIfDirty)

	// Ensure Xray keeps its per-VPN dokodemo ports bound (rebinds after a rare
	// silent bind failure on restart, so L2TP/PPTP/OpenVPN internet self-heals)
	s.cron.AddJob("@every 20s", job.NewCheckVpnDokodemoJob())

	go func() {
		time.Sleep(time.Second * 5)
		// Statistics every 10 seconds, start the delay for 5 seconds for the first time, and staggered with the time to restart xray
		s.cron.AddJob("@every 10s", job.NewXrayTrafficJob(&s.radiusService))
	}()

	// Clean stale RADIUS sessions every 60 seconds
	s.cron.AddFunc("@every 60s", func() {
		s.radiusService.CleanStaleSessions()
	})

	// check client ips from log file every 10 sec
	s.cron.AddJob("@every 10s", job.NewCheckClientIpJob())

	// check client ips from log file every day
	s.cron.AddJob("@daily", job.NewClearLogsJob())

	// Inbound traffic reset jobs
	// Run every hour
	s.cron.AddJob("@hourly", job.NewPeriodicTrafficResetJob("hourly"))
	// Run once a day, midnight
	s.cron.AddJob("@daily", job.NewPeriodicTrafficResetJob("daily"))
	// Run once a week, midnight between Sat/Sun
	s.cron.AddJob("@weekly", job.NewPeriodicTrafficResetJob("weekly"))
	// Run once a month, midnight, first of month
	s.cron.AddJob("@monthly", job.NewPeriodicTrafficResetJob("monthly"))

	// Renew the managed TLS certificate when it comes due. This is the only renewal
	// scheduler on the box: acme.sh's own cron is deliberately not installed, because
	// two of them racing for port 80 fail validation and failed validations are the
	// metered kind. See job.SSLRenewSchedule for why six hours and not a day.
	//
	// Registered here rather than below the Telegram block on purpose: that block
	// RETURNS early on a bad tgbot runtime (see the AddJob error path), and a renewal
	// that silently stops happening because somebody mistyped a cron string in a
	// completely unrelated setting is exactly the kind of failure nobody notices
	// until TLS is already dead.
	sslRenewJob := job.NewCheckSSLRenewJob()
	s.cron.AddJob(job.SSLRenewSchedule, sslRenewJob)

	go func() {
		// cron's first "@every" tick is one whole interval away, so without this a box
		// that reboots more often than the interval would never renew at all. Bound to
		// the server context rather than a bare sleep: a SIGHUP restart builds a whole
		// new Server (main.go:340), and this must not fire into the next one.
		select {
		case <-time.After(job.SSLRenewStartupDelay):
			sslRenewJob.Run()
		case <-s.ctx.Done():
		}
	}()

	// Refresh the built-in geo data files. Registered unconditionally and gated
	// INSIDE the job rather than here, so flipping the switch in the overview's
	// Geofiles dialog takes effect on the next tick instead of on the next panel
	// restart. Placed above the Telegram block for the same reason the SSL job is:
	// that block returns early on a bad tgbot cron string.
	geofileJob := job.NewUpdateGeofileJob()
	s.cron.AddJob(job.GeofileUpdateSchedule, geofileJob)

	go func() {
		// Same reasoning as the SSL startup run above: cron's first "@every" tick is a
		// whole interval away, and the context binding keeps a SIGHUP restart from
		// firing this into the next Server.
		select {
		case <-time.After(job.GeofileUpdateStartupDelay):
			geofileJob.Run()
		case <-s.ctx.Done():
		}
	}()

	// LDAP sync scheduling
	if ldapEnabled, _ := s.settingService.GetLdapEnable(); ldapEnabled {
		runtime, err := s.settingService.GetLdapSyncCron()
		if err != nil || runtime == "" {
			runtime = "@every 1m"
		}
		j := job.NewLdapSyncJob()
		// job has zero-value services with method receivers that read settings on demand
		s.cron.AddJob(runtime, j)
	}

	// Make a traffic condition every day, 8:30
	var entry cron.EntryID
	isTgbotenabled, err := s.settingService.GetTgbotEnabled()
	if (err == nil) && (isTgbotenabled) {
		runtime, err := s.settingService.GetTgbotRuntime()
		if err != nil {
			logger.Warningf("Add NewStatsNotifyJob: failed to load runtime: %v; using default @daily", err)
			runtime = "@daily"
		} else if strings.TrimSpace(runtime) == "" {
			logger.Warning("Add NewStatsNotifyJob runtime is empty, using default @daily")
			runtime = "@daily"
		}
		logger.Infof("Tg notify enabled,run at %s", runtime)
		_, err = s.cron.AddJob(runtime, job.NewStatsNotifyJob())
		if err != nil {
			logger.Warningf("Add NewStatsNotifyJob: failed to schedule runtime %q: %v", runtime, err)
			return
		}

		// check for Telegram bot callback query hash storage reset
		s.cron.AddJob("@every 2m", job.NewCheckHashStorageJob())

		// Check CPU load and alarm to TgBot if threshold passes
		cpuThreshold, err := s.settingService.GetTgCpu()
		if (err == nil) && (cpuThreshold > 0) {
			s.cron.AddJob("@every 10s", job.NewCheckCpuJob())
		}
	} else {
		s.cron.Remove(entry)
	}
}

// Start initializes and starts the web server with configured settings, routes, and background jobs.
func (s *Server) Start() (err error) {
	// This is an anonymous function, no function name
	defer func() {
		if err != nil {
			s.Stop()
		}
	}()

	loc, err := s.settingService.GetTimeLocation()
	if err != nil {
		return err
	}
	s.cron = cron.New(cron.WithLocation(loc), cron.WithSeconds())
	s.cron.Start()

	s.customGeoService = service.NewCustomGeoService()

	engine, err := s.initRouter()
	if err != nil {
		return err
	}

	certFile, err := s.settingService.GetCertFile()
	if err != nil {
		return err
	}
	keyFile, err := s.settingService.GetKeyFile()
	if err != nil {
		return err
	}
	listen, err := s.settingService.GetListen()
	if err != nil {
		return err
	}
	port, err := s.settingService.GetPort()
	if err != nil {
		return err
	}
	listenAddr := net.JoinHostPort(listen, strconv.Itoa(port))
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	scheme := "http"
	if certFile != "" || keyFile != "" {
		certReloader, err := network.NewCertReloader(certFile, keyFile)
		if err == nil {
			c := &tls.Config{
				// Looked up per handshake so a renewal is picked up in place.
				// Restarting to reload would kill every VPN daemon the panel
				// parents, and short-lived certificates renew every few days.
				GetCertificate: certReloader.GetCertificate,
			}
			listener = network.NewAutoHttpsListener(listener)
			listener = tls.NewListener(listener, c)
			scheme = "https"
			logger.Info("Web server running HTTPS on", listener.Addr())
		} else {
			logger.Error("Error loading certificates:", err)
			logger.Info("Web server running HTTP on", listener.Addr())
		}
	} else {
		logger.Info("Web server running HTTP on", listener.Addr())
	}
	s.listener = listener

	// Always print the access URL to stdout so the operator sees the port on
	// launch (the logger.Info above may go to syslog/file and be invisible on a
	// bare run). Empty/wildcard listen means all interfaces.
	basePath, _ := s.settingService.GetBasePath()
	hostDisp := listen
	if hostDisp == "" || hostDisp == "0.0.0.0" || hostDisp == "::" {
		hostDisp = "0.0.0.0"
	}
	fmt.Printf("\nvpn-ui panel listening on %s://%s:%d%s\n\n", scheme, hostDisp, port, basePath)

	s.httpServer = &http.Server{
		Handler: engine,
	}

	go func() {
		s.httpServer.Serve(listener)
	}()

	s.startTask()

	isTgbotenabled, err := s.settingService.GetTgbotEnabled()
	if (err == nil) && (isTgbotenabled) {
		tgBot := s.tgbotService.NewTgbot()
		tgBot.Start(i18nFS)
	}

	return nil
}

// Stop gracefully shuts down the web server, stops Xray, RADIUS, cron jobs, and Telegram bot.
func (s *Server) Stop() error {
	s.cancel()
	// Terminate the supervised VPN daemons (openvpn/xl2tpd/pptpd) so they die
	// with the panel rather than orphaning.
	service.GetProcManager().StopAll()
	// SSH is an in-binary listener, not a supervised child, so StopAll does not cover it.
	s.sshService.StopServices()
	s.sshOutboundService.StopAll()
	// Client tunnels are kernel netdevs (and, for some protocols, their own client
	// daemons), so they outlive the panel unless they are taken down explicitly.
	s.vpnOutboundService.StopAll()
	s.radiusService.Stop()
	s.xrayService.StopXray()
	if s.cron != nil {
		s.cron.Stop()
	}
	if s.tgbotService.IsRunning() {
		s.tgbotService.Stop()
	}
	// Gracefully stop WebSocket hub
	if s.wsHub != nil {
		s.wsHub.Stop()
	}
	var err1 error
	var err2 error
	if s.httpServer != nil {
		err1 = s.httpServer.Shutdown(s.ctx)
	}
	if s.listener != nil {
		err2 = s.listener.Close()
	}
	return common.Combine(err1, err2)
}

// GetCtx returns the server's context for cancellation and deadline management.
func (s *Server) GetCtx() context.Context {
	return s.ctx
}

// GetCron returns the server's cron scheduler instance.
func (s *Server) GetCron() *cron.Cron {
	return s.cron
}

// GetWSHub returns the WebSocket hub instance.
func (s *Server) GetWSHub() any {
	return s.wsHub
}

// getOrCreateRadiusSecret retrieves or generates the RADIUS shared secret from settings.
func (s *Server) getOrCreateRadiusSecret() string {
	secret, err := s.settingService.GetRadiusSecret()
	if err == nil && secret != "" {
		return secret
	}
	// Generate a random 32-byte hex secret
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		logger.Warning("RADIUS: failed to generate secret:", err)
		return "default-radius-secret"
	}
	secret = fmt.Sprintf("%x", b)
	if err := s.settingService.SetRadiusSecret(secret); err != nil {
		logger.Warning("RADIUS: failed to save secret:", err)
	}
	return secret
}

func (s *Server) RestartXray() error {
	return s.xrayService.RestartXray(true)
}
