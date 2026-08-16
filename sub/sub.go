// Package sub provides subscription server functionality for the vpn-ui panel,
// including HTTP/HTTPS servers for serving subscription links and JSON configurations.
package sub

import (
	"context"
	"crypto/tls"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/web/locale"
	"github.com/hasan1808/pro-ui/web/middleware"
	"github.com/hasan1808/pro-ui/web/network"
	"github.com/hasan1808/pro-ui/web/service"

	"github.com/gin-gonic/gin"
)

// setEmbeddedTemplates parses and sets embedded templates on the engine
func (s *Server) setEmbeddedTemplates(engine *gin.Engine) error {
	t, err := template.New("").Funcs(engine.FuncMap).ParseFS(
		s.htmlFS,
		"html/common/page.html",
		"html/component/aThemeSwitch.html",
		"html/settings/panel/subscription/subpage.html",
	)
	if err != nil {
		return err
	}
	engine.SetHTMLTemplate(t)
	return nil
}

// Server represents the subscription server that serves subscription links and JSON configurations.
type Server struct {
	httpServer *http.Server
	listener   net.Listener

	sub            *SUBController
	settingService service.SettingService

	// htmlFS/assetsFS are the embedded templates/static assets owned by the web
	// package. They are injected by main (which imports both web and sub) so that
	// package sub never imports package web: the panel's controllers import sub
	// for the subscription-template preview, and web imports controller, so sub
	// importing web would close an import cycle.
	htmlFS   fs.FS
	assetsFS fs.FS

	ctx    context.Context
	cancel context.CancelFunc
}

// NewServer creates a new subscription server instance with a cancellable context.
func NewServer() *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		ctx:    ctx,
		cancel: cancel,
	}
}

// SetEmbedded sets the embedded HTML templates and static assets filesystems for
// this subscription server, supplied by the process that builds it (main).
func (s *Server) SetEmbedded(htmlFS fs.FS, assetsFS fs.FS) {
	s.htmlFS = htmlFS
	s.assetsFS = assetsFS
}

// initRouter configures the subscription server's Gin engine, middleware,
// templates and static assets and returns the ready-to-use engine.
func (s *Server) initRouter() (*gin.Engine, error) {
	// Always run in release mode for the subscription server
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard
	gin.SetMode(gin.ReleaseMode)

	engine := gin.Default()

	subDomain, err := s.settingService.GetSubDomain()
	if err != nil {
		return nil, err
	}

	if subDomain != "" {
		engine.Use(middleware.DomainValidatorMiddleware(subDomain))
	}

	LinksPath, err := s.settingService.GetSubPath()
	if err != nil {
		return nil, err
	}

	JsonPath, err := s.settingService.GetSubJsonPath()
	if err != nil {
		return nil, err
	}

	ClashPath, err := s.settingService.GetSubClashPath()
	if err != nil {
		return nil, err
	}

	subJsonEnable, err := s.settingService.GetSubJsonEnable()
	if err != nil {
		return nil, err
	}

	subClashEnable, err := s.settingService.GetSubClashEnable()
	if err != nil {
		return nil, err
	}

	// Set base_path based on LinksPath for template rendering
	// Ensure LinksPath ends with "/" for proper asset URL generation
	basePath := LinksPath
	if basePath != "/" && !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	// logger.Debug("sub: Setting base_path to:", basePath)
	engine.Use(func(c *gin.Context) {
		c.Set("base_path", basePath)
	})

	Encrypt, err := s.settingService.GetSubEncrypt()
	if err != nil {
		return nil, err
	}

	ShowInfo, err := s.settingService.GetSubShowInfo()
	if err != nil {
		return nil, err
	}

	RemarkModel, err := s.settingService.GetRemarkModel()
	if err != nil {
		RemarkModel = "-ieo"
	}

	SubUpdates, err := s.settingService.GetSubUpdates()
	if err != nil {
		SubUpdates = "10"
	}

	SubJsonFragment, err := s.settingService.GetSubJsonFragment()
	if err != nil {
		SubJsonFragment = ""
	}

	SubJsonNoises, err := s.settingService.GetSubJsonNoises()
	if err != nil {
		SubJsonNoises = ""
	}

	SubJsonMux, err := s.settingService.GetSubJsonMux()
	if err != nil {
		SubJsonMux = ""
	}

	SubJsonRules, err := s.settingService.GetSubJsonRules()
	if err != nil {
		SubJsonRules = ""
	}

	SubTitle, err := s.settingService.GetSubTitle()
	if err != nil {
		SubTitle = ""
	}

	SubSupportUrl, err := s.settingService.GetSubSupportUrl()
	if err != nil {
		SubSupportUrl = ""
	}

	SubProfileUrl, err := s.settingService.GetSubProfileUrl()
	if err != nil {
		SubProfileUrl = ""
	}

	SubAnnounce, err := s.settingService.GetSubAnnounce()
	if err != nil {
		SubAnnounce = ""
	}

	SubEnableRouting, err := s.settingService.GetSubEnableRouting()
	if err != nil {
		return nil, err
	}

	SubRoutingRules, err := s.settingService.GetSubRoutingRules()
	if err != nil {
		SubRoutingRules = ""
	}

	// set per-request localizer from headers/cookies
	engine.Use(locale.LocalizerMiddleware())

	// register i18n function similar to web server
	i18nWebFunc := func(key string, params ...string) string {
		return locale.I18n(locale.Web, key, params...)
	}
	engine.SetFuncMap(map[string]any{"i18n": i18nWebFunc})

	// Templates: prefer embedded; fallback to disk if necessary
	if err := s.setEmbeddedTemplates(engine); err != nil {
		logger.Warning("sub: failed to parse embedded templates:", err)
		if files, derr := s.getHtmlFiles(); derr == nil {
			engine.LoadHTMLFiles(files...)
		} else {
			logger.Error("sub: no templates available (embedded parse and disk load failed)", err, derr)
		}
	}

	// Assets: use disk if present, fallback to embedded
	// Serve under both root (/assets) and under the subscription path prefix (LinksPath + "assets")
	// so reverse proxies with a URI prefix can load assets correctly.
	// Determine LinksPath earlier to compute prefixed assets mount.
	// Note: LinksPath always starts and ends with "/" (validated in settings).
	var linksPathForAssets string
	if LinksPath == "/" {
		linksPathForAssets = "/assets"
	} else {
		// ensure single slash join
		linksPathForAssets = strings.TrimRight(LinksPath, "/") + "/assets"
	}

	// Mount assets in multiple paths to handle different URL patterns
	var assetsFS http.FileSystem
	if _, err := os.Stat("web/assets"); err == nil {
		assetsFS = http.FS(os.DirFS("web/assets"))
	} else {
		if subFS, err := fs.Sub(s.assetsFS, "assets"); err == nil {
			assetsFS = http.FS(subFS)
		} else {
			logger.Error("sub: failed to mount embedded assets:", err)
		}
	}

	if assetsFS != nil {
		engine.StaticFS("/assets", assetsFS)
		if linksPathForAssets != "/assets" {
			engine.StaticFS(linksPathForAssets, assetsFS)
		}

		// Add middleware to handle dynamic asset paths with subid
		if LinksPath != "/" {
			engine.Use(func(c *gin.Context) {
				path := c.Request.URL.Path
				// Check if this is an asset request with subid pattern: /sub/path/{subid}/assets/...
				pathPrefix := strings.TrimRight(LinksPath, "/") + "/"
				if strings.HasPrefix(path, pathPrefix) && strings.Contains(path, "/assets/") {
					// Extract the asset path after /assets/
					assetsIndex := strings.Index(path, "/assets/")
					if assetsIndex != -1 {
						assetPath := path[assetsIndex+8:] // +8 to skip "/assets/"
						if assetPath != "" {
							// Serve the asset file
							c.FileFromFS(assetPath, assetsFS)
							c.Abort()
							return
						}
					}
				}
				c.Next()
			})
		}
	}

	g := engine.Group("/")

	s.sub = NewSUBController(
		g, LinksPath, JsonPath, ClashPath, subJsonEnable, subClashEnable, Encrypt, ShowInfo, RemarkModel, SubUpdates,
		SubJsonFragment, SubJsonNoises, SubJsonMux, SubJsonRules, SubTitle, SubSupportUrl,
		SubProfileUrl, SubAnnounce, SubEnableRouting, SubRoutingRules)

	return engine, nil
}

// getHtmlFiles loads templates from local folder (used in debug mode)
func (s *Server) getHtmlFiles() ([]string, error) {
	dir, _ := os.Getwd()
	files := []string{}
	// common layout
	common := filepath.Join(dir, "web", "html", "common", "page.html")
	if _, err := os.Stat(common); err == nil {
		files = append(files, common)
	}
	// components used
	theme := filepath.Join(dir, "web", "html", "component", "aThemeSwitch.html")
	if _, err := os.Stat(theme); err == nil {
		files = append(files, theme)
	}
	// page itself
	page := filepath.Join(dir, "web", "html", "subpage.html")
	if _, err := os.Stat(page); err == nil {
		files = append(files, page)
	} else {
		return nil, err
	}
	return files, nil
}

// Start initializes and starts the subscription server with configured settings.
func (s *Server) Start() (err error) {
	// This is an anonymous function, no function name
	defer func() {
		if err != nil {
			s.Stop()
		}
	}()

	subEnable, err := s.settingService.GetSubEnable()
	if err != nil {
		return err
	}
	if !subEnable {
		return nil
	}

	engine, err := s.initRouter()
	if err != nil {
		return err
	}

	certFile, err := s.settingService.GetSubCertFile()
	if err != nil {
		return err
	}
	keyFile, err := s.settingService.GetSubKeyFile()
	if err != nil {
		return err
	}
	listen, err := s.settingService.GetSubListen()
	if err != nil {
		return err
	}
	port, err := s.settingService.GetSubPort()
	if err != nil {
		return err
	}

	listenAddr := net.JoinHostPort(listen, strconv.Itoa(port))
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}

	if certFile != "" || keyFile != "" {
		certReloader, err := network.NewCertReloader(certFile, keyFile)
		if err == nil {
			c := &tls.Config{
				// Same reason as the panel listener: renewals must not need a
				// restart. See network.CertReloader.
				GetCertificate: certReloader.GetCertificate,
			}
			listener = network.NewAutoHttpsListener(listener)
			listener = tls.NewListener(listener, c)
			logger.Info("Sub server running HTTPS on", listener.Addr())
		} else {
			logger.Error("Error loading certificates:", err)
			logger.Info("Sub server running HTTP on", listener.Addr())
		}
	} else {
		logger.Info("Sub server running HTTP on", listener.Addr())
	}
	s.listener = listener

	s.httpServer = &http.Server{
		Handler: engine,
	}

	go func() {
		s.httpServer.Serve(listener)
	}()

	return nil
}

// Stop gracefully shuts down the subscription server and closes the listener.
func (s *Server) Stop() error {
	s.cancel()

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
