package controller

import (
	"strings"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/web/service"

	"github.com/gin-gonic/gin"
)

// CoreController exposes status and control for the backend "cores"
// (Xray, L2TP/IPsec, PPTP, OpenVPN, RADIUS) shown in the Core Settings panel.
type CoreController struct {
	coreService service.CoreService
}

// NewCoreController creates a new CoreController and initializes its routes.
func NewCoreController(g *gin.RouterGroup) *CoreController {
	a := &CoreController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for core status and control under /panel/core.
func (a *CoreController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/core")
	g.Use(requirePerm(model.PermCoreSettings))
	g.GET("/status", a.status)
	g.GET("/catalog", a.catalog)
	g.POST("/provision", a.provision)
	g.GET("/provision-status", a.provisionStatus)
	// Removing a core deletes its files and stops its daemon: escalation-class,
	// like the host reboot below.
	g.POST("/uninstall", requireSuperAdmin(), a.uninstallCores)
	g.GET("/uninstall-status", a.uninstallStatus)
	// Reboots the HOST: escalation-class.
	g.POST("/reboot", requireSuperAdmin(), a.reboot)
	g.POST("/restart/:core", a.restart)
	g.POST("/restart-all", a.restartAll)
	g.POST("/stop/:core", a.stop)
	g.GET("/logs/:core", a.logs)
}

// status returns the status of all cores plus the host/kernel system status and
// whether the VPN backend has been provisioned (setup completed).
func (a *CoreController) status(c *gin.Context) {
	prov := a.coreService.ProvisionState()
	jsonObj(c, gin.H{
		"cores":            a.coreService.GetCoresStatus(),
		"system":           a.coreService.GetSystemStatus(),
		"provisioned":      a.coreService.IsProvisioned(),
		"missingProtocols": a.coreService.MissingProtocols(),
		"rebootRequired":   prov.RebootRequired,
		"rebootModules":    prov.RebootModules,
		"rebootPkg":        prov.RebootPkg,
	}, nil)
}

// catalog lists every core with its install state, for the setup / add-core /
// uninstall-core dialogs.
func (a *CoreController) catalog(c *gin.Context) {
	jsonObj(c, gin.H{
		"cores":       a.coreService.CoreCatalog(),
		"provisioned": a.coreService.IsProvisioned(),
	}, nil)
}

// selectedCores reads the `cores` form field, a comma-separated list of core
// names. Absent or empty means "every installable core", which is what the
// legacy all-in-one setup button sent and what the CLI still wants.
func selectedCores(c *gin.Context) []string {
	raw := c.PostForm("cores")
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// provision starts host/kernel provisioning (kernel modules + sysctl + daemon
// extraction) for the selected cores in the background and returns the initial
// run state. The client then polls provisionStatus for the live per-step
// progress. If a run is already in progress, this does not start a second one.
func (a *CoreController) provision(c *gin.Context) {
	started := a.coreService.StartProvision(selectedCores(c))
	st := a.coreService.ProvisionState()
	jsonObj(c, gin.H{
		"started":        started,
		"running":        st.Running,
		"done":           st.Done,
		"steps":          st.Steps,
		"rebootRequired": st.RebootRequired,
		"rebootModules":  st.RebootModules,
		"rebootPkg":      st.RebootPkg,
	}, nil)
}

// provisionStatus returns the live progress of the current/most-recent
// provisioning run: the steps emitted so far, whether it is still running or
// done, and the resulting provisioned flag.
func (a *CoreController) provisionStatus(c *gin.Context) {
	st := a.coreService.ProvisionState()
	jsonObj(c, gin.H{
		"running":        st.Running,
		"done":           st.Done,
		"steps":          st.Steps,
		"rebootRequired": st.RebootRequired,
		"rebootModules":  st.RebootModules,
		"rebootPkg":      st.RebootPkg,
		"provisioned":    a.coreService.IsProvisioned(),
	}, nil)
}

// uninstallCores removes the selected cores in the background. It refuses up
// front (with the reason) when a core is not installed or still has inbounds,
// so the dialog never opens a console on a run that was never going to start.
func (a *CoreController) uninstallCores(c *gin.Context) {
	cores := selectedCores(c)
	// `inbounds` carries the operator's answer to "these cores still serve
	// inbounds": "delete" removes them with the core, "keep" strands them on
	// purpose. Absent means the question was never asked, and the service still
	// refuses - so an old client cannot strand inbounds by omission.
	started, err := a.coreService.StartCoreUninstall(cores, c.PostForm("inbounds"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.core.toasts.uninstalled"), err)
		return
	}
	st := a.coreService.CoreUninstallStatus()
	jsonObj(c, gin.H{
		"started": started,
		"running": st.Running,
		"done":    st.Done,
		"steps":   st.Steps,
		"kept":    st.Kept,
		"cores":   st.Cores,
	}, nil)
}

// uninstallStatus returns the live progress of the current/most-recent core
// uninstall, in the same shape as provisionStatus so one console renders both.
func (a *CoreController) uninstallStatus(c *gin.Context) {
	st := a.coreService.CoreUninstallStatus()
	jsonObj(c, gin.H{
		"running": st.Running,
		"done":    st.Done,
		"steps":   st.Steps,
		"kept":    st.Kept,
		"cores":   st.Cores,
	}, nil)
}

// reboot restarts the host machine. It is offered after provisioning installs a
// kernel-modules package whose modules only load into a freshly booted kernel
// (L2TP/PPTP on minimal cloud images). The response is sent before the machine
// goes down, so the client can show a "rebooting" state.
func (a *CoreController) reboot(c *gin.Context) {
	err := a.coreService.Reboot()
	jsonMsg(c, I18nWeb(c, "pages.core.toasts.rebooting"), err)
}

// restart restarts the daemon(s) for the given core.
func (a *CoreController) restart(c *gin.Context) {
	err := a.coreService.RestartCore(c.Param("core"))
	jsonMsg(c, I18nWeb(c, "pages.core.toasts.restarted"), err)
}

// restartAll restarts every core.
func (a *CoreController) restartAll(c *gin.Context) {
	err := a.coreService.RestartAll()
	jsonMsg(c, I18nWeb(c, "pages.core.toasts.restarted"), err)
}

// stop stops the given core, where supported (xray, l2tp, pptp, openvpn, radius).
func (a *CoreController) stop(c *gin.Context) {
	err := a.coreService.StopCore(c.Param("core"))
	jsonMsg(c, I18nWeb(c, "pages.core.toasts.stopped"), err)
}

// logs returns the recent captured output for a core's process(es).
func (a *CoreController) logs(c *gin.Context) {
	jsonObj(c, a.coreService.CoreLogs(c.Param("core")), nil)
}
