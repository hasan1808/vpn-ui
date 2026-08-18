package controller

import (
	"net/http"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/web/session"

	"github.com/gin-gonic/gin"
)

// APIController handles the main API routes for the vpn-ui panel, including inbounds and server management.
type APIController struct {
	BaseController
	inboundController *InboundController
	serverController  *ServerController
	Tgbot             service.Tgbot
}

// NewAPIController creates a new APIController instance and initializes its routes.
func NewAPIController(g *gin.RouterGroup, customGeo *service.CustomGeoService) *APIController {
	a := &APIController{}
	a.initRouter(g, customGeo)
	return a
}

// checkAPIAuth is a middleware that returns 404 for unauthenticated API requests
// to hide the existence of API endpoints from unauthorized users
func (a *APIController) checkAPIAuth(c *gin.Context) {
	if !session.IsLogin(c) {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Next()
}

// initRouter sets up the API routes for inbounds, server, and other endpoints.
func (a *APIController) initRouter(g *gin.RouterGroup, customGeo *service.CustomGeoService) {
	// Main API group
	api := g.Group("/panel/api")
	api.Use(a.checkAPIAuth)

	// Inbounds API
	inbounds := api.Group("/inbounds")
	a.inboundController = NewInboundController(inbounds)

	// Clients API: the account-centric read model behind the Clients page. Same
	// claim as the inbounds group because it shows the same accounts from the other
	// side; the rows are narrowed per caller inside the service.
	clients := api.Group("/clients")
	clients.Use(requirePerm(model.PermAccessInbounds))
	NewClientsController(clients)

	// Server API
	server := api.Group("/server")
	a.serverController = NewServerController(server)

	// Custom geo sources feed Xray routing, so they follow the Xray permission. They
	// are ALSO read by the overview's geofiles dialog, which is why the group takes
	// either claim: the Xray bit alone left the dialog unreachable for anyone whose
	// only claim on it is the overview, which is every reseller. The writes inside
	// still ask for the overview bit specifically.
	customGeoGroup := api.Group("/custom-geo")
	customGeoGroup.Use(requireXrayOrOverviewManage())
	NewCustomGeoController(customGeoGroup, customGeo)

	// Extra routes
	// Mails the entire SQLite DB (every admin's inbounds, client credentials, and
	// the users table with its bcrypt hashes) to a Telegram chat: escalation-class.
	api.GET("/backuptotgbot", requireOverviewManage(), a.BackuptoTgbot)
}

// BackuptoTgbot sends a backup of the panel data to Telegram bot admins.
func (a *APIController) BackuptoTgbot(c *gin.Context) {
	a.Tgbot.SendBackupToAdmins()
}
