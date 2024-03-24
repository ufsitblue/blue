package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true
    },
}

func addPublicRoutes(g *gin.RouterGroup) {
    g.GET("/", basicAuth)
    g.GET("/ws/agent", wsAgent)
    g.POST("/api/agents/add", AddAgent)
}

func addPrivateRoutes(g *gin.RouterGroup) {
    g.GET("/topology", index)
    g.GET("/connections", connections)
    g.GET("/filter", filter)
    g.GET("/agents", agents)

    g.GET("/api/connections/get", GetConnections)
    g.GET("/api/agents/get", GetAgents)
    g.GET("/ws/web", wsWeb)

}

func index(c *gin.Context) {
    c.HTML(200, "index.html", gin.H{})
}

func connections(c *gin.Context) {
    c.HTML(200, "connections.html", gin.H{})
}

func filter(c *gin.Context) {
    c.HTML(200, "filter.html", gin.H{})
}

func agents(c *gin.Context) {
    c.HTML(200, "agents.html", gin.H{})
}
