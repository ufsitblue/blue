package main

import (
	"log"
	"net/http"
	"networkinator/models"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func GetConnections(c *gin.Context) {
    connections, err := GetAllConnections(db)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    connectionMap := make(map[string][]string)
    for _, connection := range connections {
        connectionMap[connection.ID] = []string{connection.Src, connection.Dst, strconv.Itoa(connection.Port), strconv.FormatFloat(connection.Count, 'f', -1, 64)}
    }

    c.JSON(http.StatusOK, connectionMap)
}

func AddConnection(jsonData map[string]interface{}) {
    id := jsonData["ID"].(string)
    src := jsonData["Src"].(string)
    dst := jsonData["Dst"].(string)
    port := jsonData["Port"].(string)
    count := jsonData["Count"].(float64)

	portInt, err := strconv.Atoi(port)
	if err != nil || portInt < 0 || portInt > 65535 {
        log.Println(err)
		return
	}

    connection := models.Connection{}
    tx := db.First(&connection, "ID = ?", id)
	if tx.Error == nil {
        log.Println("Connection already exists")
		return
	}

	err = AddConnectionToDB(id, src, dst, portInt, count)
	if err != nil {
        log.Println(err)
		return
	}

    for client := range webClients {
        err := client.WriteJSON(jsonData)
        if err != nil {
            log.Println(err)
            client.Close()
            delete(webClients, client)
        }
    }
}

func GetAgents(c *gin.Context) {
    agents, err := GetAllAgents()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    agentArr := make([][]string, len(agents))
    for i := 0; i < len(agents); i++ {
        agentArr[i] = []string{agents[i].Hostname, agents[i].HostOS, agents[i].IP, agents[i].ID}
    }

    c.JSON(http.StatusOK, agentArr)
}

func AddAgent(c *gin.Context) {
    jsonData := make(map[string]interface{})
    err := c.ShouldBindJSON(&jsonData)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    hostname := jsonData["Hostname"].(string)
    hostOS := jsonData["HostOS"].(string)
    id := jsonData["ID"].(string)
    key := jsonData["Key"].(string)
    ip := strings.Split(c.ClientIP(), ":")[0]

    if strings.Compare(key, tomlConf.AgentKey) != 0 {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid key"})
        return
    }

    agent := models.Agent{}
    tx := db.First(&agent, "Hostname = ?", hostname)
    if tx.Error == nil {
        c.JSON(http.StatusOK, gin.H{"message": "Agent already exists"})
        return
    }

    err = AddAgentToDB(id, hostname, hostOS, ip)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Agent added"})
}

func AgentStatus(jsonData []byte) {
    for client := range webClients {
        err := client.WriteMessage(websocket.TextMessage, jsonData)
        if err != nil {
            log.Println(err)
            client.Close()
            delete(webClients, client)
        }
    }
}

func sendToAgents(jsonData []byte) {
    for client := range agentClients {
        err := client.WriteMessage(websocket.TextMessage, jsonData)
        if err != nil {
            log.Println(err)
            client.Close()
            delete(agentClients, client)
        }
    }
}
