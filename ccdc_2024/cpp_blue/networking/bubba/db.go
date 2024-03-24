package main

import (
	"networkinator/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func ConnectToSQLite() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("network.db"), &gorm.Config{})
	if err != nil {
        panic(err)
	}
    return db
}

func AddConnectionToDB(id string, src, dst string, port int, count float64) error {
	connection := models.Connection{ID: id, Src: src, Dst: dst, Port: port, Count: count}
	result := db.Create(&connection)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func DeleteConnectionFromDB(id string) error {
    var connection models.Connection
    result := db.Where("id = ?", id).First(&connection)
    if result.Error != nil {
        return result.Error
    }
    result = db.Delete(&connection)
    if result.Error != nil {
        return result.Error
    }
    return nil
}

func GetAllConnections(db *gorm.DB) ([]models.Connection, error) {
	var connections []models.Connection
	result := db.Find(&connections)
	if result.Error != nil {
		return nil, result.Error
	}
	return connections, nil
}

func GetConnectionsByIP(host string) ([]models.Connection, error) {
    var connections []models.Connection
    result := db.Where("src = ? OR dst = ?", host, host).Find(&connections)
    if result.Error != nil {
        return nil, result.Error
    }
    return connections, nil
}

func UpdateConnectionCount(id string, count float64) error {
    var connection models.Connection
    result := db.Where("id = ?", id).First(&connection)
    if result.Error != nil {
        return result.Error
    }
    connection.Count = count
    result = db.Save(&connection)
    if result.Error != nil {
        return result.Error
    }
    return nil
}

func AddAgentToDB(ID string, hostname, hostOS, ip string) error {
    agent := models.Agent{ID: ID, Hostname: hostname, HostOS: hostOS, IP: ip, Status: "Alive"}
    result := db.Create(&agent)
    if result.Error != nil {
        return result.Error
    }
    return nil
}

func GetAllAgents() ([]models.Agent, error) {
    var agents []models.Agent
    result := db.Find(&agents)
    if result.Error != nil {
        return nil, result.Error
    }
    return agents, nil
}

func GetAgentByIP(ip string) (models.Agent, error) {
    var agent models.Agent
    result := db.Where("IP = ?", ip).First(&agent)
    if result.Error != nil {
        return agent, result.Error
    }
    return agent, nil
}
