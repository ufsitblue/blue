package main

import (
    "net/http"

    "github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

func authRequired(c *gin.Context) {
    session := sessions.Default(c)
    id := session.Get("id")
    if id == nil {
        c.String(http.StatusUnauthorized, "Unauthorized")
        c.Abort()
        return
    }
    c.Next()
}

func getUUID() string {
    return uuid.NewString()
}

func initCookies(router *gin.Engine) {
    uuid := getUUID()
    store := cookie.NewStore([]byte(uuid))
    router.Use(sessions.Sessions("session", store))
}

func basicAuth(c *gin.Context) {
    session := sessions.Default(c)
    user, pass, hasAuth := c.Request.BasicAuth()
    if hasAuth && user == tomlConf.AdminUsername && pass == tomlConf.AdminPassword {
        session.Set("id", user)
        if err := session.Save(); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to save session."})
            return
        }        
        c.Redirect(http.StatusSeeOther, "/topology")
    } else { 
        c.Header("WWW-Authenticate", "Basic realm=Restricted")
        c.AbortWithStatus(http.StatusUnauthorized)
    }
}
