package models

import (
    "os"
    "log"

    "github.com/BurntSushi/toml"
)

var (
    configErrors []string
)

type Config struct {
    AdminUsername string
    AdminPassword string
    AgentKey string
}

func ReadConfig(conf *Config, configPath string) {
	fileContent, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalln("Configuration file ("+configPath+") not found:", err)
	}
	if md, err := toml.Decode(string(fileContent), &conf); err != nil {
		log.Fatalln(err)
	} else {
		for _, undecoded := range md.Undecoded() {
			errMsg := "[WARN] Undecoded scoring configuration key \"" + undecoded.String() + "\" will not be used."
			configErrors = append(configErrors, errMsg)
			log.Println(errMsg)
		}
	}
}
