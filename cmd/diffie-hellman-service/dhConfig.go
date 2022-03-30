package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type DhParams struct {
	KeySize uint32 `json:"keySize"`
	P       string `json:"p"`
	G       int    `json:"g"`
}

type DhConfig struct {
	AppName  string   `json:"appName"`
	DhParams DhParams `json:"dhConfig"`
}

var dhCfgData DhConfig

func initDhConfig(configPath string) *DhConfig {

	configFile, err := os.Open(configPath)

	if err != nil {
		log.Printf("Error: %v", err)

		configPath = "./config-dh.json"

		configFile, err = os.Open(configPath)

		if err != nil {
			log.Printf("Error: %v", err)
			return &dhCfgData
		}
	}
	log.Print("Successfully Opened config file:", configPath)

	defer configFile.Close()

	byteValue, _ := ioutil.ReadAll(configFile)

	err = json.Unmarshal(byteValue, &dhCfgData)

	if err != nil {
		log.Printf("Error: %v", err)
		return nil
	}

	log.Println("dhConfiguration appName:", dhCfgData.AppName)
	log.Println("dhConfiguration Key size:", dhCfgData.DhParams.KeySize)
	log.Println("dhConfiguration P:", dhCfgData.DhParams.P)
	log.Print("dhConfiguration G:", dhCfgData.DhParams.G)

	return &dhCfgData
}
