package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type GrpcServerConfig struct {
	TlsEnable bool   `json:"tlsEnable"`
	Url       string `json:"url"`
	Port      uint32 `json:"port"`
	CertFile  string `json:"certFile"`
	KeyFile   string `json:"keyFile"`
}

type ClientConfig struct {
	AppName          string           `json:"appName"`
	GrpcServerConfig GrpcServerConfig `json:"gRPCServerConfig"`
}

var configData ClientConfig

func initConfig(configPath string) *ClientConfig {

	configFile, err := os.Open(configPath)

	if err != nil {
		log.Printf("Error: %v", err)

		configPath = "./config-server.json"

		configFile, err = os.Open(configPath)

		if err != nil {
			log.Printf("Error: %v", err)
			return &configData
		}
	}
	log.Print("Successfully Opened config file:", configPath)

	defer configFile.Close()

	byteValue, _ := ioutil.ReadAll(configFile)

	// err = json.Unmarshal([]byte(byteValue), &configData)
	err = json.Unmarshal(byteValue, &configData)

	if err != nil {
		log.Printf("Error: %v", err)
		return nil
	}

	log.Print("gRPCClient SSL enable:", configData.GrpcServerConfig.TlsEnable)
	log.Print("gRPCClient Url: ", configData.GrpcServerConfig.Url)
	log.Print("gRPCClient port: ", configData.GrpcServerConfig.Port)
	log.Print("gRPCClient cert file: ", configData.GrpcServerConfig.CertFile)
	log.Print("gRPCClient key file: ", configData.GrpcServerConfig.KeyFile)

	return &configData
}
