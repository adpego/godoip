package main

import (
	"fmt"
	"log"

	"github.com/adpego/godoip/internal/config"
)

func main() {
	fmt.Println("GoDoIP Server - Starting...")

	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	fmt.Printf("TCP port: %d, UDP port: %d\n", cfg.Server.TCPPort, cfg.Server.UDPPort)
	for _, ecu := range cfg.ECUs {
		fmt.Printf("ECU: (0x%X)\n", ecu.LogicalAddress)
	}
}
