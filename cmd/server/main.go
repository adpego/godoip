package main

import (
	"log"
	"net"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/doip"
	"github.com/adpego/godoip/internal/transport"
)

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	announce, err := buildAnnouncement(cfg)
	if err != nil {
		log.Fatalf("invalid announcement config: %v", err)
	}

	errCh := make(chan error, 2)

	go func() {
		errCh <- transport.NewUDPServer(cfg.Server.UDPPort, announce).Listen()
	}()

	go func() {
		tcpServer := transport.NewTCPServer(
			cfg.Server.TCPPort,
			cfg.Server.DoIPVersion,
			uint16(cfg.Server.LogicalAddress),
			uint16(cfg.Server.ClientLogicalAddressMin),
			uint16(cfg.Server.ClientLogicalAddressMax),
		)
		errCh <- tcpServer.Listen()
	}()

	if err := <-errCh; err != nil {
		log.Fatal(err)
	}
}

func parseHWAddr(s string) ([6]byte, error) {
	var out [6]byte
	hw, err := net.ParseMAC(s)
	if err != nil {
		return out, err
	}
	copy(out[:], hw)
	return out, nil
}

func buildAnnouncement(cfg *config.Config) (doip.AnnouncePayload, error) {
	var vin string
	var logicalAddr uint16

	if len(cfg.ECUs) > 0 {
		ecu := cfg.ECUs[0]
		logicalAddr = uint16(ecu.LogicalAddress)
		for _, svc := range ecu.Services {
			for _, did := range svc.DIDs {
				if did.ID == 0xF190 {
					vin = did.Value
				}
			}
		}
	}

	eid, err := parseHWAddr(cfg.Server.EID)
	if err != nil {
		return doip.AnnouncePayload{}, err
	}

	gid, err := parseHWAddr(cfg.Server.GID)
	if err != nil {
		return doip.AnnouncePayload{}, err
	}

	return doip.AnnouncePayload{
		Version:        cfg.Server.DoIPVersion,
		VIN:            vin,
		LogicalAddress: logicalAddr,
		EID:            eid,
		GID:            gid,
	}, nil
}
