package main

import (
	"log"
	"net"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/doip"
	"github.com/adpego/godoip/internal/transport"
	"github.com/adpego/godoip/internal/uds"
)

const defaultFunctionalAddress = 0xE400

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	ecu, err := uds.NewECU(cfg.ECU)
	if err != nil {
		log.Fatalf("invalid ECU config: %v", err)
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
		errCh <- transport.NewTCPServer(buildTCPConfig(cfg), ecu).Listen()
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

func buildTCPConfig(cfg *config.Config) transport.TCPConfig {
	functional := cfg.Server.FunctionalAddress
	if functional == 0 {
		functional = defaultFunctionalAddress
	}
	return transport.TCPConfig{
		Port:              cfg.Server.TCPPort,
		DoIPVersion:       cfg.Server.DoIPVersion,
		LogicalAddress:    uint16(cfg.Server.LogicalAddress),
		FunctionalAddress: uint16(functional),
		ClientAddrMin:     uint16(cfg.Server.ClientLogicalAddressMin),
		ClientAddrMax:     uint16(cfg.Server.ClientLogicalAddressMax),
	}
}

func buildAnnouncement(cfg *config.Config) (doip.AnnouncePayload, error) {
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
		VIN:            cfg.Server.VIN,
		LogicalAddress: uint16(cfg.Server.LogicalAddress),
		EID:            eid,
		GID:            gid,
	}, nil
}
