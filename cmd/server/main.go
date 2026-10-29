package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/doip"
	"github.com/adpego/godoip/internal/transport"
	"github.com/adpego/godoip/internal/uds/services"
)

const (
	defaultFunctionalAddress = 0xE400
	defaultAnnounceAddress   = "255.255.255.255"
	defaultAnnounceCount     = 3
	defaultAnnounceInterval  = 500 * time.Millisecond
	defaultPort              = 13400 // ISO 13400-2 UDP_DISCOVERY / TCP_DATA
	defaultDoIPVersion       = 0x02  // ISO 13400-2:2012
	defaultClientAddrMin     = 0x0E00
	defaultClientAddrMax     = 0x0FFF // ISO 13400-2 external test equipment range

	// vinDID is the standard VIN data identifier, used when no VIN is configured.
	vinDID = 0xF190
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	applyServerDefaults(&cfg.Server)

	ecu, err := services.New(cfg.ECU)
	if err != nil {
		log.Fatalf("invalid ECU config: %v", err)
	}

	entityCfg, err := buildEntityConfig(cfg)
	if err != nil {
		log.Fatalf("invalid DoIP entity config: %v", err)
	}
	entity := transport.NewEntity(entityCfg)

	errCh := make(chan error, 2)
	go func() {
		errCh <- transport.NewUDPServer(cfg.Server.UDPPort, entity, buildAnnouncementConfig(cfg)).Listen()
	}()
	go func() {
		errCh <- transport.NewTCPServer(buildTCPConfig(cfg), entity, ecu).Listen()
	}()

	if err := <-errCh; err != nil {
		log.Fatal(err)
	}
}

// applyServerDefaults fills the DoIP settings left out of the configuration
// with their ISO 13400-2 defaults.
func applyServerDefaults(s *config.ServerConfig) {
	if s.TCPPort == 0 {
		s.TCPPort = defaultPort
	}
	if s.UDPPort == 0 {
		s.UDPPort = defaultPort
	}
	if s.DoIPVersion == 0 {
		s.DoIPVersion = defaultDoIPVersion
	}
	if s.ClientLogicalAddressMin == 0 && s.ClientLogicalAddressMax == 0 {
		s.ClientLogicalAddressMin, s.ClientLogicalAddressMax = defaultClientAddrMin, defaultClientAddrMax
	}
}

func buildEntityConfig(cfg *config.Config) (transport.EntityConfig, error) {
	s := cfg.Server
	vin, err := announcedVIN(cfg)
	if err != nil {
		return transport.EntityConfig{}, err
	}
	eid, err := parseHWAddr(s.EID)
	if err != nil {
		return transport.EntityConfig{}, fmt.Errorf("eid: %w", err)
	}
	gid, err := parseHWAddr(s.GID)
	if err != nil {
		return transport.EntityConfig{}, fmt.Errorf("gid: %w", err)
	}

	nodeType := doip.NodeTypeNode
	switch s.NodeType {
	case "", "node":
	case "gateway":
		nodeType = doip.NodeTypeGateway
	default:
		return transport.EntityConfig{}, fmt.Errorf("node_type must be node or gateway, got %q", s.NodeType)
	}

	powerMode := doip.PowerModeReady
	if s.PowerMode != nil {
		powerMode = *s.PowerMode
	}

	return transport.EntityConfig{
		DoIPVersion:    s.DoIPVersion,
		LogicalAddress: uint16(s.LogicalAddress),
		VIN:            vin,
		EID:            eid,
		GID:            gid,
		FurtherAction:  s.FurtherAction,
		SyncStatus:     s.VINGIDSyncStatus,
		NodeType:       nodeType,
		MaxSockets:     s.MaxTCPSockets,
		MaxDataSize:    s.MaxDataSize,
		PowerMode:      powerMode,
	}, nil
}

func buildAnnouncementConfig(cfg *config.Config) transport.AnnouncementConfig {
	a := cfg.Server.Announcement
	out := transport.AnnouncementConfig{
		Enabled:      a.Enabled == nil || *a.Enabled,
		Count:        defaultAnnounceCount,
		Interval:     defaultAnnounceInterval,
		InitialDelay: time.Duration(a.InitialDelayMs) * time.Millisecond,
	}
	if a.Count > 0 {
		out.Count = a.Count
	}
	if a.IntervalMs > 0 {
		out.Interval = time.Duration(a.IntervalMs) * time.Millisecond
	}
	host, port := a.Address, a.Port
	if host == "" {
		host = defaultAnnounceAddress
	}
	if port == 0 {
		port = cfg.Server.UDPPort
	}
	out.Address = net.JoinHostPort(host, fmt.Sprint(port))
	return out
}

func buildTCPConfig(cfg *config.Config) transport.TCPConfig {
	s := cfg.Server
	functional := s.FunctionalAddress
	if functional == 0 {
		functional = defaultFunctionalAddress
	}
	return transport.TCPConfig{
		Port:              s.TCPPort,
		FunctionalAddress: uint16(functional),
		ClientAddrMin:     uint16(s.ClientLogicalAddressMin),
		ClientAddrMax:     uint16(s.ClientLogicalAddressMax),
		ActivationTypes:   s.ActivationTypes,
		InitialInactivity: time.Duration(s.InitialInactivity) * time.Millisecond,
		GeneralInactivity: time.Duration(s.GeneralInactivity) * time.Millisecond,
		AliveCheckTimeout: time.Duration(s.AliveCheckTimeout) * time.Millisecond,
	}
}

// announcedVIN returns the configured VIN, or the initial value of DID 0xF190.
func announcedVIN(cfg *config.Config) (string, error) {
	if cfg.Server.VIN != "" {
		return cfg.Server.VIN, nil
	}
	for _, d := range cfg.ECU.DIDs {
		if d.ID == vinDID {
			v, err := d.Bytes()
			return string(v), err
		}
	}
	return "", nil
}

// parseHWAddr parses a 6-byte EID/GID; an empty string gives all zeros.
func parseHWAddr(s string) ([6]byte, error) {
	var out [6]byte
	if s == "" {
		return out, nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return out, err
	}
	if len(hw) != 6 {
		return out, fmt.Errorf("%q is not a 6-byte address", s)
	}
	copy(out[:], hw)
	return out, nil
}
