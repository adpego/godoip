package main

import (
	"testing"
	"time"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/doip"
	"github.com/adpego/godoip/internal/uds/services"
)

// TestExampleConfig makes sure the shipped configurations are always valid.
func TestExampleConfig(t *testing.T) {
	for _, path := range []string{"../../config.yaml", "../../tests/e2e/config.yaml"} {
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("%s: load: %v", path, err)
		}
		if _, err := services.New(cfg.ECU); err != nil {
			t.Fatalf("%s: services.New: %v", path, err)
		}
		if _, err := buildEntityConfig(cfg); err != nil {
			t.Fatalf("%s: buildEntityConfig: %v", path, err)
		}
		if tcp := buildTCPConfig(cfg); tcp.FunctionalAddress == 0 {
			t.Errorf("%s: unexpected TCP config: %+v", path, tcp)
		}
	}
}

func baseConfig() *config.Config {
	return &config.Config{Server: config.ServerConfig{
		UDPPort: 13400,
		EID:     "00:00:00:00:00:01",
		GID:     "00:00:00:00:00:02",
	}}
}

func TestAnnouncementVINFallsBackToDID(t *testing.T) {
	cfg := baseConfig()
	cfg.ECU.DIDs = []config.DID{{ID: vinDID, Data: config.Data{ASCII: "VF1AAAAA555555555"}}}

	e, err := buildEntityConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.VIN != "VF1AAAAA555555555" {
		t.Errorf("VIN: got %q", e.VIN)
	}

	cfg.Server.VIN = "WBA12345678901234"
	if e, _ := buildEntityConfig(cfg); e.VIN != "WBA12345678901234" {
		t.Errorf("configured VIN should win, got %q", e.VIN)
	}
}

func TestEntityConfigDefaultsAndOptions(t *testing.T) {
	cfg := baseConfig()
	e, err := buildEntityConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.NodeType != doip.NodeTypeNode || e.PowerMode != doip.PowerModeReady || e.SyncStatus != nil {
		t.Errorf("defaults: %+v", e)
	}

	mode, sync := uint8(0x00), uint8(0x10)
	cfg.Server.NodeType = "gateway"
	cfg.Server.PowerMode = &mode
	cfg.Server.VINGIDSyncStatus = &sync
	e, err = buildEntityConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.NodeType != doip.NodeTypeGateway || e.PowerMode != 0x00 || *e.SyncStatus != 0x10 {
		t.Errorf("options: %+v", e)
	}

	for name, bad := range map[string]func(*config.Config){
		"node type": func(c *config.Config) { c.Server.NodeType = "router" },
		"eid":       func(c *config.Config) { c.Server.EID = "nope" },
		"gid":       func(c *config.Config) { c.Server.GID = "00:00:00:00:00:00:00:01" },
	} {
		c := baseConfig()
		bad(c)
		if _, err := buildEntityConfig(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAnnouncementConfig(t *testing.T) {
	cfg := baseConfig()
	a := buildAnnouncementConfig(cfg)
	if !a.Enabled || a.Count != 3 || a.Interval != 500*time.Millisecond || a.Address != "255.255.255.255:13400" {
		t.Errorf("defaults: %+v", a)
	}

	disabled := false
	cfg.Server.Announcement = config.Announcement{
		Enabled: &disabled, Count: 1, IntervalMs: 100, InitialDelayMs: 50, Address: "127.0.0.1", Port: 13401,
	}
	a = buildAnnouncementConfig(cfg)
	if a.Enabled || a.Count != 1 || a.Interval != 100*time.Millisecond || a.InitialDelay != 50*time.Millisecond || a.Address != "127.0.0.1:13401" {
		t.Errorf("custom: %+v", a)
	}
}
