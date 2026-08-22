package main

import (
	"testing"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/uds/services"
)

// TestExampleConfig makes sure the shipped config.yaml is always valid.
func TestExampleConfig(t *testing.T) {
	cfg, err := config.Load("../../config.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := services.New(cfg.ECU); err != nil {
		t.Fatalf("services.New: %v", err)
	}
	if _, err := buildAnnouncement(cfg); err != nil {
		t.Fatalf("buildAnnouncement: %v", err)
	}
	if tcp := buildTCPConfig(cfg); tcp.FunctionalAddress == 0 || tcp.LogicalAddress == 0 {
		t.Errorf("unexpected TCP config: %+v", tcp)
	}
}

func TestAnnouncementVINFallsBackToDID(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{EID: "00:00:00:00:00:01", GID: "00:00:00:00:00:02"},
		ECU: config.ECU{DIDs: []config.DID{
			{ID: vinDID, Data: config.Data{ASCII: "VF1AAAAA555555555"}},
		}},
	}
	a, err := buildAnnouncement(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.VIN != "VF1AAAAA555555555" {
		t.Errorf("VIN: got %q", a.VIN)
	}

	cfg.Server.VIN = "WBA12345678901234"
	if a, _ := buildAnnouncement(cfg); a.VIN != "WBA12345678901234" {
		t.Errorf("configured VIN should win, got %q", a.VIN)
	}
}
