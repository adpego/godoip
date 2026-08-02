package main

import (
	"testing"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/uds"
)

// TestExampleConfig makes sure the shipped config.yaml is always valid.
func TestExampleConfig(t *testing.T) {
	cfg, err := config.Load("../../config.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := uds.NewECU(cfg.ECU); err != nil {
		t.Fatalf("NewECU: %v", err)
	}
	if _, err := buildAnnouncement(cfg); err != nil {
		t.Fatalf("buildAnnouncement: %v", err)
	}
	if tcp := buildTCPConfig(cfg); tcp.FunctionalAddress == 0 || tcp.LogicalAddress == 0 {
		t.Errorf("unexpected TCP config: %+v", tcp)
	}
}
