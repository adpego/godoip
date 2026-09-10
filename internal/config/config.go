package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	TCPPort                 int    `yaml:"tcp_port"`
	UDPPort                 int    `yaml:"udp_port"`
	DoIPVersion             uint8  `yaml:"doip_version"`
	LogicalAddress          int    `yaml:"logical_address"`    // DoIP entity address, also the ECU physical address
	FunctionalAddress       int    `yaml:"functional_address"` // UDS functional address; defaults to 0xE400
	VIN                     string `yaml:"vin"`                // announced VIN; defaults to DID 0xF190 if present
	EID                     string `yaml:"eid"`                // hex MAC, e.g. "00:1A:2B:3C:4D:5E"
	GID                     string `yaml:"gid"`                // hex MAC-like group ID
	ClientLogicalAddressMin int    `yaml:"client_logical_address_min"`
	ClientLogicalAddressMax int    `yaml:"client_logical_address_max"`

	NodeType          string  `yaml:"node_type"`             // node | gateway; defaults to node
	MaxTCPSockets     int     `yaml:"max_tcp_sockets"`       // defaults to 15
	MaxDataSize       uint32  `yaml:"max_data_size"`         // max DoIP payload accepted; defaults to 4096
	PowerMode         *uint8  `yaml:"power_mode"`            // diagnostic power mode; defaults to 0x01 (ready)
	FurtherAction     uint8   `yaml:"further_action"`        // announcement further action required
	VINGIDSyncStatus  *uint8  `yaml:"vin_gid_sync_status"`   // optional announcement byte; nil omits it
	ActivationTypes   []uint8 `yaml:"activation_types"`      // supported routing activation types; defaults to 0x00, 0x01
	InitialInactivity int     `yaml:"initial_inactivity_ms"` // close sockets without routing activation; defaults to 2000
	GeneralInactivity int     `yaml:"general_inactivity_ms"` // close idle sockets; defaults to 300000

	Announcement Announcement `yaml:"announcement"`
}

// Announcement configures the vehicle announcements sent on start-up.
type Announcement struct {
	Enabled        *bool  `yaml:"enabled"`          // defaults to true
	Count          int    `yaml:"count"`            // defaults to 3
	IntervalMs     int    `yaml:"interval_ms"`      // defaults to 500
	InitialDelayMs int    `yaml:"initial_delay_ms"` // delay before the first announcement
	Address        string `yaml:"address"`          // destination; defaults to 255.255.255.255
	Port           int    `yaml:"port"`             // destination port; defaults to udp_port
}

type Config struct {
	Server ServerConfig `yaml:"server"`
	ECU    ECU          `yaml:"ecu"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, err
	}
	// File paths in the configuration are relative to the configuration file.
	if cfg.ECU.Memory != nil {
		cfg.ECU.Memory.resolvePaths(filepath.Dir(path))
	}
	return cfg, nil
}

// Parse decodes a YAML configuration document.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
