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
