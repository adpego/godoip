package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	TCPPort                 int    `yaml:"tcp_port"`
	UDPPort                 int    `yaml:"udp_port"`
	DoIPVersion             uint8  `yaml:"doip_version"`
	LogicalAddress          int    `yaml:"logical_address"`
	EID                     string `yaml:"eid"` // hex MAC, e.g. "00:1A:2B:3C:4D:5E"
	GID                     string `yaml:"gid"` // hex MAC-like group ID
	ClientLogicalAddressMin int    `yaml:"client_logical_address_min"`
	ClientLogicalAddressMax int    `yaml:"client_logical_address_max"`
}

type DID struct {
	ID    int    `yaml:"id"`
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
	NRC   byte   `yaml:"nrc"` // if non-zero, respond with this NRC instead of value
}

type Service struct {
	SID      int   `yaml:"sid"`
	NRC      byte  `yaml:"nrc"` // if non-zero, deny the entire service with this NRC
	DIDs     []DID `yaml:"dids"`
	Sessions []int `yaml:"sessions"`
}

type ECU struct {
	LogicalAddress int       `yaml:"logical_address"`
	Services       []Service `yaml:"services"`
}

type Config struct {
	Server ServerConfig `yaml:"server"`
	ECUs   []ECU        `yaml:"ecus"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
