// Package transport implements the DoIP UDP and TCP servers.
package transport

import (
	"sync/atomic"
	"time"

	"github.com/adpego/godoip/internal/doip"
)

// EntityConfig describes the DoIP entity shared by the UDP and TCP servers.
type EntityConfig struct {
	DoIPVersion    uint8
	LogicalAddress uint16 // DoIP entity and ECU physical address
	VIN            string
	EID, GID       [6]byte
	FurtherAction  uint8
	SyncStatus     *uint8
	NodeType       uint8
	MaxSockets     int
	MaxDataSize    uint32
	PowerMode      uint8
}

// Entity is the DoIP entity state shared by the UDP and TCP servers.
type Entity struct {
	cfg         EntityConfig
	openSockets atomic.Int32
}

// NewEntity creates an entity, filling unset limits with ISO defaults.
func NewEntity(cfg EntityConfig) *Entity {
	if cfg.MaxSockets <= 0 {
		cfg.MaxSockets = 15
	}
	if cfg.MaxDataSize == 0 {
		cfg.MaxDataSize = 4096
	}
	return &Entity{cfg: cfg}
}

// Announcement returns the vehicle announcement / identification payload.
func (e *Entity) Announcement() doip.AnnouncePayload {
	return doip.AnnouncePayload{
		Version:        e.cfg.DoIPVersion,
		VIN:            e.cfg.VIN,
		LogicalAddress: e.cfg.LogicalAddress,
		EID:            e.cfg.EID,
		GID:            e.cfg.GID,
		FurtherAction:  e.cfg.FurtherAction,
		SyncStatus:     e.cfg.SyncStatus,
	}
}

// Status returns the current entity status.
func (e *Entity) Status() doip.EntityStatus {
	return doip.EntityStatus{
		NodeType:    e.cfg.NodeType,
		MaxSockets:  uint8(e.cfg.MaxSockets),
		OpenSockets: uint8(e.openSockets.Load()),
		MaxDataSize: e.cfg.MaxDataSize,
	}
}

// AnnouncementConfig configures the vehicle announcements sent on start-up.
type AnnouncementConfig struct {
	Enabled      bool
	Count        int
	Interval     time.Duration
	InitialDelay time.Duration
	Address      string // host:port
}
