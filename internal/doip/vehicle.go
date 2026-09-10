package doip

import (
	"encoding/binary"
	"fmt"
)

// AnnouncePayload holds the data of a vehicle announcement / vehicle
// identification response (0x0004).
type AnnouncePayload struct {
	Version        uint8
	VIN            string // 17 chars, padded/truncated
	LogicalAddress uint16
	EID            [6]byte // typically the MAC address
	GID            [6]byte
	FurtherAction  uint8  // 0x00 = no further action, 0x10 = routing activation for central security
	SyncStatus     *uint8 // VIN/GID sync status; nil omits the optional byte
}

// BuildAnnouncement builds a vehicle announcement / identification response.
func BuildAnnouncement(p AnnouncePayload) []byte {
	payloadLen := 32
	if p.SyncStatus != nil {
		payloadLen = 33
	}
	payload := make([]byte, payloadLen)

	vin := []byte(p.VIN)
	if len(vin) > 17 {
		vin = vin[:17]
	}
	copy(payload[0:17], vin)
	binary.BigEndian.PutUint16(payload[17:19], p.LogicalAddress)
	copy(payload[19:25], p.EID[:])
	copy(payload[25:31], p.GID[:])
	payload[31] = p.FurtherAction
	if p.SyncStatus != nil {
		payload[32] = *p.SyncStatus
	}

	return append(BuildHeader(p.Version, VehicleIdentResponse, uint32(payloadLen)), payload...)
}

// VehicleIdentMatches reports whether a vehicle identification request
// (0x0001, 0x0002 or 0x0003) addresses the entity described by p.
func VehicleIdentMatches(payloadType uint16, payload []byte, p AnnouncePayload) (bool, error) {
	switch payloadType {
	case VehicleIdentRequest:
		return true, nil
	case VehicleIdentRequestEID:
		if len(payload) != 6 {
			return false, fmt.Errorf("EID request: %d bytes", len(payload))
		}
		return [6]byte(payload) == p.EID, nil
	case VehicleIdentRequestVIN:
		if len(payload) != 17 {
			return false, fmt.Errorf("VIN request: %d bytes", len(payload))
		}
		return string(payload) == p.VIN, nil
	}
	return false, fmt.Errorf("not a vehicle identification request: 0x%04X", payloadType)
}
