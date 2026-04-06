package doip

import "encoding/binary"

// BuildHeader builds an 8-byte DoIP header.
func BuildHeader(version uint8, payloadType uint16, payloadLen uint32) []byte {
	h := make([]byte, HeaderLength)
	h[0] = version
	h[1] = ^version
	binary.BigEndian.PutUint16(h[2:4], payloadType)
	binary.BigEndian.PutUint32(h[4:8], payloadLen)
	return h
}

// AnnouncePayload holds the data needed to build a Vehicle Announcement.
type AnnouncePayload struct {
	Version        uint8
	VIN            string // 17 chars
	LogicalAddress uint16
	EID            [6]byte // typically the MAC address
	GID            [6]byte
}

// BuildAnnouncement builds a full DoIP Vehicle Announcement message (header + payload).
func BuildAnnouncement(p AnnouncePayload) []byte {
	const payloadLen = 33
	payload := make([]byte, payloadLen)

	// VIN — 17 bytes, null-padded
	vin := []byte(p.VIN)
	if len(vin) > 17 {
		vin = vin[:17]
	}
	copy(payload[0:17], vin)

	binary.BigEndian.PutUint16(payload[17:19], p.LogicalAddress)
	copy(payload[19:25], p.EID[:])
	copy(payload[25:31], p.GID[:])
	payload[31] = 0x00 // no further action required
	payload[32] = 0x00 // VIN/GID sync status

	header := BuildHeader(p.Version, VehicleIdentResponse, payloadLen)
	return append(header, payload...)
}
