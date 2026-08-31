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

// Routing activation response codes (ISO 13400-2).
const (
	ActivationDeniedUnknownSrc       uint8 = 0x00 // Unknown source address — close socket
	ActivationDeniedNoFreeSockets    uint8 = 0x01 // All TCP sockets active — close socket
	ActivationDeniedSAMismatch       uint8 = 0x02 // SA mismatch on active socket — close socket
	ActivationDeniedSAAlreadyActive  uint8 = 0x03 // SA active on different socket — close socket
	ActivationDeniedMissingAuth      uint8 = 0x04 // Authentication required — register, do not activate
	ActivationDeniedConfirmRejected  uint8 = 0x05 // Confirmation rejected — close socket
	ActivationDeniedUnsupportedType  uint8 = 0x06 // Unsupported activation type — close socket
	ActivationSuccess                uint8 = 0x10 // Successfully activated
	ActivationSuccessConfirmRequired uint8 = 0x11 // Activated, confirmation required
)

// BuildRoutingActivationResponse builds a Routing Activation Response message.
func BuildRoutingActivationResponse(version uint8, clientAddr, gatewayAddr uint16, code uint8) []byte {
	const payloadLen = 9
	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint16(payload[0:2], clientAddr)
	binary.BigEndian.PutUint16(payload[2:4], gatewayAddr)
	payload[4] = code
	// payload[5:9] reserved, zero

	header := BuildHeader(version, RoutingActivationResp, payloadLen)
	return append(header, payload...)
}

// Diagnostic negative ack codes (ISO 13400-2).
const (
	DiagNackInvalidSourceAddress uint8 = 0x02 // Source address unknown or not activated
	DiagNackUnknownTargetAddress uint8 = 0x03 // Target address not reachable
	DiagNackMessageTooLarge      uint8 = 0x04
	DiagNackOutOfMemory          uint8 = 0x05
	DiagNackTargetUnreachable    uint8 = 0x06
)

// BuildDiagnosticAck builds a Diagnostic Positive Ack message (0x8002).
func BuildDiagnosticAck(version uint8, sourceAddr, targetAddr uint16) []byte {
	payload := make([]byte, 5)
	binary.BigEndian.PutUint16(payload[0:2], sourceAddr)
	binary.BigEndian.PutUint16(payload[2:4], targetAddr)
	payload[4] = 0x00
	return append(BuildHeader(version, DiagnosticPositiveAck, 5), payload...)
}

// BuildDiagnosticNack builds a Diagnostic Negative Ack message (0x8003).
func BuildDiagnosticNack(version uint8, sourceAddr, targetAddr uint16, nackCode uint8) []byte {
	payload := make([]byte, 5)
	binary.BigEndian.PutUint16(payload[0:2], sourceAddr)
	binary.BigEndian.PutUint16(payload[2:4], targetAddr)
	payload[4] = nackCode
	return append(BuildHeader(version, DiagnosticNegativeAck, 5), payload...)
}

// BuildDiagnosticMsg wraps a UDS response into a DoIP Diagnostic Message (0x8001).
func BuildDiagnosticMsg(version uint8, sourceAddr, targetAddr uint16, udsData []byte) []byte {
	payloadLen := uint32(4 + len(udsData))
	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint16(payload[0:2], sourceAddr)
	binary.BigEndian.PutUint16(payload[2:4], targetAddr)
	copy(payload[4:], udsData)
	return append(BuildHeader(version, DiagnosticMessage, payloadLen), payload...)
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
