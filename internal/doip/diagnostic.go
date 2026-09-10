package doip

import (
	"encoding/binary"
	"fmt"
)

// Diagnostic negative ack codes (ISO 13400-2).
const (
	DiagNackInvalidSourceAddress uint8 = 0x02 // Source address unknown or not activated
	DiagNackUnknownTargetAddress uint8 = 0x03 // Target address not reachable
	DiagNackMessageTooLarge      uint8 = 0x04
	DiagNackOutOfMemory          uint8 = 0x05
	DiagNackTargetUnreachable    uint8 = 0x06
)

// DiagnosticMsg represents payload type 0x8001.
type DiagnosticMsg struct {
	SourceAddress uint16
	TargetAddress uint16
	UserData      []byte
}

func ParseDiagnosticMessage(payload []byte) (DiagnosticMsg, error) {
	if len(payload) < 5 {
		return DiagnosticMsg{}, fmt.Errorf("diagnostic message too short: %d bytes", len(payload))
	}
	return DiagnosticMsg{
		SourceAddress: binary.BigEndian.Uint16(payload[0:2]),
		TargetAddress: binary.BigEndian.Uint16(payload[2:4]),
		UserData:      payload[4:],
	}, nil
}

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
