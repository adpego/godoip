package doip

import "encoding/binary"

// Node types for the entity status response.
const (
	NodeTypeGateway uint8 = 0x00
	NodeTypeNode    uint8 = 0x01
)

// Diagnostic power modes.
const (
	PowerModeNotReady     uint8 = 0x00
	PowerModeReady        uint8 = 0x01
	PowerModeNotSupported uint8 = 0x02
)

// EntityStatus is the payload of a DoIP entity status response (0x4002).
type EntityStatus struct {
	NodeType    uint8
	MaxSockets  uint8
	OpenSockets uint8
	MaxDataSize uint32 // 0 omits the optional field
}

// BuildEntityStatusResponse builds a DoIP entity status response.
func BuildEntityStatusResponse(version uint8, s EntityStatus) []byte {
	payload := []byte{s.NodeType, s.MaxSockets, s.OpenSockets}
	if s.MaxDataSize > 0 {
		payload = binary.BigEndian.AppendUint32(payload, s.MaxDataSize)
	}
	return append(BuildHeader(version, EntityStatusResp, uint32(len(payload))), payload...)
}

// BuildPowerModeResponse builds a diagnostic power mode information response.
func BuildPowerModeResponse(version uint8, mode uint8) []byte {
	return append(BuildHeader(version, DiagnosticPowerModeResp, 1), mode)
}

// BuildAliveCheckRequest builds an alive check request (sent by the entity).
func BuildAliveCheckRequest(version uint8) []byte {
	return BuildHeader(version, AliveCheckReq, 0)
}

// BuildAliveCheckResponse builds an alive check response carrying addr.
func BuildAliveCheckResponse(version uint8, addr uint16) []byte {
	return binary.BigEndian.AppendUint16(BuildHeader(version, AliveCheckResp, 2), addr)
}
