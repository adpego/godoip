// Package doip encodes and decodes DoIP (ISO 13400-2) messages.
package doip

const (
	HeaderLength = 8

	// DefaultVersion is accepted in vehicle identification requests
	// regardless of the configured protocol version.
	DefaultVersion uint8 = 0xFF
)

// Payload types (ISO 13400-2, table 17).
const (
	GenericNack             uint16 = 0x0000
	VehicleIdentRequest     uint16 = 0x0001
	VehicleIdentRequestEID  uint16 = 0x0002
	VehicleIdentRequestVIN  uint16 = 0x0003
	VehicleIdentResponse    uint16 = 0x0004
	RoutingActivationReq    uint16 = 0x0005
	RoutingActivationResp   uint16 = 0x0006
	AliveCheckReq           uint16 = 0x0007
	AliveCheckResp          uint16 = 0x0008
	EntityStatusReq         uint16 = 0x4001
	EntityStatusResp        uint16 = 0x4002
	DiagnosticPowerModeReq  uint16 = 0x4003
	DiagnosticPowerModeResp uint16 = 0x4004
	DiagnosticMessage       uint16 = 0x8001
	DiagnosticPositiveAck   uint16 = 0x8002
	DiagnosticNegativeAck   uint16 = 0x8003
)

// Generic DoIP header negative acknowledge codes (ISO 13400-2, table 19).
const (
	NackIncorrectPattern     uint8 = 0x00 // close socket
	NackUnknownPayloadType   uint8 = 0x01
	NackMessageTooLarge      uint8 = 0x02
	NackOutOfMemory          uint8 = 0x03
	NackInvalidPayloadLength uint8 = 0x04 // close socket
)

// payloadLengths lists the valid payload lengths of fixed-size requests
// handled by a DoIP entity; nil means "at least min".
var payloadLengths = map[uint16]struct {
	min   uint32
	exact []uint32
}{
	VehicleIdentRequest:    {exact: []uint32{0}},
	VehicleIdentRequestEID: {exact: []uint32{6}},
	VehicleIdentRequestVIN: {exact: []uint32{17}},
	RoutingActivationReq:   {exact: []uint32{7, 11}},
	AliveCheckReq:          {exact: []uint32{0}},
	AliveCheckResp:         {exact: []uint32{2}},
	EntityStatusReq:        {exact: []uint32{0}},
	DiagnosticPowerModeReq: {exact: []uint32{0}},
	DiagnosticMessage:      {min: 5},
}

// ValidPayloadLength reports whether n is a valid payload length for the
// payload type. Unknown payload types are always valid.
func ValidPayloadLength(payloadType uint16, n uint32) bool {
	rule, ok := payloadLengths[payloadType]
	if !ok {
		return true
	}
	if rule.exact == nil {
		return n >= rule.min
	}
	for _, e := range rule.exact {
		if n == e {
			return true
		}
	}
	return false
}
