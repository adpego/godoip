package doip

import (
	"encoding/binary"
	"fmt"
)

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

// RoutingActivationRequest represents payload type 0x0005.
type RoutingActivationRequest struct {
	SourceAddress  uint16
	ActivationType uint8
	OEMSpecific    []byte // optional, 4 bytes
}

func ParseRoutingActivationRequest(payload []byte) (RoutingActivationRequest, error) {
	if len(payload) < 7 {
		return RoutingActivationRequest{}, fmt.Errorf("routing activation request too short: %d bytes", len(payload))
	}
	req := RoutingActivationRequest{
		SourceAddress:  binary.BigEndian.Uint16(payload[0:2]),
		ActivationType: payload[2],
	}
	if len(payload) >= 11 {
		req.OEMSpecific = payload[7:11]
	}
	return req, nil
}

// BuildRoutingActivationResponse builds a Routing Activation Response message.
func BuildRoutingActivationResponse(version uint8, clientAddr, gatewayAddr uint16, code uint8) []byte {
	const payloadLen = 9
	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint16(payload[0:2], clientAddr)
	binary.BigEndian.PutUint16(payload[2:4], gatewayAddr)
	payload[4] = code
	// payload[5:9] reserved, zero

	return append(BuildHeader(version, RoutingActivationResp, payloadLen), payload...)
}
