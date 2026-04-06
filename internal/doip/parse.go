package doip

import (
	"encoding/binary"
	"fmt"
	"io"
)

type Header struct {
	Version     uint8
	PayloadType uint16
	PayloadLen  uint32
}

func ReadHeader(r io.Reader) (Header, error) {
	buf := make([]byte, HeaderLength)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Header{}, fmt.Errorf("read header: %w", err)
	}
	return Header{
		Version:     buf[0],
		PayloadType: binary.BigEndian.Uint16(buf[2:4]),
		PayloadLen:  binary.BigEndian.Uint32(buf[4:8]),
	}, nil
}

// RoutingActivationRequest represents payload type 0x0005.
type RoutingActivationRequest struct {
	SourceAddress  uint16
	ActivationType uint8
}

func ParseRoutingActivationRequest(payload []byte) (RoutingActivationRequest, error) {
	if len(payload) < 7 {
		return RoutingActivationRequest{}, fmt.Errorf("routing activation request too short: %d bytes", len(payload))
	}
	return RoutingActivationRequest{
		SourceAddress:  binary.BigEndian.Uint16(payload[0:2]),
		ActivationType: payload[2],
	}, nil
}
