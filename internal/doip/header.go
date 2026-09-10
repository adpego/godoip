package doip

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Header is a DoIP generic header.
type Header struct {
	Version        uint8
	InverseVersion uint8
	PayloadType    uint16
	PayloadLen     uint32
}

// BuildHeader builds an 8-byte DoIP header.
func BuildHeader(version uint8, payloadType uint16, payloadLen uint32) []byte {
	h := make([]byte, HeaderLength)
	h[0] = version
	h[1] = ^version
	binary.BigEndian.PutUint16(h[2:4], payloadType)
	binary.BigEndian.PutUint32(h[4:8], payloadLen)
	return h
}

// ParseHeader decodes a header from the first 8 bytes of b.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLength {
		return Header{}, fmt.Errorf("header too short: %d bytes", len(b))
	}
	return Header{
		Version:        b[0],
		InverseVersion: b[1],
		PayloadType:    binary.BigEndian.Uint16(b[2:4]),
		PayloadLen:     binary.BigEndian.Uint32(b[4:8]),
	}, nil
}

// ReadHeader reads and decodes a header from r.
func ReadHeader(r io.Reader) (Header, error) {
	buf := make([]byte, HeaderLength)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Header{}, fmt.Errorf("read header: %w", err)
	}
	return ParseHeader(buf)
}

// Validate checks a received header (ISO 13400-2, figure 7) against the
// supported protocol version, the payload types handled by the receiver and
// the maximum payload size. It returns the generic NACK code to send, or
// ok=true. NackIncorrectPattern and NackInvalidPayloadLength require closing
// a TCP socket.
func (h Header) Validate(version uint8, handled map[uint16]bool, maxPayload uint32) (code uint8, ok bool) {
	if h.InverseVersion != ^h.Version {
		return NackIncorrectPattern, false
	}
	isIdentRequest := h.PayloadType >= VehicleIdentRequest && h.PayloadType <= VehicleIdentRequestVIN
	if h.Version != version && !(h.Version == DefaultVersion && isIdentRequest) {
		return NackIncorrectPattern, false
	}
	if !handled[h.PayloadType] {
		return NackUnknownPayloadType, false
	}
	if maxPayload > 0 && h.PayloadLen > maxPayload {
		return NackMessageTooLarge, false
	}
	if !ValidPayloadLength(h.PayloadType, h.PayloadLen) {
		return NackInvalidPayloadLength, false
	}
	return 0, true
}

// BuildGenericNack builds a generic DoIP header negative acknowledge (0x0000).
func BuildGenericNack(version uint8, code uint8) []byte {
	return append(BuildHeader(version, GenericNack, 1), code)
}
