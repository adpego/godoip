package doip

import (
	"bytes"
	"testing"
)

// --- BuildHeader ---

func TestBuildHeader(t *testing.T) {
	h := BuildHeader(0x02, VehicleIdentResponse, 33)

	if h[0] != 0x02 {
		t.Errorf("version: got 0x%02X, want 0x02", h[0])
	}
	if h[1] != ^uint8(0x02) {
		t.Errorf("inverse version: got 0x%02X, want 0x%02X", h[1], ^uint8(0x02))
	}
	if h[2] != 0x00 || h[3] != 0x04 {
		t.Errorf("payload type: got 0x%02X%02X, want 0x0004", h[2], h[3])
	}
	if h[4] != 0x00 || h[5] != 0x00 || h[6] != 0x00 || h[7] != 0x21 {
		t.Errorf("payload length: got %d, want 33", uint32(h[4])<<24|uint32(h[5])<<16|uint32(h[6])<<8|uint32(h[7]))
	}
}

func TestBuildHeaderLength(t *testing.T) {
	h := BuildHeader(0x02, GenericNack, 0)
	if len(h) != HeaderLength {
		t.Errorf("header length: got %d, want %d", len(h), HeaderLength)
	}
}

// --- ReadHeader ---

func TestReadHeader(t *testing.T) {
	original := BuildHeader(0x03, RoutingActivationReq, 7)
	hdr, err := ReadHeader(bytes.NewReader(original))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hdr.Version != 0x03 {
		t.Errorf("version: got 0x%02X, want 0x03", hdr.Version)
	}
	if hdr.PayloadType != RoutingActivationReq {
		t.Errorf("payload type: got 0x%04X, want 0x%04X", hdr.PayloadType, RoutingActivationReq)
	}
	if hdr.PayloadLen != 7 {
		t.Errorf("payload length: got %d, want 7", hdr.PayloadLen)
	}
}

func TestReadHeaderTooShort(t *testing.T) {
	_, err := ReadHeader(bytes.NewReader([]byte{0x02, 0xFD}))
	if err == nil {
		t.Error("expected error for short input, got nil")
	}
}

// --- ParseRoutingActivationRequest ---

func TestParseRoutingActivationRequest(t *testing.T) {
	payload := []byte{0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // addr=0x0E00, type=0x00
	req, err := ParseRoutingActivationRequest(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.SourceAddress != 0x0E00 {
		t.Errorf("source address: got 0x%04X, want 0x0E00", req.SourceAddress)
	}
	if req.ActivationType != 0x00 {
		t.Errorf("activation type: got 0x%02X, want 0x00", req.ActivationType)
	}
}

func TestParseRoutingActivationRequestTooShort(t *testing.T) {
	_, err := ParseRoutingActivationRequest([]byte{0x0E, 0x00})
	if err == nil {
		t.Error("expected error for short payload, got nil")
	}
}

// --- BuildRoutingActivationResponse ---

func TestBuildRoutingActivationResponse(t *testing.T) {
	msg := BuildRoutingActivationResponse(0x02, 0x0E00, 0x0E80, ActivationSuccess)

	if len(msg) != HeaderLength+9 {
		t.Fatalf("message length: got %d, want %d", len(msg), HeaderLength+9)
	}

	// Check header payload type
	hdr, _ := ReadHeader(bytes.NewReader(msg[:HeaderLength]))
	if hdr.PayloadType != RoutingActivationResp {
		t.Errorf("payload type: got 0x%04X, want 0x%04X", hdr.PayloadType, RoutingActivationResp)
	}

	payload := msg[HeaderLength:]
	clientAddr := uint16(payload[0])<<8 | uint16(payload[1])
	gatewayAddr := uint16(payload[2])<<8 | uint16(payload[3])
	code := payload[4]

	if clientAddr != 0x0E00 {
		t.Errorf("client addr: got 0x%04X, want 0x0E00", clientAddr)
	}
	if gatewayAddr != 0x0E80 {
		t.Errorf("gateway addr: got 0x%04X, want 0x0E80", gatewayAddr)
	}
	if code != ActivationSuccess {
		t.Errorf("response code: got 0x%02X, want 0x%02X", code, ActivationSuccess)
	}
}

// --- BuildAnnouncement ---

func TestBuildAnnouncement(t *testing.T) {
	sync := uint8(0x00)
	p := AnnouncePayload{
		SyncStatus:     &sync,
		Version:        0x02,
		VIN:            "WBA12345678901234",
		LogicalAddress: 0x0E00,
		EID:            [6]byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E},
		GID:            [6]byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5F},
	}
	msg := BuildAnnouncement(p)

	if len(msg) != HeaderLength+33 {
		t.Fatalf("message length: got %d, want %d", len(msg), HeaderLength+33)
	}

	hdr, _ := ReadHeader(bytes.NewReader(msg[:HeaderLength]))
	if hdr.PayloadType != VehicleIdentResponse {
		t.Errorf("payload type: got 0x%04X, want 0x%04X", hdr.PayloadType, VehicleIdentResponse)
	}

	payload := msg[HeaderLength:]
	if string(payload[0:17]) != "WBA12345678901234" {
		t.Errorf("VIN: got %q, want %q", string(payload[0:17]), "WBA12345678901234")
	}
	logAddr := uint16(payload[17])<<8 | uint16(payload[18])
	if logAddr != 0x0E00 {
		t.Errorf("logical address: got 0x%04X, want 0x0E00", logAddr)
	}
}

func TestBuildAnnouncementVINTooLong(t *testing.T) {
	p := AnnouncePayload{
		Version: 0x02,
		VIN:     "ABCDEFGHIJKLMNOPQRSTUVWXYZ", // 26 chars, must be truncated to 17
	}
	msg := BuildAnnouncement(p)
	payload := msg[HeaderLength:]
	if len(payload[0:17]) != 17 {
		t.Errorf("VIN field should always be 17 bytes")
	}
}

// --- ParseDiagnosticMessage ---

func TestParseDiagnosticMessage(t *testing.T) {
	payload := []byte{0x0E, 0x00, 0x0E, 0x80, 0x22, 0xF1, 0x90}
	msg, err := ParseDiagnosticMessage(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.SourceAddress != 0x0E00 {
		t.Errorf("source address: got 0x%04X, want 0x0E00", msg.SourceAddress)
	}
	if msg.TargetAddress != 0x0E80 {
		t.Errorf("target address: got 0x%04X, want 0x0E80", msg.TargetAddress)
	}
	if !bytes.Equal(msg.UserData, []byte{0x22, 0xF1, 0x90}) {
		t.Errorf("user data: got % X, want 22 F1 90", msg.UserData)
	}
}

func TestParseDiagnosticMessageTooShort(t *testing.T) {
	_, err := ParseDiagnosticMessage([]byte{0x0E, 0x00, 0x0E})
	if err == nil {
		t.Error("expected error for short payload, got nil")
	}
}

// --- BuildDiagnosticAck ---

func TestBuildDiagnosticAck(t *testing.T) {
	msg := BuildDiagnosticAck(0x02, 0x0E80, 0x0E00)

	if len(msg) != HeaderLength+5 {
		t.Fatalf("length: got %d, want %d", len(msg), HeaderLength+5)
	}
	hdr, _ := ReadHeader(bytes.NewReader(msg[:HeaderLength]))
	if hdr.PayloadType != DiagnosticPositiveAck {
		t.Errorf("payload type: got 0x%04X, want 0x%04X", hdr.PayloadType, DiagnosticPositiveAck)
	}
	payload := msg[HeaderLength:]
	if payload[4] != 0x00 {
		t.Errorf("ack code: got 0x%02X, want 0x00", payload[4])
	}
}

// --- BuildDiagnosticNack ---

func TestBuildDiagnosticNack(t *testing.T) {
	msg := BuildDiagnosticNack(0x02, 0x0E80, 0x0E00, DiagNackUnknownTargetAddress)

	if len(msg) != HeaderLength+5 {
		t.Fatalf("length: got %d, want %d", len(msg), HeaderLength+5)
	}
	hdr, _ := ReadHeader(bytes.NewReader(msg[:HeaderLength]))
	if hdr.PayloadType != DiagnosticNegativeAck {
		t.Errorf("payload type: got 0x%04X, want 0x%04X", hdr.PayloadType, DiagnosticNegativeAck)
	}
	payload := msg[HeaderLength:]
	if payload[4] != DiagNackUnknownTargetAddress {
		t.Errorf("nack code: got 0x%02X, want 0x%02X", payload[4], DiagNackUnknownTargetAddress)
	}
}

// --- BuildDiagnosticMsg ---

func TestBuildDiagnosticMsg(t *testing.T) {
	udsData := []byte{0x62, 0xF1, 0x90, 0x57, 0x42, 0x41}
	msg := BuildDiagnosticMsg(0x02, 0x0E80, 0x0E00, udsData)

	if len(msg) != HeaderLength+4+len(udsData) {
		t.Fatalf("length: got %d, want %d", len(msg), HeaderLength+4+len(udsData))
	}
	hdr, _ := ReadHeader(bytes.NewReader(msg[:HeaderLength]))
	if hdr.PayloadType != DiagnosticMessage {
		t.Errorf("payload type: got 0x%04X, want 0x%04X", hdr.PayloadType, DiagnosticMessage)
	}
	payload := msg[HeaderLength:]
	if !bytes.Equal(payload[4:], udsData) {
		t.Errorf("uds data: got % X, want % X", payload[4:], udsData)
	}
}

func TestBuildAnnouncementWithoutSyncStatus(t *testing.T) {
	msg := BuildAnnouncement(AnnouncePayload{Version: 0x02, FurtherAction: 0x10})
	if len(msg) != HeaderLength+32 {
		t.Fatalf("length: got %d, want %d", len(msg), HeaderLength+32)
	}
	if msg[HeaderLength+31] != 0x10 {
		t.Errorf("further action: got 0x%02X", msg[HeaderLength+31])
	}
}

// --- header validation ---

var handled = map[uint16]bool{VehicleIdentRequest: true, VehicleIdentRequestEID: true, RoutingActivationReq: true, DiagnosticMessage: true}

func TestHeaderValidate(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
		code   uint8
		ok     bool
	}{
		{"valid", BuildHeader(0x02, RoutingActivationReq, 7), 0, true},
		{"valid with OEM data", BuildHeader(0x02, RoutingActivationReq, 11), 0, true},
		{"bad inverse", []byte{0x02, 0x00, 0x00, 0x05, 0, 0, 0, 7}, NackIncorrectPattern, false},
		{"bad version", BuildHeader(0x03, RoutingActivationReq, 7), NackIncorrectPattern, false},
		{"default version ident", BuildHeader(0xFF, VehicleIdentRequest, 0), 0, true},
		{"default version other", BuildHeader(0xFF, RoutingActivationReq, 7), NackIncorrectPattern, false},
		{"unknown type", BuildHeader(0x02, 0x1234, 0), NackUnknownPayloadType, false},
		{"not handled", BuildHeader(0x02, AliveCheckReq, 0), NackUnknownPayloadType, false},
		{"too large", BuildHeader(0x02, DiagnosticMessage, 5000), NackMessageTooLarge, false},
		{"bad length", BuildHeader(0x02, RoutingActivationReq, 8), NackInvalidPayloadLength, false},
		{"bad EID length", BuildHeader(0x02, VehicleIdentRequestEID, 5), NackInvalidPayloadLength, false},
		{"short diag", BuildHeader(0x02, DiagnosticMessage, 4), NackInvalidPayloadLength, false},
	}
	for _, c := range cases {
		h, err := ParseHeader(c.header)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		code, ok := h.Validate(0x02, handled, 4096)
		if ok != c.ok || (!ok && code != c.code) {
			t.Errorf("%s: got (0x%02X, %v), want (0x%02X, %v)", c.name, code, ok, c.code, c.ok)
		}
	}
}

func TestParseHeaderTooShort(t *testing.T) {
	if _, err := ParseHeader([]byte{0x02}); err == nil {
		t.Error("expected error")
	}
}

func TestBuildGenericNack(t *testing.T) {
	want := []byte{0x02, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, NackUnknownPayloadType}
	if got := BuildGenericNack(0x02, NackUnknownPayloadType); !bytes.Equal(got, want) {
		t.Errorf("got % X, want % X", got, want)
	}
}

// --- vehicle identification ---

func TestVehicleIdentMatches(t *testing.T) {
	p := AnnouncePayload{VIN: "WBA12345678901234", EID: [6]byte{1, 2, 3, 4, 5, 6}}
	cases := []struct {
		name    string
		typ     uint16
		payload []byte
		want    bool
	}{
		{"generic", VehicleIdentRequest, nil, true},
		{"eid match", VehicleIdentRequestEID, []byte{1, 2, 3, 4, 5, 6}, true},
		{"eid mismatch", VehicleIdentRequestEID, []byte{1, 2, 3, 4, 5, 7}, false},
		{"vin match", VehicleIdentRequestVIN, []byte("WBA12345678901234"), true},
		{"vin mismatch", VehicleIdentRequestVIN, []byte("WBA12345678901235"), false},
	}
	for _, c := range cases {
		got, err := VehicleIdentMatches(c.typ, c.payload, p)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v", c.name, got, err)
		}
	}
	if _, err := VehicleIdentMatches(VehicleIdentRequestEID, []byte{1}, p); err == nil {
		t.Error("short EID: expected error")
	}
	if _, err := VehicleIdentMatches(RoutingActivationReq, nil, p); err == nil {
		t.Error("wrong type: expected error")
	}
}

// --- routing activation with OEM data ---

func TestParseRoutingActivationRequestOEM(t *testing.T) {
	req, err := ParseRoutingActivationRequest([]byte{0x0E, 0x00, 0x00, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.OEMSpecific, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("OEM data: got % X", req.OEMSpecific)
	}
}

// --- status messages ---

func TestBuildEntityStatusResponse(t *testing.T) {
	got := BuildEntityStatusResponse(0x02, EntityStatus{NodeType: NodeTypeNode, MaxSockets: 15, OpenSockets: 2, MaxDataSize: 4096})
	want := append(BuildHeader(0x02, EntityStatusResp, 7), 0x01, 0x0F, 0x02, 0x00, 0x00, 0x10, 0x00)
	if !bytes.Equal(got, want) {
		t.Errorf("got % X, want % X", got, want)
	}
	got = BuildEntityStatusResponse(0x02, EntityStatus{NodeType: NodeTypeGateway, MaxSockets: 1})
	if len(got) != HeaderLength+3 {
		t.Errorf("without max data size: got % X", got)
	}
}

func TestBuildPowerModeAndAliveCheck(t *testing.T) {
	if got := BuildPowerModeResponse(0x02, PowerModeReady); !bytes.Equal(got, append(BuildHeader(0x02, DiagnosticPowerModeResp, 1), 0x01)) {
		t.Errorf("power mode: got % X", got)
	}
	if got := BuildAliveCheckResponse(0x02, 0x0E80); !bytes.Equal(got, append(BuildHeader(0x02, AliveCheckResp, 2), 0x0E, 0x80)) {
		t.Errorf("alive check response: got % X", got)
	}
	if got := BuildAliveCheckRequest(0x02); !bytes.Equal(got, BuildHeader(0x02, AliveCheckReq, 0)) {
		t.Errorf("alive check request: got % X", got)
	}
}
