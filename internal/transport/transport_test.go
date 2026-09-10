package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/adpego/godoip/internal/config"
	"github.com/adpego/godoip/internal/doip"
	"github.com/adpego/godoip/internal/uds/services"
)

const (
	version    = 0x02
	ecuAddr    = 0x0E80
	clientAddr = 0x0E00
	funcAddr   = 0xE400
)

func testEntity() *Entity {
	sync := uint8(0x00)
	return NewEntity(EntityConfig{
		DoIPVersion:    version,
		LogicalAddress: ecuAddr,
		VIN:            "WBA12345678901234",
		EID:            [6]byte{1, 2, 3, 4, 5, 6},
		GID:            [6]byte{1, 2, 3, 4, 5, 7},
		SyncStatus:     &sync,
		NodeType:       doip.NodeTypeNode,
		MaxSockets:     2,
		MaxDataSize:    64,
		PowerMode:      doip.PowerModeReady,
	})
}

// --- TCP ---

func newTCPServer(t *testing.T, entity *Entity) *TCPServer {
	t.Helper()
	ecu, err := services.New(config.ECU{Services: config.Services{TesterPresent: &config.Service{}}})
	if err != nil {
		t.Fatal(err)
	}
	return NewTCPServer(TCPConfig{
		FunctionalAddress: funcAddr,
		ClientAddrMin:     0x0E00,
		ClientAddrMax:     0x0E0F,
		InitialInactivity: 200 * time.Millisecond,
	}, entity, ecu)
}

// dial connects a client to the server over loopback TCP, starting the
// server listener on first use.
func dial(t *testing.T, s *TCPServer) net.Conn {
	t.Helper()
	addr, ok := listeners[s]
	if !ok {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go s.Serve(ln)
		t.Cleanup(func() { ln.Close(); delete(listeners, s) })
		addr = ln.Addr().String()
		listeners[s] = addr
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

var listeners = map[*TCPServer]string{}

func send(t *testing.T, c net.Conn, payloadType uint16, payload []byte) {
	t.Helper()
	msg := append(doip.BuildHeader(version, payloadType, uint32(len(payload))), payload...)
	c.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// expect reads one DoIP message and checks it byte for byte.
func expect(t *testing.T, c net.Conn, want []byte) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(time.Second))
	hdr, err := doip.ReadHeader(c)
	if err != nil {
		t.Fatalf("read header: %v (want % X)", err, want)
	}
	payload := make([]byte, hdr.PayloadLen)
	if _, err := io.ReadFull(c, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	got := append(doip.BuildHeader(hdr.Version, hdr.PayloadType, hdr.PayloadLen), payload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("got % X, want % X", got, want)
	}
}

// expectClosed checks that the server closed the connection.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(time.Second))
	// EOF, or a reset when the server closed with unread data.
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("expected the server to close the connection, got %v", err)
	}
}

func activation(addr uint16, activationType uint8) []byte {
	p := make([]byte, 7)
	binary.BigEndian.PutUint16(p, addr)
	p[2] = activationType
	return p
}

func activate(t *testing.T, c net.Conn, addr uint16) {
	t.Helper()
	send(t, c, doip.RoutingActivationReq, activation(addr, 0x00))
	expect(t, c, doip.BuildRoutingActivationResponse(version, addr, ecuAddr, doip.ActivationSuccess))
}

func diag(src, target uint16, uds ...byte) []byte {
	p := binary.BigEndian.AppendUint16(nil, src)
	p = binary.BigEndian.AppendUint16(p, target)
	return append(p, uds...)
}

func TestRoutingActivationAndDiagnostic(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	activate(t, c, clientAddr)

	send(t, c, doip.DiagnosticMessage, diag(clientAddr, ecuAddr, 0x3E, 0x00))
	expect(t, c, doip.BuildDiagnosticAck(version, ecuAddr, clientAddr))
	expect(t, c, doip.BuildDiagnosticMsg(version, ecuAddr, clientAddr, []byte{0x7E, 0x00}))

	// Re-activating the same address on the same socket is accepted.
	activate(t, c, clientAddr)
}

func TestFunctionalDiagnostic(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	activate(t, c, clientAddr)
	send(t, c, doip.DiagnosticMessage, diag(clientAddr, funcAddr, 0x3E, 0x00))
	expect(t, c, doip.BuildDiagnosticAck(version, funcAddr, clientAddr))
	expect(t, c, doip.BuildDiagnosticMsg(version, ecuAddr, clientAddr, []byte{0x7E, 0x00}))

	// Suppressed response: only the ACK is sent.
	send(t, c, doip.DiagnosticMessage, diag(clientAddr, funcAddr, 0x3E, 0x80))
	expect(t, c, doip.BuildDiagnosticAck(version, funcAddr, clientAddr))
	send(t, c, doip.AliveCheckReq, nil)
	expect(t, c, doip.BuildAliveCheckResponse(version, ecuAddr))
}

func TestRoutingActivationDenied(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		code    uint8
	}{
		{"unknown source", activation(0x0F00, 0x00), doip.ActivationDeniedUnknownSrc},
		{"unsupported type", activation(clientAddr, 0xE0), doip.ActivationDeniedUnsupportedType},
	}
	for _, tc := range cases {
		c := dial(t, newTCPServer(t, testEntity()))
		send(t, c, doip.RoutingActivationReq, tc.payload)
		addr := binary.BigEndian.Uint16(tc.payload)
		expect(t, c, doip.BuildRoutingActivationResponse(version, addr, ecuAddr, tc.code))
		expectClosed(t, c)
	}
}

func TestRoutingActivationSAMismatch(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	activate(t, c, clientAddr)
	send(t, c, doip.RoutingActivationReq, activation(clientAddr+1, 0x00))
	expect(t, c, doip.BuildRoutingActivationResponse(version, clientAddr+1, ecuAddr, doip.ActivationDeniedSAMismatch))
	expectClosed(t, c)
}

func TestRoutingActivationAlreadyActiveAndNoFreeSockets(t *testing.T) {
	s := newTCPServer(t, testEntity()) // max 2 sockets
	c1 := dial(t, s)
	activate(t, c1, clientAddr)

	c2 := dial(t, s)
	send(t, c2, doip.RoutingActivationReq, activation(clientAddr, 0x00))
	expect(t, c2, doip.BuildRoutingActivationResponse(version, clientAddr, ecuAddr, doip.ActivationDeniedSAAlreadyActive))
	expectClosed(t, c2)

	c3 := dial(t, s)
	activate(t, c3, clientAddr+1)
	c4 := dial(t, s)
	send(t, c4, doip.RoutingActivationReq, activation(clientAddr+2, 0x00))
	expect(t, c4, doip.BuildRoutingActivationResponse(version, clientAddr+2, ecuAddr, doip.ActivationDeniedNoFreeSockets))
	expectClosed(t, c4)

	// Closing a socket frees its address.
	c1.Close()
	time.Sleep(50 * time.Millisecond)
	c5 := dial(t, s)
	activate(t, c5, clientAddr)
}

func TestDiagnosticBeforeActivationClosesSocket(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	send(t, c, doip.DiagnosticMessage, diag(clientAddr, ecuAddr, 0x3E, 0x00))
	expect(t, c, doip.BuildDiagnosticNack(version, ecuAddr, clientAddr, doip.DiagNackInvalidSourceAddress))
	expectClosed(t, c)
}

func TestDiagnosticWrongSourceClosesSocket(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	activate(t, c, clientAddr)
	send(t, c, doip.DiagnosticMessage, diag(clientAddr+1, ecuAddr, 0x3E, 0x00))
	expect(t, c, doip.BuildDiagnosticNack(version, ecuAddr, clientAddr+1, doip.DiagNackInvalidSourceAddress))
	expectClosed(t, c)
}

func TestDiagnosticUnknownTarget(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	activate(t, c, clientAddr)
	send(t, c, doip.DiagnosticMessage, diag(clientAddr, 0x1234, 0x3E, 0x00))
	expect(t, c, doip.BuildDiagnosticNack(version, 0x1234, clientAddr, doip.DiagNackUnknownTargetAddress))
	// The socket stays open.
	send(t, c, doip.AliveCheckReq, nil)
	expect(t, c, doip.BuildAliveCheckResponse(version, ecuAddr))
}

func TestGenericNackKeepsSocket(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	activate(t, c, clientAddr)

	send(t, c, 0x1234, []byte{1, 2, 3})
	expect(t, c, doip.BuildGenericNack(version, doip.NackUnknownPayloadType))

	send(t, c, doip.DiagnosticMessage, diag(clientAddr, ecuAddr, make([]byte, 100)...))
	expect(t, c, doip.BuildGenericNack(version, doip.NackMessageTooLarge))

	// The discarded payloads do not corrupt the stream.
	send(t, c, doip.AliveCheckReq, nil)
	expect(t, c, doip.BuildAliveCheckResponse(version, ecuAddr))
}

func TestGenericNackClosesSocket(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	send(t, c, doip.RoutingActivationReq, []byte{0x0E, 0x00, 0x00})
	expect(t, c, doip.BuildGenericNack(version, doip.NackInvalidPayloadLength))
	expectClosed(t, c)

	c = dial(t, newTCPServer(t, testEntity()))
	c.Write([]byte{0x02, 0x00, 0x00, 0x05, 0, 0, 0, 7})
	expect(t, c, doip.BuildGenericNack(version, doip.NackIncorrectPattern))
	expectClosed(t, c)
}

func TestInitialInactivityClosesSocket(t *testing.T) {
	c := dial(t, newTCPServer(t, testEntity()))
	time.Sleep(300 * time.Millisecond)
	expectClosed(t, c)
}

func TestOpenSocketsCount(t *testing.T) {
	entity := testEntity()
	s := newTCPServer(t, entity)
	c := dial(t, s)
	activate(t, c, clientAddr)
	if n := entity.Status().OpenSockets; n != 1 {
		t.Errorf("open sockets: got %d, want 1", n)
	}
	c.Close()
	time.Sleep(50 * time.Millisecond)
	if n := entity.Status().OpenSockets; n != 0 {
		t.Errorf("open sockets after close: got %d, want 0", n)
	}
}

func TestTCPServeAndClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := newTCPServer(t, testEntity())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	activate(t, c, clientAddr)

	ln.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve: got %v", err)
	}
}

// --- UDP ---

type udpTest struct {
	client net.PacketConn
	server net.Addr
}

func startUDP(t *testing.T, entity *Entity, announce AnnouncementConfig) *udpTest {
	t.Helper()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if announce.Address == "" {
		announce.Address = client.LocalAddr().String()
	}
	go NewUDPServer(0, entity, announce).Serve(serverConn)
	t.Cleanup(func() { client.Close(); serverConn.Close() })
	return &udpTest{client: client, server: serverConn.LocalAddr()}
}

func (u *udpTest) request(t *testing.T, msg []byte) []byte {
	t.Helper()
	if _, err := u.client.WriteTo(msg, u.server); err != nil {
		t.Fatal(err)
	}
	return u.receive(t, 300*time.Millisecond)
}

func (u *udpTest) receive(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	buf := make([]byte, 1024)
	u.client.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := u.client.ReadFrom(buf)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		t.Fatal(err)
	}
	return buf[:n]
}

func udpMsg(v uint8, payloadType uint16, payload []byte) []byte {
	return append(doip.BuildHeader(v, payloadType, uint32(len(payload))), payload...)
}

func TestVehicleIdentification(t *testing.T) {
	entity := testEntity()
	u := startUDP(t, entity, AnnouncementConfig{})
	want := doip.BuildAnnouncement(entity.Announcement())

	cases := []struct {
		name string
		msg  []byte
		want []byte
	}{
		{"generic", udpMsg(version, doip.VehicleIdentRequest, nil), want},
		{"default version", udpMsg(0xFF, doip.VehicleIdentRequest, nil), want},
		{"eid match", udpMsg(version, doip.VehicleIdentRequestEID, []byte{1, 2, 3, 4, 5, 6}), want},
		{"eid mismatch", udpMsg(version, doip.VehicleIdentRequestEID, []byte{9, 9, 9, 9, 9, 9}), nil},
		{"vin match", udpMsg(version, doip.VehicleIdentRequestVIN, []byte("WBA12345678901234")), want},
		{"vin mismatch", udpMsg(version, doip.VehicleIdentRequestVIN, []byte("XXXXXXXXXXXXXXXXX")), nil},
	}
	for _, c := range cases {
		if got := u.request(t, c.msg); !bytes.Equal(got, c.want) {
			t.Errorf("%s: got % X, want % X", c.name, got, c.want)
		}
	}
}

func TestEntityStatusAndPowerMode(t *testing.T) {
	u := startUDP(t, testEntity(), AnnouncementConfig{})
	got := u.request(t, udpMsg(version, doip.EntityStatusReq, nil))
	want := doip.BuildEntityStatusResponse(version, doip.EntityStatus{NodeType: doip.NodeTypeNode, MaxSockets: 2, MaxDataSize: 64})
	if !bytes.Equal(got, want) {
		t.Errorf("entity status: got % X, want % X", got, want)
	}
	got = u.request(t, udpMsg(version, doip.DiagnosticPowerModeReq, nil))
	if !bytes.Equal(got, doip.BuildPowerModeResponse(version, doip.PowerModeReady)) {
		t.Errorf("power mode: got % X", got)
	}
}

func TestUDPGenericNack(t *testing.T) {
	u := startUDP(t, testEntity(), AnnouncementConfig{})
	cases := []struct {
		name string
		msg  []byte
		code uint8
	}{
		{"bad pattern", []byte{0x02, 0x00, 0x00, 0x01, 0, 0, 0, 0}, doip.NackIncorrectPattern},
		{"unknown type", udpMsg(version, doip.RoutingActivationReq, make([]byte, 7)), doip.NackUnknownPayloadType},
		{"bad length", udpMsg(version, doip.VehicleIdentRequestEID, []byte{1}), doip.NackInvalidPayloadLength},
		{"length mismatch", append(doip.BuildHeader(version, doip.VehicleIdentRequest, 0), 0x00), doip.NackInvalidPayloadLength},
	}
	for _, c := range cases {
		if got := u.request(t, c.msg); !bytes.Equal(got, doip.BuildGenericNack(version, c.code)) {
			t.Errorf("%s: got % X", c.name, got)
		}
	}
	// Announcements from other entities and garbage are ignored.
	if got := u.request(t, doip.BuildAnnouncement(doip.AnnouncePayload{Version: version})); got != nil {
		t.Errorf("announcement: got % X, want no response", got)
	}
	if got := u.request(t, []byte{0x01, 0x02}); got != nil {
		t.Errorf("garbage: got % X, want no response", got)
	}
}

func TestAnnouncements(t *testing.T) {
	entity := testEntity()
	u := startUDP(t, entity, AnnouncementConfig{Enabled: true, Count: 2, Interval: 20 * time.Millisecond})
	want := doip.BuildAnnouncement(entity.Announcement())
	for i := 0; i < 2; i++ {
		if got := u.receive(t, time.Second); !bytes.Equal(got, want) {
			t.Fatalf("announcement %d: got % X, want % X", i+1, got, want)
		}
	}
	if got := u.receive(t, 100*time.Millisecond); got != nil {
		t.Errorf("unexpected extra announcement: % X", got)
	}
}

func TestAnnouncementsDisabled(t *testing.T) {
	u := startUDP(t, testEntity(), AnnouncementConfig{Enabled: false, Count: 3})
	if got := u.receive(t, 200*time.Millisecond); got != nil {
		t.Errorf("got % X, want no announcement", got)
	}
}
