package transport

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/adpego/godoip/internal/doip"
	"github.com/adpego/godoip/internal/uds"
)

// tcpHandled lists the payload types accepted on TCP.
var tcpHandled = map[uint16]bool{
	doip.RoutingActivationReq: true,
	doip.AliveCheckReq:        true,
	doip.AliveCheckResp:       true,
	doip.DiagnosticMessage:    true,
}

// TCPConfig holds the TCP-specific DoIP settings.
type TCPConfig struct {
	Port              int
	FunctionalAddress uint16 // UDS functional address
	ClientAddrMin     uint16
	ClientAddrMax     uint16
	ActivationTypes   []uint8       // supported routing activation types
	InitialInactivity time.Duration // max time before routing activation
	GeneralInactivity time.Duration // max idle time of an activated socket
}

type TCPServer struct {
	cfg    TCPConfig
	entity *Entity
	ecu    *uds.ECU

	mu             sync.Mutex
	activeSessions map[uint16]net.Conn // sourceAddr -> conn
}

func NewTCPServer(cfg TCPConfig, entity *Entity, ecu *uds.ECU) *TCPServer {
	if cfg.ActivationTypes == nil {
		cfg.ActivationTypes = []uint8{0x00, 0x01}
	}
	if cfg.InitialInactivity <= 0 {
		cfg.InitialInactivity = 2 * time.Second
	}
	if cfg.GeneralInactivity <= 0 {
		cfg.GeneralInactivity = 5 * time.Minute
	}
	return &TCPServer{
		cfg:            cfg,
		entity:         entity,
		ecu:            ecu,
		activeSessions: make(map[uint16]net.Conn),
	}
}

func (s *TCPServer) Listen() error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp listen on %s: %w", addr, err)
	}
	defer ln.Close()
	log.Printf("TCP server listening on %s", addr)
	return s.Serve(ln)
}

// Serve accepts connections on ln until it is closed.
func (s *TCPServer) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Printf("TCP accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// connState is the state of one TCP connection.
type connState struct {
	conn      net.Conn
	addr      uint16 // registered source address
	activated bool

	wmu  sync.Mutex    // serializes writes (responses and unsolicited messages)
	done chan struct{} // closed when the connection ends
}

func (c *connState) write(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.conn.Write(b)
	return err
}

// client is the uds.Client of an activated connection: unsolicited UDS
// messages are sent as diagnostic messages from the ECU to the tester.
type client struct {
	c       *connState
	version uint8
	ecuAddr uint16
	tester  uint16
}

func (cl client) Send(data []byte) error {
	select {
	case <-cl.c.done:
		return net.ErrClosed
	default:
	}
	return cl.c.write(doip.BuildDiagnosticMsg(cl.version, cl.ecuAddr, cl.tester, data))
}

func (cl client) Done() <-chan struct{} { return cl.c.done }

func (s *TCPServer) version() uint8 { return s.entity.cfg.DoIPVersion }

func (s *TCPServer) handleConn(conn net.Conn) {
	s.entity.openSockets.Add(1)
	defer s.entity.openSockets.Add(-1)
	defer conn.Close()
	log.Printf("TCP connection from %s", conn.RemoteAddr())

	c := &connState{conn: conn, done: make(chan struct{})}
	defer close(c.done)
	defer func() {
		if c.activated {
			s.mu.Lock()
			delete(s.activeSessions, c.addr)
			s.mu.Unlock()
			log.Printf("Session 0x%04X unregistered", c.addr)
		}
	}()

	for {
		timeout := s.cfg.InitialInactivity
		if c.activated {
			timeout = s.cfg.GeneralInactivity
		}
		conn.SetReadDeadline(time.Now().Add(timeout))

		hdr, err := doip.ReadHeader(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("TCP header read error: %v", err)
			}
			return
		}

		if code, ok := hdr.Validate(s.version(), tcpHandled, s.entity.cfg.MaxDataSize); !ok {
			log.Printf("TCP generic NACK 0x%02X for header %+v", code, hdr)
			c.write(doip.BuildGenericNack(s.version(), code))
			if code == doip.NackIncorrectPattern || code == doip.NackInvalidPayloadLength {
				return
			}
			// Discard the payload and wait for the next message.
			if _, err := io.CopyN(io.Discard, conn, int64(hdr.PayloadLen)); err != nil {
				return
			}
			continue
		}

		payload := make([]byte, hdr.PayloadLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			log.Printf("TCP payload read error: %v", err)
			return
		}

		if !s.handleMessage(c, hdr.PayloadType, payload) {
			return
		}
	}
}

// handleMessage processes a validated message and reports whether the
// connection must be kept open.
func (s *TCPServer) handleMessage(c *connState, payloadType uint16, payload []byte) bool {
	switch payloadType {
	case doip.RoutingActivationReq:
		return s.handleRoutingActivation(c, payload)

	case doip.AliveCheckReq:
		return c.write(doip.BuildAliveCheckResponse(s.version(), s.entity.cfg.LogicalAddress)) == nil

	case doip.AliveCheckResp:
		return true // only meaningful as an answer to our own alive checks

	case doip.DiagnosticMessage:
		return s.handleDiagnosticMessage(c, payload)
	}
	return true
}

func (s *TCPServer) handleDiagnosticMessage(c *connState, payload []byte) bool {
	msg, err := doip.ParseDiagnosticMessage(payload)
	if err != nil {
		log.Printf("diagnostic message parse error: %v", err)
		return false
	}
	log.Printf("Diagnostic message: src=0x%04X target=0x%04X uds=% X", msg.SourceAddress, msg.TargetAddress, msg.UserData)

	nack := func(code uint8) {
		c.write(doip.BuildDiagnosticNack(s.version(), msg.TargetAddress, msg.SourceAddress, code))
	}

	// Source address must be activated on this socket; otherwise close it.
	if !c.activated || msg.SourceAddress != c.addr {
		nack(doip.DiagNackInvalidSourceAddress)
		return false
	}

	// Target must be the ECU itself or the functional address.
	functional := msg.TargetAddress == s.cfg.FunctionalAddress
	if msg.TargetAddress != s.entity.cfg.LogicalAddress && !functional {
		nack(doip.DiagNackUnknownTargetAddress)
		return true
	}

	ack := doip.BuildDiagnosticAck(s.version(), msg.TargetAddress, msg.SourceAddress)
	if err := c.write(ack); err != nil {
		log.Printf("diagnostic ack write error: %v", err)
		return false
	}

	// Responses always come from the ECU physical address, even for
	// functional requests.
	cl := client{c: c, version: s.version(), ecuAddr: s.entity.cfg.LogicalAddress, tester: msg.SourceAddress}
	for _, m := range s.ecu.Process(cl, msg.UserData, functional) {
		time.Sleep(m.Delay)
		if err := cl.Send(m.Data); err != nil {
			log.Printf("diagnostic response write error: %v", err)
			return false
		}
	}
	return true
}

func (s *TCPServer) handleRoutingActivation(c *connState, payload []byte) bool {
	req, err := doip.ParseRoutingActivationRequest(payload)
	if err != nil {
		log.Printf("routing activation parse error: %v", err)
		return false
	}
	log.Printf("Routing activation request from 0x%04X, type 0x%02X", req.SourceAddress, req.ActivationType)

	code := s.activate(c, req)
	resp := doip.BuildRoutingActivationResponse(s.version(), req.SourceAddress, s.entity.cfg.LogicalAddress, code)
	if err := c.write(resp); err != nil {
		log.Printf("routing activation response write error: %v", err)
		return false
	}
	if code != doip.ActivationSuccess {
		log.Printf("Routing activation denied (0x%02X) for 0x%04X", code, req.SourceAddress)
		return false
	}
	log.Printf("Routing activation successful for 0x%04X", req.SourceAddress)
	return true
}

// activate validates a routing activation and registers the source address.
func (s *TCPServer) activate(c *connState, req doip.RoutingActivationRequest) uint8 {
	if !slices.Contains(s.cfg.ActivationTypes, req.ActivationType) {
		return doip.ActivationDeniedUnsupportedType
	}
	if req.SourceAddress < s.cfg.ClientAddrMin || req.SourceAddress > s.cfg.ClientAddrMax {
		return doip.ActivationDeniedUnknownSrc
	}
	if c.activated {
		if c.addr != req.SourceAddress {
			return doip.ActivationDeniedSAMismatch
		}
		return doip.ActivationSuccess // already active on this socket
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.activeSessions[req.SourceAddress]; ok {
		return doip.ActivationDeniedSAAlreadyActive
	}
	if len(s.activeSessions) >= s.entity.cfg.MaxSockets {
		return doip.ActivationDeniedNoFreeSockets
	}
	s.activeSessions[req.SourceAddress] = c.conn
	c.addr, c.activated = req.SourceAddress, true
	return doip.ActivationSuccess
}
