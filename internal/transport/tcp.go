package transport

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/adpego/godoip/internal/doip"
)

const maxSessions = 15 // ISO 13400 allows up to 15 concurrent TCP connections

type TCPServer struct {
	port           int
	doipVersion    uint8
	gatewayAddr    uint16
	clientAddrMin  uint16
	clientAddrMax  uint16

	mu             sync.Mutex
	activeSessions map[uint16]net.Conn // sourceAddr -> conn
}

func NewTCPServer(port int, doipVersion uint8, gatewayAddr, clientAddrMin, clientAddrMax uint16) *TCPServer {
	return &TCPServer{
		port:           port,
		doipVersion:    doipVersion,
		gatewayAddr:    gatewayAddr,
		clientAddrMin:  clientAddrMin,
		clientAddrMax:  clientAddrMax,
		activeSessions: make(map[uint16]net.Conn),
	}
}

func (s *TCPServer) Listen() error {
	addr := fmt.Sprintf(":%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp listen on %s: %w", addr, err)
	}
	defer ln.Close()

	log.Printf("TCP server listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("TCP accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *TCPServer) handleConn(conn net.Conn) {
	defer conn.Close()
	log.Printf("TCP connection from %s", conn.RemoteAddr())

	var registeredAddr uint16
	var activated bool

	defer func() {
		if activated {
			s.mu.Lock()
			delete(s.activeSessions, registeredAddr)
			s.mu.Unlock()
			log.Printf("Session 0x%04X unregistered", registeredAddr)
		}
	}()

	for {
		hdr, err := doip.ReadHeader(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("TCP header read error: %v", err)
			}
			return
		}

		payload := make([]byte, hdr.PayloadLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			log.Printf("TCP payload read error: %v", err)
			return
		}

		switch hdr.PayloadType {
		case doip.RoutingActivationReq:
			addr, ok := s.handleRoutingActivation(conn, payload, registeredAddr, activated)
			if !ok {
				return // connection must be closed after denial
			}
			registeredAddr = addr
			activated = true
		default:
			log.Printf("TCP unhandled payload type: 0x%04X", hdr.PayloadType)
		}
	}
}

// handleRoutingActivation processes the request and returns (sourceAddr, keep connection).
func (s *TCPServer) handleRoutingActivation(conn net.Conn, payload []byte, currentAddr uint16, alreadyActivated bool) (uint16, bool) {
	req, err := doip.ParseRoutingActivationRequest(payload)
	if err != nil {
		log.Printf("routing activation parse error: %v", err)
		return 0, false
	}

	log.Printf("Routing activation request from 0x%04X, type 0x%02X", req.SourceAddress, req.ActivationType)

	code := s.validateActivation(conn, req, currentAddr, alreadyActivated)
	resp := doip.BuildRoutingActivationResponse(s.doipVersion, req.SourceAddress, s.gatewayAddr, code)

	if _, err := conn.Write(resp); err != nil {
		log.Printf("routing activation response write error: %v", err)
		return 0, false
	}

	if code != doip.ActivationSuccess {
		log.Printf("Routing activation denied (0x%02X) for 0x%04X", code, req.SourceAddress)
		return 0, false
	}

	s.mu.Lock()
	s.activeSessions[req.SourceAddress] = conn
	s.mu.Unlock()

	log.Printf("Routing activation successful for 0x%04X", req.SourceAddress)
	return req.SourceAddress, true
}

func (s *TCPServer) validateActivation(conn net.Conn, req doip.RoutingActivationRequest, currentAddr uint16, alreadyActivated bool) uint8 {
	// Unsupported activation type (only 0x00 Default and 0x01 WWH-OBD are defined)
	if req.ActivationType > 0x01 {
		return doip.ActivationDeniedUnsupportedType
	}

	// Source address out of allowed range
	if req.SourceAddress < s.clientAddrMin || req.SourceAddress > s.clientAddrMax {
		return doip.ActivationDeniedUnknownSrc
	}

	// This socket is already activated with a different source address
	if alreadyActivated && currentAddr != req.SourceAddress {
		return doip.ActivationDeniedSAMismatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Source address already active on a different socket
	if existing, ok := s.activeSessions[req.SourceAddress]; ok && existing != conn {
		return doip.ActivationDeniedSAAlreadyActive
	}

	// No free sockets
	if len(s.activeSessions) >= maxSessions {
		return doip.ActivationDeniedNoFreeSockets
	}

	return doip.ActivationSuccess
}
