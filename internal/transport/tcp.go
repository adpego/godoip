package transport

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/adpego/godoip/internal/doip"
)

type TCPServer struct {
	port           int
	doipVersion    uint8
	gatewayAddr    uint16
}

func NewTCPServer(port int, doipVersion uint8, gatewayAddr uint16) *TCPServer {
	return &TCPServer{
		port:        port,
		doipVersion: doipVersion,
		gatewayAddr: gatewayAddr,
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
			s.handleRoutingActivation(conn, payload)
		default:
			log.Printf("TCP unhandled payload type: 0x%04X", hdr.PayloadType)
		}
	}
}

func (s *TCPServer) handleRoutingActivation(conn net.Conn, payload []byte) {
	req, err := doip.ParseRoutingActivationRequest(payload)
	if err != nil {
		log.Printf("routing activation parse error: %v", err)
		return
	}

	log.Printf("Routing activation request from 0x%04X, type 0x%02X", req.SourceAddress, req.ActivationType)

	resp := doip.BuildRoutingActivationResponse(s.doipVersion, req.SourceAddress, s.gatewayAddr, doip.ActivationSuccess)
	if _, err := conn.Write(resp); err != nil {
		log.Printf("routing activation response error: %v", err)
	}
}
