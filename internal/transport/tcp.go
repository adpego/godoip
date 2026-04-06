package transport

import (
	"fmt"
	"log"
	"net"
)

type TCPServer struct {
	port int
}

func NewTCPServer(port int) *TCPServer {
	return &TCPServer{port: port}
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
}
