package transport

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/adpego/godoip/internal/doip"
)

const (
	broadcastAddr      = "255.255.255.255"
	announcementCount  = 3
	announcementDelay  = 500 * time.Millisecond
)

type UDPServer struct {
	port    int
	announce doip.AnnouncePayload
}

func NewUDPServer(port int, announce doip.AnnouncePayload) *UDPServer {
	return &UDPServer{port: port, announce: announce}
}

func (s *UDPServer) Listen() error {
	addr := fmt.Sprintf(":%d", s.port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("udp listen on %s: %w", addr, err)
	}
	defer conn.Close()

	log.Printf("UDP server listening on %s", addr)

	if err := s.sendAnnouncements(conn); err != nil {
		log.Printf("announcement error: %v", err)
	}

	buf := make([]byte, 4096)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}
		go s.handlePacket(conn, src, buf[:n])
	}
}

func (s *UDPServer) sendAnnouncements(conn net.PacketConn) error {
	dst, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", broadcastAddr, s.port))
	if err != nil {
		return err
	}

	msg := doip.BuildAnnouncement(s.announce)

	for i := range announcementCount {
		if _, err := conn.WriteTo(msg, dst); err != nil {
			return fmt.Errorf("announcement %d: %w", i+1, err)
		}
		log.Printf("Vehicle announcement %d/%d sent", i+1, announcementCount)
		if i < announcementCount-1 {
			time.Sleep(announcementDelay)
		}
	}
	return nil
}

func (s *UDPServer) handlePacket(conn net.PacketConn, src net.Addr, data []byte) {
	log.Printf("UDP packet from %s (%d bytes)", src, len(data))
}
