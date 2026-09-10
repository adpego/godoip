package transport

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/adpego/godoip/internal/doip"
)

// udpHandled lists the payload types answered on UDP. Vehicle identification
// responses (announcements from other entities, or our own broadcasts) are
// accepted and ignored.
var udpHandled = map[uint16]bool{
	doip.VehicleIdentRequest:    true,
	doip.VehicleIdentRequestEID: true,
	doip.VehicleIdentRequestVIN: true,
	doip.VehicleIdentResponse:   true,
	doip.EntityStatusReq:        true,
	doip.DiagnosticPowerModeReq: true,
}

type UDPServer struct {
	port     int
	entity   *Entity
	announce AnnouncementConfig
}

func NewUDPServer(port int, entity *Entity, announce AnnouncementConfig) *UDPServer {
	return &UDPServer{port: port, entity: entity, announce: announce}
}

// Listen opens the UDP port and serves requests until an error occurs.
func (s *UDPServer) Listen() error {
	addr := fmt.Sprintf(":%d", s.port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("udp listen on %s: %w", addr, err)
	}
	defer conn.Close()
	log.Printf("UDP server listening on %s", addr)
	return s.Serve(conn)
}

// Serve sends the start-up announcements (if enabled) and answers requests
// received on conn until it is closed.
func (s *UDPServer) Serve(conn net.PacketConn) error {
	if s.announce.Enabled {
		go func() {
			if err := s.sendAnnouncements(conn); err != nil {
				log.Printf("announcement error: %v", err)
			}
		}()
	}

	buf := make([]byte, 4096)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		if resp := s.handlePacket(buf[:n]); resp != nil {
			if _, err := conn.WriteTo(resp, src); err != nil {
				log.Printf("UDP write to %s: %v", src, err)
			}
		}
	}
}

func (s *UDPServer) sendAnnouncements(conn net.PacketConn) error {
	dst, err := net.ResolveUDPAddr("udp", s.announce.Address)
	if err != nil {
		return err
	}
	msg := doip.BuildAnnouncement(s.entity.Announcement())

	time.Sleep(s.announce.InitialDelay)
	for i := range s.announce.Count {
		if _, err := conn.WriteTo(msg, dst); err != nil {
			return fmt.Errorf("announcement %d: %w", i+1, err)
		}
		log.Printf("Vehicle announcement %d/%d sent to %s", i+1, s.announce.Count, dst)
		if i < s.announce.Count-1 {
			time.Sleep(s.announce.Interval)
		}
	}
	return nil
}

// handlePacket returns the response to a datagram, or nil.
func (s *UDPServer) handlePacket(data []byte) []byte {
	version := s.entity.cfg.DoIPVersion
	hdr, err := doip.ParseHeader(data)
	if err != nil {
		return nil // too short to be DoIP: discard
	}
	if code, ok := hdr.Validate(version, udpHandled, s.entity.cfg.MaxDataSize); !ok {
		return doip.BuildGenericNack(version, code)
	}
	if uint32(len(data)-doip.HeaderLength) != hdr.PayloadLen {
		return doip.BuildGenericNack(version, doip.NackInvalidPayloadLength)
	}
	payload := data[doip.HeaderLength:]

	switch hdr.PayloadType {
	case doip.VehicleIdentRequest, doip.VehicleIdentRequestEID, doip.VehicleIdentRequestVIN:
		ann := s.entity.Announcement()
		if match, _ := doip.VehicleIdentMatches(hdr.PayloadType, payload, ann); match {
			return doip.BuildAnnouncement(ann)
		}
	case doip.EntityStatusReq:
		return doip.BuildEntityStatusResponse(version, s.entity.Status())
	case doip.DiagnosticPowerModeReq:
		return doip.BuildPowerModeResponse(version, s.entity.cfg.PowerMode)
	}
	return nil
}
