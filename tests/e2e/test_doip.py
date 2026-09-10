import socket
import struct

from doipclient import DoIPClient
from doipclient.messages import (
    AliveCheckResponse,
    DiagnosticPowerModeResponse,
    EntityStatusResponse,
    VehicleIdentificationResponse,
)

from conftest import DOIP_VERSION, ECU_ADDRESS, TCP_PORT, UDP_PORT

EID = bytes.fromhex("001A2B3C4D5E")
VIN = "WBA12345678901234"


def test_vehicle_identification(doip):
    resp = doip.request_vehicle_identification()
    assert isinstance(resp, VehicleIdentificationResponse)
    assert resp.vin == VIN
    assert resp.logical_address == ECU_ADDRESS
    assert resp.eid == EID
    assert resp.gid == bytes.fromhex("001A2B3C4D5F")


def test_vehicle_identification_by_eid_and_vin(doip):
    assert doip.request_vehicle_identification(eid=EID).vin == VIN
    assert doip.request_vehicle_identification(vin=VIN).logical_address == ECU_ADDRESS


def test_entity_status(doip):
    resp = doip.request_entity_status()
    assert isinstance(resp, EntityStatusResponse)
    assert resp.node_type == 0x01
    assert resp.max_concurrent_sockets == 15
    assert resp.currently_open_sockets == 1  # this client
    assert resp.max_data_size == 4096


def test_power_mode(doip):
    resp = doip.request_diagnostic_power_mode()
    assert isinstance(resp, DiagnosticPowerModeResponse)
    assert resp.diagnostic_power_mode == 0x01


def test_alive_check(doip):
    resp = doip.request_alive_check()
    assert isinstance(resp, AliveCheckResponse)
    assert resp.source_address == ECU_ADDRESS


def _raw_tcp(port=TCP_PORT):
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    return s


def _header(payload_type, length, version=DOIP_VERSION):
    return struct.pack(">BBHI", version, version ^ 0xFF, payload_type, length)


def test_generic_nack_unknown_payload_type(server):
    with _raw_tcp() as s:
        s.sendall(_header(0x1234, 0))
        data = s.recv(64)
    assert data == _header(0x0000, 1) + b"\x01"


def test_generic_nack_incorrect_pattern_closes(server):
    with _raw_tcp() as s:
        s.sendall(bytes([0x02, 0x00, 0x00, 0x05, 0, 0, 0, 7]))
        assert s.recv(64) == _header(0x0000, 1) + b"\x00"
        assert s.recv(64) == b""  # closed


def test_routing_activation_denied_unknown_source(server):
    with _raw_tcp() as s:
        s.sendall(_header(0x0005, 7) + struct.pack(">HB4x", 0x0F00, 0x00))
        resp = s.recv(64)
    assert resp[8:12] == struct.pack(">HH", 0x0F00, ECU_ADDRESS)
    assert resp[12] == 0x00


def test_udp_generic_nack(server):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        s.sendto(_header(0x0005, 0), ("127.0.0.1", UDP_PORT))
        data, _ = s.recvfrom(64)
    assert data == _header(0x0000, 1) + b"\x01"


def test_announcement_on_startup(start_server):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    start_server({
        "  announcement:\n    enabled: false\n":
            f"  announcement:\n    count: 2\n    interval_ms: 50\n    address: 127.0.0.1\n    port: {port}\n",
    })
    announcements = []
    for _ in range(2):
        resp = DoIPClient.await_vehicle_announcement(sock=listener, timeout=3)
        announcements.append(resp)
    listener.close()
    _, ann = announcements[0]
    assert ann.vin == VIN and ann.logical_address == ECU_ADDRESS


def test_no_announcement_when_disabled(start_server):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(1)
    port = listener.getsockname()[1]
    start_server({
        "  announcement:\n    enabled: false\n":
            f"  announcement:\n    enabled: false\n    address: 127.0.0.1\n    port: {port}\n",
    })
    try:
        data = listener.recv(64)
    except socket.timeout:
        data = None
    listener.close()
    assert data is None
