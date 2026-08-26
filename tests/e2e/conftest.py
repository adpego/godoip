"""End-to-end test fixtures: build the Go server, start a fresh instance per
test and connect to it with doipclient.

Set GODOIP_HOST to test an already running server instead (state is then
shared between tests, so some tests may fail).
"""

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import udsoncan
from doipclient import DoIPClient
from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client

REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_DIR = Path(__file__).resolve().parent
# Files copied to the per-test working directory of the server.
SERVER_FILES = ["config.yaml", "firmware.s19"]

TCP_PORT = 13410
ECU_ADDRESS = 0x0E80
CLIENT_ADDRESS = 0x0E00
FUNCTIONAL_ADDRESS = 0xE400
DOIP_VERSION = 2


@pytest.fixture(scope="session")
def server_binary(tmp_path_factory):
    binary = tmp_path_factory.mktemp("bin") / "godoip"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/server"], cwd=REPO_ROOT, check=True)
    return binary


def _wait_for_port(host, port, proc, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"server exited with code {proc.returncode}")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"server did not open {host}:{port}")


@pytest.fixture
def server(server_binary, tmp_path):
    """A fresh server per test, so every test starts from the initial state."""
    host = os.environ.get("GODOIP_HOST")
    if host:
        yield host
        return

    for name in SERVER_FILES:
        shutil.copy(E2E_DIR / name, tmp_path / name)
    log = open(tmp_path / "server.log", "w")
    proc = subprocess.Popen(
        [str(server_binary), "-config", str(tmp_path / "config.yaml")],
        cwd=tmp_path, stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_port("127.0.0.1", TCP_PORT, proc)
        yield "127.0.0.1"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        log.close()


@pytest.fixture
def workdir(server, tmp_path):
    """Directory holding the server configuration and memory files."""
    return tmp_path


@pytest.fixture
def doip(server):
    client = DoIPClient(
        server, ECU_ADDRESS,
        tcp_port=TCP_PORT,
        protocol_version=DOIP_VERSION,
        client_logical_address=CLIENT_ADDRESS,
    )
    yield client
    client.close()


class RawUDS:
    """Sends raw UDS requests and returns raw responses (or None)."""

    def __init__(self, doip):
        self.doip = doip

    def __call__(self, request, timeout=1.0):
        self.doip.send_diagnostic(bytes(request))
        try:
            return bytes(self.doip.receive_diagnostic(timeout=timeout))
        except TimeoutError:
            return None

    def functional(self, request, timeout=1.0):
        self.doip.send_diagnostic_to_address(FUNCTIONAL_ADDRESS, bytes(request))
        try:
            return bytes(self.doip.receive_diagnostic(timeout=timeout))
        except TimeoutError:
            return None


@pytest.fixture
def uds(doip):
    return RawUDS(doip)


def xor_key(level, seed, params=None):
    return bytes(s ^ m for s, m in zip(seed, bytes.fromhex("AABBCCDD")))


@pytest.fixture
def client(doip):
    """A udsoncan client, which strictly validates responses."""
    config = dict(udsoncan.configs.default_client_config)
    config["security_algo"] = xor_key
    config["data_identifiers"] = {
        0xF190: udsoncan.AsciiCodec(17),
        0xF189: "BBB",
        0x0100: ">H",
        0x0101: udsoncan.AsciiCodec(6),
    }
    config["request_timeout"] = 2
    with Client(DoIPClientUDSConnector(doip), config=config) as c:
        yield c


def nrc(sid, code):
    return bytes([0x7F, sid, code])
