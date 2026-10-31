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

TCP_PORT = 13400  # standard DoIP ports
UDP_PORT = 13400
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


def _ensure_port_free(port):
    """Fails if a server already listens on the port: the tests would
    otherwise talk to it instead of the one they start."""
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
    except OSError:
        return
    raise RuntimeError(f"port {port} is already in use: stop the running DoIP server "
                       "(or set GODOIP_HOST to test it)")


class ServerProcess:
    """Runs the server binary in a working directory with a copy of the e2e
    configuration, optionally edited with text replacements."""

    def __init__(self, binary, workdir, replacements=None, tcp_port=TCP_PORT):
        for name in SERVER_FILES:
            shutil.copy(E2E_DIR / name, workdir / name)
        shutil.copytree(E2E_DIR / "files", workdir / "files")
        shutil.copytree(E2E_DIR / "pki", workdir / "pki")
        config = workdir / "config.yaml"
        text = config.read_text()
        for old, new in (replacements or {}).items():
            assert old in text, f"{old!r} not found in config.yaml"
            text = text.replace(old, new)
        config.write_text(text)

        _ensure_port_free(tcp_port)
        self.log = open(workdir / "server.log", "w")
        self.proc = subprocess.Popen(
            [str(binary), "-config", str(config)],
            cwd=workdir, stdout=self.log, stderr=subprocess.STDOUT,
        )
        self.tcp_port = tcp_port

    def wait_ready(self):
        _wait_for_port("127.0.0.1", self.tcp_port, self.proc)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.log.close()


@pytest.fixture
def start_server(server_binary, tmp_path):
    """Factory starting a server with a customized configuration."""
    started = []

    def start(replacements=None, tcp_port=TCP_PORT, wait=True):
        srv = ServerProcess(server_binary, tmp_path, replacements, tcp_port)
        started.append(srv)
        if wait:
            srv.wait_ready()
        return srv

    yield start
    for srv in started:
        srv.stop()


@pytest.fixture
def server(start_server):
    """A fresh server per test, so every test starts from the initial state."""
    host = os.environ.get("GODOIP_HOST")
    if host:
        yield host
        return
    start_server()
    yield "127.0.0.1"


@pytest.fixture
def workdir(server, tmp_path):
    """Directory holding the server configuration and memory files."""
    return tmp_path


@pytest.fixture
def doip(server):
    client = DoIPClient(
        server, ECU_ADDRESS,
        tcp_port=TCP_PORT,
        udp_port=UDP_PORT,
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

    def receive(self, timeout=1.0):
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
    config["input_output"] = {0x0500: "B"}
    config["request_timeout"] = 2
    with Client(DoIPClientUDSConnector(doip), config=config) as c:
        yield c


def nrc(sid, code):
    return bytes([0x7F, sid, code])
