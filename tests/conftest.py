import pytest

from domin import proxy, scanner


@pytest.fixture(autouse=True)
def no_zone_transfer(monkeypatch):
    """Internal scans try AXFR against the configured DNS servers: no test may reach a real one. Their DNS pacing
    is lifted so a fake resolver answers at once (test_paced_resolver checks the pacing itself)."""
    monkeypatch.setattr(scanner, "from_axfr", lambda domain, servers: set())
    monkeypatch.setattr(scanner, "INTERNAL_QPS", 1e6)


@pytest.fixture(autouse=True)
def no_proxy_connect(monkeypatch):
    """Proxy handshakes and the Mullvad tunnel check connect with socket.create_connection: no test reaches a real
    proxy (tests that check a handshake put a fake socket in its place)."""
    def refused(addr, timeout=None, *a, **k):
        raise ConnectionRefusedError(111, "Connection refused (tests)")
    monkeypatch.setattr(proxy.socket, "create_connection", refused)
    proxy._probes.clear()   # cached probe results must not leak from one test into the next
