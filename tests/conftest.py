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


# Test data uses private and documentation addresses only (never someone's real host). The posture and fingerprint
# engines refuse every non-global address on a public install (domin.netscope), so the suite runs as an on-prem
# install whose scan networks are those ranges; tests of the address check itself set the mode they need.
TEST_SCAN_NETS = "10.0.0.0/8,172.16.0.0/12,192.0.2.0/24,198.51.100.0/24,203.0.113.0/24"


@pytest.fixture(scope="session")
def totp_key_file(tmp_path_factory):
    """A throwaway two-factor encryption key for the whole run (never /etc/domin/totp.key)."""
    from domin import secretbox
    path = tmp_path_factory.mktemp("totpkey") / "totp.key"
    secretbox.write_key(path, secretbox.new_key())
    return path


@pytest.fixture(autouse=True)
def totp_key(monkeypatch, totp_key_file):
    monkeypatch.setenv("DOMIN_TOTP_KEY", str(totp_key_file))
    return totp_key_file


@pytest.fixture(autouse=True)
def on_prem_test_networks(monkeypatch):
    monkeypatch.setenv("DOMIN_INSTALL_MODE", "internal")
    monkeypatch.setenv("DOMIN_SCAN_NETS", TEST_SCAN_NETS)
