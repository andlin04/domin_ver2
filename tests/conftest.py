import pytest

from domin import scanner


@pytest.fixture(autouse=True)
def no_zone_transfer(monkeypatch):
    """Internal scans try AXFR against the configured DNS servers: no test may reach a real one. Their DNS pacing
    is lifted so a fake resolver answers at once (test_paced_resolver checks the pacing itself)."""
    monkeypatch.setattr(scanner, "from_axfr", lambda domain, servers: set())
    monkeypatch.setattr(scanner, "INTERNAL_QPS", 1e6)
