import pytest

from domin import scanner


@pytest.fixture(autouse=True)
def no_zone_transfer(monkeypatch):
    """Internal scans try AXFR against the configured DNS servers: no test may reach a real one."""
    monkeypatch.setattr(scanner, "from_axfr", lambda domain, servers: set())
