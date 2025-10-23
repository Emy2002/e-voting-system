import pytest
from datetime import datetime, timedelta
import types

from backend.security.intrusion_detection import IntrusionDetection

class FrozenDateTime:
    """Helper to monkeypatch datetime.utcnow()"""
    def __init__(self, start):
        self._now = start

    def advance(self, **kwargs):
        self._now += timedelta(**kwargs)

    def utcnow(self):
        return self._now


@pytest.fixture
def start_time():
    return datetime(2025, 10, 23, 12, 0, 0)


@pytest.fixture
def frozen_datetime(monkeypatch, start_time):
    fd = FrozenDateTime(start_time)
    fake_dt = types.SimpleNamespace(utcnow=fd.utcnow)
    # Monkeypatch the datetime module in intrusion_detection to use our fake
    import backend.security.intrusion_detection as id_mod
    monkeypatch.setattr(id_mod, 'datetime', fake_dt)
    return fd


def test_record_and_blocking(frozen_datetime):
    id_system = IntrusionDetection(max_attempts=3, window_minutes=15)
    ip = '1.2.3.4'

    # record two failed attempts, should not be blocked yet
    d1 = id_system.record_failed_attempt(ip)
    d2 = id_system.record_failed_attempt(ip)
    # progressive delays should increase
    assert isinstance(d1, int) and d1 >= 1
    assert isinstance(d2, int) and d2 >= d1
    assert id_system.is_ip_throttled(ip) is True

    # third attempt within window -> locked out
    d3 = id_system.record_failed_attempt(ip)
    assert id_system.is_ip_blocked(ip) is True
    assert d3 > 0


def test_window_expiry_and_clear_old_records(frozen_datetime):
    id_system = IntrusionDetection(max_attempts=3, window_minutes=15)
    ip = '5.6.7.8'

    # add attempts
    id_system.record_failed_attempt(ip)
    id_system.record_failed_attempt(ip)
    id_system.record_failed_attempt(ip)
    assert id_system.is_ip_blocked(ip) is True

    # advance time beyond window
    frozen_datetime.advance(minutes=16)

    # clear old records should remove the IP and expired locks
    id_system.clear_old_records()
    assert ip not in id_system.failed_logins
    assert id_system.is_ip_blocked(ip) is False


def test_multiple_ips_and_isolation(frozen_datetime):
    id_system = IntrusionDetection(max_attempts=2, window_minutes=10)
    ip1 = '10.0.0.1'
    ip2 = '10.0.0.2'

    id_system.record_failed_attempt(ip1)
    id_system.record_failed_attempt(ip2)
    id_system.record_failed_attempt(ip1)

    assert id_system.is_ip_blocked(ip1) is True
    assert id_system.is_ip_blocked(ip2) is False
    # ip2 may be throttled but not blocked
    assert id_system.is_ip_throttled(ip2) is True


def test_zero_window_blocks_only_same_instant(monkeypatch, start_time):
    # window_minutes = 0 means only same-instant attempts count
    id_system = IntrusionDetection(max_attempts=2, window_minutes=0)
    ip = '127.0.0.1'

    # record first attempt
    d1 = id_system.record_failed_attempt(ip)
    assert id_system.is_ip_blocked(ip) is False
    assert d1 >= 1

    # simulate time move by patching datetime.utcnow to later
    import backend.security.intrusion_detection as id_mod
    class FakeDT:
        def __init__(self, now):
            self._now = now
        def utcnow(self):
            return self._now
    fake_dt = FakeDT(start_time + timedelta(seconds=1))
    monkeypatch.setattr(id_mod, 'datetime', fake_dt)

    # another attempt after 1 second should not count in zero window
    d2 = id_system.record_failed_attempt(ip)
    assert id_system.is_ip_blocked(ip) is False
    assert d2 >= 1

    # but if we record at the same instant (simulate UTC now same), it would count
    monkeypatch.setattr(id_mod, 'datetime', FakeDT(start_time))
    d3 = id_system.record_failed_attempt(ip)
    assert id_system.is_ip_blocked(ip) is True
    assert d3 > 0
