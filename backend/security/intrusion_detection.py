# backend/security/intrusion_detection.py

from collections import defaultdict
from datetime import datetime, timedelta

# SR-10: Intrusion Detection by tracking failed login attempts per IP
# Implement progressive delay + short lockout to throttle brute-force attempts


class IntrusionDetection:
    def __init__(self, max_attempts=5, window_minutes=15, lockout_minutes=5,
                 base_delay_seconds=1, max_delay_seconds=60):
        """
        max_attempts: attempts within `window_minutes` that trigger lockout
        window_minutes: sliding window to count attempts
        lockout_minutes: duration of short lockout when max_attempts reached
        base_delay_seconds: starting delay applied after first failed attempt
        max_delay_seconds: cap for exponential backoff delay
        """
        self.failed_logins = defaultdict(list)  # ip -> list[datetime]
        self.max_attempts = max_attempts
        self.window = timedelta(minutes=window_minutes)
        self.lockout_duration = timedelta(minutes=lockout_minutes)
        self.base_delay_seconds = base_delay_seconds
        self.max_delay_seconds = max_delay_seconds

        # stateful controls
        self.locks = {}  # ip -> locked_until datetime
        self.next_allowed = {}  # ip -> datetime when next attempt is allowed (throttle)

    def _now(self):
        # extracted for easier monkeypatching in tests
        return datetime.utcnow()

    def record_failed_attempt(self, ip):
        """
        Record a failed attempt for `ip`.

        Returns:
            delay_seconds (int): number of seconds client should wait before next attempt.
                If a lockout is in effect, returns remaining lockout seconds (>0).
        """
        now = self._now()

        # If currently locked, return remaining lockout time
        locked_until = self.locks.get(ip)
        if locked_until and now < locked_until:
            remaining = int((locked_until - now).total_seconds())
            return remaining

        # record attempt and prune old ones
        attempts = self.failed_logins[ip]
        attempts.append(now)
        attempts = [t for t in attempts if now - t <= self.window]
        self.failed_logins[ip] = attempts

        count = len(attempts)

        # If threshold reached, apply lockout
        if count >= self.max_attempts:
            locked_until = now + self.lockout_duration
            self.locks[ip] = locked_until
            # reset attempts after lockout starts
            self.failed_logins[ip] = []
            return int(self.lockout_duration.total_seconds())

        # Progressive exponential backoff delay (in seconds)
        delay = min(self.base_delay_seconds * (2 ** (count - 1)), self.max_delay_seconds)
        next_allowed = now + timedelta(seconds=delay)
        self.next_allowed[ip] = next_allowed
        return int(delay)

    def is_ip_blocked(self, ip):
        """Return True if IP is in short lockout period (not for short throttle delays)."""
        now = self._now()
        locked_until = self.locks.get(ip)
        if locked_until and now < locked_until:
            return True
        return False

    def is_ip_throttled(self, ip):
        """Return True if IP should wait before next attempt due to progressive delay."""
        now = self._now()
        next_allowed = self.next_allowed.get(ip)
        if next_allowed and now < next_allowed:
            return True
        return False

    def clear_old_records(self):
        now = self._now()
        to_delete = []
        for ip, attempts in list(self.failed_logins.items()):
            pruned = [t for t in attempts if now - t <= self.window]
            if pruned:
                self.failed_logins[ip] = pruned
            else:
                del self.failed_logins[ip]

        # clear expired locks and next_allowed entries
        for ip, locked_until in list(self.locks.items()):
            if now >= locked_until:
                del self.locks[ip]

        for ip, when in list(self.next_allowed.items()):
            if now >= when:
                del self.next_allowed[ip]

# Usage example:
# id_system = IntrusionDetection()
# id_system.record_failed_attempt('192.168.1.1')
# print(id_system.is_ip_blocked('192.168.1.1'))
