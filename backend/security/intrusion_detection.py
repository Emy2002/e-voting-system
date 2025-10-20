# backend/security/intrusion_detection.py

from collections import defaultdict
from datetime import datetime, timedelta

# SR-10: Intrusion Detection by tracking failed login attempts per IP

class IntrusionDetection:
    def __init__(self, max_attempts=5, window_minutes=15):
        self.failed_logins = defaultdict(list)
        self.max_attempts = max_attempts
        self.window = timedelta(minutes=window_minutes)

    def record_failed_attempt(self, ip):
        now = datetime.utcnow()
        self.failed_logins[ip].append(now)
        self.failed_logins[ip] = [t for t in self.failed_logins[ip] if now - t <= self.window]

    def is_ip_blocked(self, ip):
        return len(self.failed_logins[ip]) >= self.max_attempts

    def clear_old_records(self):
        now = datetime.utcnow()
        to_delete = []
        for ip, attempts in self.failed_logins.items():
            self.failed_logins[ip] = [t for t in attempts if now - t <= self.window]
            if not self.failed_logins[ip]:
                to_delete.append(ip)
        for ip in to_delete:
            del self.failed_logins[ip]

# Usage example:
# id_system = IntrusionDetection()
# id_system.record_failed_attempt('192.168.1.1')
# print(id_system.is_ip_blocked('192.168.1.1'))
