# backend/operations/time_sync.py

# SR-14: Time sync check placeholder

# backend/operations/time_sync.py

# SR-14: Time sync check placeholder

# backend/operations/time_sync.py
# SR-14: NTP time offset verification

from typing import Dict, Tuple
import ntplib, time

NTP_SERVERS = ["time.google.com", "pool.ntp.org"]
MAX_OFFSET_SECONDS = 0.5  # fail if clock is off by > 500ms

def _query_ntp(server: str) -> Tuple[float, float]:
    c = ntplib.NTPClient()
    resp = c.request(server, version=3)
    # offset: local_time - server_time; delay: round-trip
    return resp.offset, resp.delay

def check_time_sync() -> Dict:
    """
    Checks time offset against multiple NTP servers and returns a summary.
    """
    results = []
    for s in NTP_SERVERS:
        try:
            offset, delay = _query_ntp(s)
            results.append({"server": s, "offset_s": offset, "delay_s": delay, "ok": abs(offset) <= MAX_OFFSET_SECONDS})
        except Exception as e:
            results.append({"server": s, "error": str(e), "ok": False})

    ok = all(r.get("ok") for r in results if "ok" in r)
    summary = {"max_allowed_offset_s": MAX_OFFSET_SECONDS, "timestamp": time.time(), "results": results, "overall_ok": ok}
    return summary

if __name__ == "__main__":
    from pprint import pprint
    pprint(check_time_sync())

