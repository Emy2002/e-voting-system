# backend/operations/time_sync.py

# SR-14: Time sync check placeholder

# backend/operations/time_sync.py
# SR-14: Time Synchronization using NTP servers for accurate event logging

import ntplib
import time
from datetime import datetime
from typing import Dict, List

# A few reliable NTP servers (you can modify or expand this list)
NTP_SERVERS = [
    "pool.ntp.org",
    "time.google.com",
    "time.windows.com",
    "time.apple.com"
]

# Maximum acceptable time offset in seconds (as per policy)
MAX_ALLOWED_OFFSET = 0.5

def check_time_sync() -> Dict:
    """
    Check time offset from multiple NTP servers.
    Returns:
        A dictionary containing offsets, average drift, and overall health.
    """
    results: List[Dict] = []
    total_offset = 0
    valid_servers = 0

    for server in NTP_SERVERS:
        try:
            client = ntplib.NTPClient()
            response = client.request(server, version=3)
            offset = response.offset
            total_offset += offset
            valid_servers += 1
            results.append({
                "server": server,
                "offset_s": round(offset, 6),
                "time": datetime.utcfromtimestamp(response.tx_time).isoformat() + "Z",
                "status": "ok" if abs(offset) <= MAX_ALLOWED_OFFSET else "drifted"
            })
        except Exception as e:
            results.append({
                "server": server,
                "error": str(e),
                "status": "failed"
            })

    avg_offset = round(total_offset / valid_servers, 6) if valid_servers else None
    overall_ok = avg_offset is not None and abs(avg_offset) <= MAX_ALLOWED_OFFSET

    return {
        "overall_ok": overall_ok,
        "average_offset_s": avg_offset,
        "max_allowed_offset_s": MAX_ALLOWED_OFFSET,
        "results": results
    }


if __name__ == "__main__":
    print("[SR-14] Time Synchronization Check")
    summary = check_time_sync()
    print(summary)
    if summary["overall_ok"]:
        print("✅ System time is synchronized within acceptable limits.")
    else:
        print("⚠️  Warning: System time drift exceeds threshold!")

