# backend/operations/health_monitor.py

# SR-19: Health check placeholder

# backend/operations/health_monitor.py
# SR-19: Liveness/Readiness health checks (DB, disk, time, app)

import os, shutil, sqlite3, time
from typing import Dict
from flask import Flask, jsonify

# Robust import so this works whether you run as a module or a script
try:
    from .time_sync import check_time_sync  # when run as package: python -m backend.operations.health_monitor
except Exception:
    try:
        from time_sync import check_time_sync  # when run directly: python backend/operations/health_monitor.py
    except Exception:
        import sys
        sys.path.append(os.path.dirname(__file__))  # last resort: add this dir to path
        from time_sync import check_time_sync

DB_PATH = os.getenv("APP_DB_PATH", "./app.sqlite")
MIN_FREE_DISK_GB = float(os.getenv("MIN_FREE_DISK_GB", "1"))
MAX_TIME_OFFSET_S = float(os.getenv("MAX_TIME_OFFSET_S", "0.5"))

def _check_db() -> Dict:
    try:
        conn = sqlite3.connect(DB_PATH, timeout=2)
        conn.execute("CREATE TABLE IF NOT EXISTS health_probe (id INTEGER PRIMARY KEY, ts INT)")
        conn.execute("INSERT INTO health_probe(ts) VALUES (?)", (int(time.time()),))
        conn.commit()
        conn.close()
        return {"ok": True, "detail": "sqlite ok", "db_path": DB_PATH}
    except Exception as e:
        return {"ok": False, "error": str(e), "db_path": DB_PATH}

def _check_disk() -> Dict:
    total, used, free = shutil.disk_usage(".")
    free_gb = free / (1024**3)
    return {"ok": free_gb >= MIN_FREE_DISK_GB, "free_gb": round(free_gb, 2), "min_required_gb": MIN_FREE_DISK_GB}

def _check_time() -> Dict:
    res = check_time_sync()
    # consider ok if all OK and offsets within bound
    res["policy_max_offset_s"] = MAX_TIME_OFFSET_S
    res["overall_ok"] = res["overall_ok"] and all(
        abs(r.get("offset_s", 0)) <= MAX_TIME_OFFSET_S for r in res["results"] if "offset_s" in r
    )
    return res

def check_health() -> Dict:
    """Aggregate overall system health."""
    db = _check_db()
    disk = _check_disk()
    tm = _check_time()
    overall = db["ok"] and disk["ok"] and tm["overall_ok"]
    return {"db": db, "disk": disk, "time": tm, "overall_ok": overall}

# Optional HTTP server for demos
def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/health")
    def liveness():
        res = check_health()
        code = 200 if res["overall_ok"] else 503
        return jsonify(res), code

    @app.get("/ready")
    def readiness():
        # readiness: DB + disk only (skip external NTP if you want faster readiness)
        db = _check_db()
        disk = _check_disk()
        ok = db["ok"] and disk["ok"]
        res = {"db": db, "disk": disk, "overall_ok": ok}
        code = 200 if ok else 503
        return jsonify(res), code

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
