# backend/operations/backup_manager.py

# backend/operations/backup_manager.py

# backend/operations/backup_manager.py
# SR-13: Automated, encrypted backups with integrity file (SHA-256)

import os, tarfile, tempfile, time, json, hashlib, secrets, pathlib
from typing import List, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# CONFIG: comma-separated absolute paths to back up, e.g. "/var/app/db.sqlite,/var/app/config"
BACKUP_SOURCES = os.getenv("BACKUP_SOURCES", "").split(",")
# Directory where encrypted backups are written
BACKUP_OUTDIR = os.getenv("BACKUP_OUTDIR", "./backups")
# 64-hex chars (32 bytes) key. Example: os.urandom(32).hex()
AES256_KEY_HEX = os.getenv("BACKUP_AES256_KEY")  # REQUIRED

pathlib.Path(BACKUP_OUTDIR).mkdir(parents=True, exist_ok=True)

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _pack_sources(sources: List[str], dest_tar_gz: str) -> None:
    with tarfile.open(dest_tar_gz, "w:gz") as tar:
        for src in filter(None, map(str.strip, sources)):
            if os.path.exists(src):
                tar.add(src, arcname=os.path.basename(src))

def perform_backup() -> Dict:
    """
    Creates a timestamped tar.gz from BACKUP_SOURCES, encrypts with AES-256-GCM,
    writes a .sha256 integrity file, and returns metadata.
    """
    if not AES256_KEY_HEX or len(AES256_KEY_HEX) != 64:
        raise ValueError("BACKUP_AES256_KEY env var (64 hex chars) is required")

    key = bytes.fromhex(AES256_KEY_HEX)
    ts = time.strftime("%Y%m%d-%H%M%S")
    tmp_tar = tempfile.mktemp(prefix=f"backup-{ts}-", suffix=".tar.gz")
    _pack_sources(BACKUP_SOURCES, tmp_tar)

    # Encrypt with AES-256-GCM (random 12B nonce)
    nonce = secrets.token_bytes(12)
    with open(tmp_tar, "rb") as f:
        plaintext = f.read()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    enc_name = f"backup-{ts}.tar.gz.aes"
    enc_path = os.path.join(BACKUP_OUTDIR, enc_name)
    with open(enc_path, "wb") as f:
        f.write(nonce + ciphertext)  # nonce (12B) + ciphertext+tag

    # Integrity file
    sha = _sha256_file(enc_path)
    sha_path = enc_path + ".sha256"
    with open(sha_path, "w") as f:
        f.write(f"{sha}  {os.path.basename(enc_path)}\n")

    # Minimal immutable behaviour: mark read-only (portable)
    os.chmod(enc_path, 0o440)
    os.remove(tmp_tar)

    meta = {
        "backup_file": enc_path,
        "sha256_file": sha_path,
        "bytes_encrypted": len(ciphertext),
        "sources": [s for s in BACKUP_SOURCES if s.strip()],
        "created_at": ts,
    }
    # optional JSON manifest
    with open(enc_path + ".json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"[SR-13] Backup created: {enc_path}")
    return meta

if __name__ == "__main__":
    perform_backup()

