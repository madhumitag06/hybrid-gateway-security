"""
Bounded PCAP Capture & Storage Rotation Manager
===============================================
Prevents unbounded packet accumulation inside the shared telemetry volume by enforcing
strict file-size and file-count limits, and coordinates on-demand captures with `lab-router`.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict, List
import urllib.request

MAX_FILES = int(os.getenv("CAPTURE_MAX_FILES", os.getenv("CAPTURE_MAX_ARCHIVED_PCAPS", "20")))
MAX_FILE_SIZE_BYTES = int(os.getenv("CAPTURE_MAX_FILE_SIZE_MB", "10")) * 1024 * 1024
ROUTER_URL = os.getenv("LAB_ROUTER_URL", os.getenv("ROUTER_AGENT_URL", "http://10.30.10.2:8099")).rstrip("/")


def enforce_capture_bounds(pcap_dir: Path, meta_dir: Path) -> Dict[str, Any]:
    """
    Prunes oversized or excess PCAP files to guarantee bounded disk usage.
    """
    pcap_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    removed_oversized: List[str] = []
    removed_rotated: List[str] = []

    files = sorted(pcap_dir.glob("*.pcap*"), key=lambda f: f.stat().st_mtime, reverse=True)
    kept: List[Path] = []

    for f in files:
        try:
            if f.stat().st_size > MAX_FILE_SIZE_BYTES:
                f.unlink(missing_ok=True)
                removed_oversized.append(f.name)
            else:
                kept.append(f)
        except Exception:
            pass

    if len(kept) > MAX_FILES:
        for old_f in kept[MAX_FILES:]:
            try:
                old_f.unlink(missing_ok=True)
                meta_f = meta_dir / f"{old_f.name}.meta.json"
                meta_f.unlink(missing_ok=True)
                removed_rotated.append(old_f.name)
            except Exception:
                pass
        kept = kept[:MAX_FILES]

    return {
        "active_pcap_files": len(kept),
        "max_files_limit": MAX_FILES,
        "max_file_size_bytes": MAX_FILE_SIZE_BYTES,
        "removed_oversized": removed_oversized,
        "removed_rotated": removed_rotated,
    }


def trigger_router_capture(
    scenario: str = "hybrid_transit",
    max_packets: int = 500,
    duration_seconds: int = 8,
) -> Dict[str, Any]:
    """
    Requests `lab-router` (over internal mgmt_net 10.30.10.2:8099) to capture transit
    packets crossing between 10.10.10.0/24 and 10.20.10.0/24.
    """
    payload = json.dumps(
        {
            "scenario": scenario,
            "max_packets": min(max(max_packets, 10), 2500),
            "duration_seconds": min(max(duration_seconds, 1), 30),
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{ROUTER_URL}/api/capture",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=duration_seconds + 5) as resp:
        return json.loads(resp.read().decode("utf-8"))

