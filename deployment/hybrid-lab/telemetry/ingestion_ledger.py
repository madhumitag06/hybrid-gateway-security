"""
Telemetry PCAP Ingestion Ledger & Deduplication Manager
======================================================
Tracks processed PCAP files across sensor restarts using SHA-256 content hashing.
Guarantees idempotent startup scanning, prevents concurrent watcher processing,
and avoids marking interrupted or failed ingestions as completed.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("telemetry.ingestion_ledger")


class IngestionLedger:
    """
    Persistent file-backed ledger tracking the ingestion lifecycle of PCAP files.
    
    Status states:
      - IN_PROGRESS: File upload and processing is underway.
      - COMPLETED:   Successfully evaluated by Gateway API and optionally converted/ingested as VPC logs.
      - FAILED:      Encountered an unhandled exception or non-2xx API error during processing.
    """

    def __init__(self, ledger_file: Optional[Path] = None, stale_timeout_sec: float = 60.0):
        self.ledger_file = ledger_file or Path("/var/lib/hybrid-lab/telemetry/metadata/pcap_ingestion_ledger.json")
        self.stale_timeout_sec = stale_timeout_sec
        self._lock = threading.RLock()
        self._active_processing_files: Set[str] = set()
        self._ledger: Dict[str, Dict[str, Any]] = {}
        self.load()

    @staticmethod
    def compute_sha256(filepath: Path) -> str:
        """
        Computes SHA-256 hash of a file's content using streaming 64 KB buffers.
        """
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def load(self) -> Dict[str, Dict[str, Any]]:
        """
        Loads the ledger from disk. If missing or corrupt, initializes an empty ledger safely.
        """
        with self._lock:
            if not self.ledger_file.exists():
                self._ledger = {}
                return self._ledger

            try:
                raw_text = self.ledger_file.read_text(encoding="utf-8")
                self._ledger = json.loads(raw_text)
                if not isinstance(self._ledger, dict):
                    self._ledger = {}
            except Exception as e:
                logger.warning(f"Failed to read ingestion ledger {self.ledger_file} ({e}); resetting in-memory ledger.")
                self._ledger = {}
            return self._ledger

    def save(self) -> None:
        """
        Persists the ledger to disk atomically using a temporary file and rename to prevent
        data loss or corrupt state during process crashes or power interruptions.
        """
        with self._lock:
            try:
                self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
                temp_file = self.ledger_file.with_suffix(".tmp")
                temp_file.write_text(json.dumps(self._ledger, indent=2, sort_keys=True), encoding="utf-8")
                temp_file.replace(self.ledger_file)
            except Exception as e:
                logger.error(f"Failed to save ingestion ledger {self.ledger_file}: {e}")

    def should_ingest(self, filepath: Path) -> Tuple[bool, str, Optional[str]]:
        """
        Determines whether a PCAP file should be ingested based on file existence, size,
        concurrency state, and persistent SHA-256 content hash matching.

        Returns:
            (should_ingest: bool, reason: str, sha256: Optional[str])
        """
        if not filepath.exists():
            return False, "FILE_NOT_FOUND", None

        try:
            stat = filepath.stat()
            file_size = stat.st_size
        except OSError:
            return False, "STAT_ERROR", None

        # Standard PCAP global header is 24 bytes; smaller files cannot be valid PCAPs
        if file_size < 24:
            return False, "INCOMPLETE_OR_EMPTY_PCAP", None

        filename = filepath.name

        with self._lock:
            # 1. Concurrency guard: Check if currently locked by an active thread / watcher
            if filename in self._active_processing_files:
                return False, "CONCURRENT_PROCESSING_ACTIVE", None

            try:
                current_sha = self.compute_sha256(filepath)
            except Exception as e:
                return False, f"HASH_ERROR: {e}", None

            entry = self._ledger.get(filename)

            if entry is None:
                return True, "NEW_UNSEEN_FILE", current_sha

            status = entry.get("status")
            recorded_sha = entry.get("sha256")

            # 2. Content change check: A genuinely changed PCAP is processed as a new version
            if recorded_sha != current_sha:
                return True, "CONTENT_MODIFIED_NEW_VERSION", current_sha

            # 3. Completed check: Unchanged and successfully completed -> skip idempotently
            if status == "COMPLETED":
                return False, "ALREADY_COMPLETED_IDENTICAL_HASH", current_sha

            # 4. Interrupted processing check: Check if previous worker crashed
            if status == "IN_PROGRESS":
                started_epoch = float(entry.get("started_epoch", 0.0))
                now_epoch = time.time()
                if (now_epoch - started_epoch) >= self.stale_timeout_sec:
                    return True, "INTERRUPTED_PROCESSING_STALE_RETRY", current_sha
                return False, "IN_PROGRESS_ACTIVE", current_sha

            # 5. Failed check: Allow retrying previously failed ingestions
            if status == "FAILED":
                return True, "RETRY_PREVIOUS_FAILURE", current_sha

            return True, f"UNKNOWN_STATE_{status}", current_sha

    def acquire_processing(self, filename: str) -> bool:
        """
        Thread-safely locks a file to ensure it is not simultaneously processed by startup
        scanning and live watcher filesystem triggers.
        """
        with self._lock:
            if filename in self._active_processing_files:
                return False
            self._active_processing_files.add(filename)
            return True

    def release_processing(self, filename: str) -> None:
        """
        Releases the in-memory concurrency lock for a file.
        """
        with self._lock:
            self._active_processing_files.discard(filename)

    def mark_in_progress(self, filepath: Path, sha256: str) -> None:
        """
        Records that ingestion has commenced for a file. Does NOT mark as completed.
        """
        with self._lock:
            filename = filepath.name
            stat = filepath.stat()
            now = datetime.now(timezone.utc)
            now_epoch = time.time()

            existing = self._ledger.get(filename, {})
            current_version = existing.get("version", 0)
            if existing.get("sha256") != sha256:
                current_version += 1

            self._ledger[filename] = {
                "filename": filename,
                "sha256": sha256,
                "file_size_bytes": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "version": max(current_version, 1),
                "status": "IN_PROGRESS",
                "started_at": now.isoformat(),
                "started_epoch": now_epoch,
                "completed_at": None,
                "error_message": None,
                "summary": existing.get("summary"),
            }
            self.save()

    def mark_completed(self, filepath: Path, sha256: str, summary: Dict[str, Any]) -> None:
        """
        Records that ingestion was verified and completed successfully by the Gateway API.
        """
        with self._lock:
            filename = filepath.name
            now = datetime.now(timezone.utc)
            entry = self._ledger.get(filename, {})

            entry.update({
                "filename": filename,
                "sha256": sha256,
                "status": "COMPLETED",
                "completed_at": now.isoformat(),
                "error_message": None,
                "summary": summary,
            })
            self._ledger[filename] = entry
            self.save()

    def mark_failed(self, filepath: Path, sha256: str, error_message: str) -> None:
        """
        Records that ingestion failed. Strictly avoids marking as completed.
        """
        with self._lock:
            filename = filepath.name
            now = datetime.now(timezone.utc)
            entry = self._ledger.get(filename, {})

            entry.update({
                "filename": filename,
                "sha256": sha256,
                "status": "FAILED",
                "failed_at": now.isoformat(),
                "error_message": str(error_message),
            })
            self._ledger[filename] = entry
            self.save()

    def get_entry(self, filename: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the recorded ledger entry for a filename.
        """
        with self._lock:
            entry = self._ledger.get(filename)
            return dict(entry) if entry else None

    def get_all_entries(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns a complete copy of the recorded ledger.
        """
        with self._lock:
            return dict(self._ledger)
