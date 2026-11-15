"""
Cloud Telemetry Checkpoint & Deduplication Service
==================================================
Manages persistent ingestion checkpoints, deduplication filters,
and audit histories for AWS CloudWatch and S3 telemetry streams.
Guarantees reliable restart recovery without historical event duplication.
"""

from collections import deque
from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

try:
    from backend.app.models.cloud_account import (
        CloudTelemetryCheckpointModel,
        CloudTelemetryIngestionModel,
    )
except ImportError:
    from app.models.cloud_account import (
        CloudTelemetryCheckpointModel,
        CloudTelemetryIngestionModel,
    )

logger = logging.getLogger(__name__)


class DeduplicationCache:
    """
    Thread-safe bounded FIFO deduplication cache for telemetry event IDs.
    Prevents duplicate ingestion when CloudWatch / S3 records overlap during incremental polls.
    """

    def __init__(self, max_size: int = 10000):
        self._max_size = max_size
        self._seen_set: Set[str] = set()
        self._queue: deque = deque()
        self._lock = threading.Lock()

    def is_duplicate(self, event_id: str) -> bool:
        """Check if an event ID has already been seen without adding it."""
        with self._lock:
            return event_id in self._seen_set

    def filter_and_record(self, event_ids: List[str]) -> Tuple[List[str], int]:
        """
        Filters out duplicate event IDs and registers new ones in the cache.
        Returns: (new_event_ids, duplicate_count)
        """
        new_ids: List[str] = []
        dup_count = 0
        with self._lock:
            for eid in event_ids:
                if not eid:
                    new_ids.append(eid)
                    continue
                if eid in self._seen_set:
                    dup_count += 1
                else:
                    self._seen_set.add(eid)
                    self._queue.append(eid)
                    new_ids.append(eid)

            # Evict oldest entries if over capacity
            while len(self._queue) > self._max_size:
                evicted = self._queue.popleft()
                self._seen_set.discard(evicted)

        return new_ids, dup_count

    def clear(self) -> None:
        """Clear cache state."""
        with self._lock:
            self._seen_set.clear()
            self._queue.clear()


# Global in-memory deduplication cache
_global_dedup_cache = DeduplicationCache(max_size=20000)


class TelemetryCheckpointService:
    """Service managing incremental checkpoints and ingestion audit records."""

    @classmethod
    def get_dedup_cache(cls) -> DeduplicationCache:
        return _global_dedup_cache

    @classmethod
    def get_checkpoint(
        cls,
        db: Session,
        provider: str,
        account_id: str,
        source_identifier: str,
    ) -> Optional[CloudTelemetryCheckpointModel]:
        """Retrieve the latest checkpoint for a specific cloud source."""
        chk_id = f"chk-{provider.upper()}-{account_id}-{source_identifier.replace('/', '_').replace(':', '_')}"
        return db.query(CloudTelemetryCheckpointModel).filter(
            CloudTelemetryCheckpointModel.id == chk_id
        ).first()

    @classmethod
    def save_checkpoint(
        cls,
        db: Session,
        provider: str,
        account_id: str,
        source_type: str,
        source_identifier: str,
        last_timestamp_ms: Optional[int] = None,
        last_token: Optional[str] = None,
        last_object_key: Optional[str] = None,
        records_added: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CloudTelemetryCheckpointModel:
        """
        Upsert a checkpoint record for a provider and source destination.
        """
        chk_id = f"chk-{provider.upper()}-{account_id}-{source_identifier.replace('/', '_').replace(':', '_')}"
        now = datetime.now(timezone.utc)
        checkpoint = db.query(CloudTelemetryCheckpointModel).filter(
            CloudTelemetryCheckpointModel.id == chk_id
        ).first()

        if checkpoint is None:
            checkpoint = CloudTelemetryCheckpointModel(
                id=chk_id,
                provider=provider.upper(),
                account_id=account_id,
                source_type=source_type,
                source_identifier=source_identifier,
                last_timestamp_ms=last_timestamp_ms,
                last_token=last_token,
                last_object_key=last_object_key,
                total_records_processed=records_added,
                last_poll_at=now,
                metadata_json=metadata or {},
            )
            db.add(checkpoint)
        else:
            if last_timestamp_ms is not None:
                checkpoint.last_timestamp_ms = max(checkpoint.last_timestamp_ms or 0, last_timestamp_ms)
            if last_token is not None:
                checkpoint.last_token = last_token
            if last_object_key is not None:
                checkpoint.last_object_key = last_object_key
            checkpoint.total_records_processed += records_added
            checkpoint.last_poll_at = now
            if metadata:
                checkpoint.metadata_json.update(metadata)

        try:
            db.commit()
            db.refresh(checkpoint)
        except Exception as e:
            logger.warning("Checkpoint save omitted or rolled back: %s", e)
            db.rollback()

        return checkpoint

    @classmethod
    def record_ingestion(
        cls,
        db: Session,
        ingestion_id: str,
        provider: str,
        account_id: str,
        source_type: str,
        source_identifier: Optional[str],
        records_discovered: int,
        records_ingested: int,
        records_duplicate_skipped: int,
        records_rejected: int,
        high_risk_detected: int,
        flows_accepted: int,
        flows_dropped: int,
        status: str,
        error_message: Optional[str] = None,
        duration_ms: float = 0.0,
        summary: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[CloudTelemetryIngestionModel]:
        """Record an ingestion run into PostgreSQL for operational auditing."""
        ingestion = CloudTelemetryIngestionModel(
            id=ingestion_id,
            provider=provider.upper(),
            account_id=account_id,
            source_type=source_type,
            source_identifier=source_identifier,
            records_discovered=records_discovered,
            records_ingested=records_ingested,
            records_duplicate_skipped=records_duplicate_skipped,
            records_rejected=records_rejected,
            high_risk_detected=high_risk_detected,
            flows_accepted=flows_accepted,
            flows_dropped=flows_dropped,
            status=status,
            error_message=error_message,
            duration_ms=duration_ms,
            summary_json=summary or [],
        )
        try:
            db.add(ingestion)
            db.commit()
            db.refresh(ingestion)
            return ingestion
        except Exception as e:
            logger.warning("Ingestion record commit omitted: %s", e)
            db.rollback()
            return None

    @classmethod
    def list_ingestion_history(
        cls,
        db: Session,
        provider: Optional[str] = None,
        account_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[CloudTelemetryIngestionModel]:
        """Query recent telemetry ingestion records."""
        q = db.query(CloudTelemetryIngestionModel)
        if provider:
            q = q.filter(CloudTelemetryIngestionModel.provider == provider.upper())
        if account_id:
            q = q.filter(CloudTelemetryIngestionModel.account_id == account_id)
        return q.order_by(CloudTelemetryIngestionModel.created_at.desc()).limit(limit).all()

