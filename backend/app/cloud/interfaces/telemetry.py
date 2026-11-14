"""
Cloud Provider Abstraction - Telemetry Provider Interface.
Defines the contract for fetching, parsing, and normalizing network flow logs into CanonicalFlowRecord format.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

try:
    from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
except ImportError:
    from app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord


class BaseTelemetryProvider(ABC):
    """Abstract base class for cloud network telemetry ingestion and parsing."""

    def __init__(self, provider_name: str, account_id: str):
        self.provider_name = provider_name
        self.account_id = account_id

    @abstractmethod
    def fetch_flow_records(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
        filter_params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch raw flow log events from the cloud provider (CloudWatch Logs, S3, Cloud Logging, Azure Storage).
        """
        pass

    @abstractmethod
    def parse_raw_log_record(
        self, raw_record: Union[str, Dict[str, Any]]
    ) -> Optional[CanonicalFlowRecord]:
        """
        Parse a single provider-specific raw flow record into a CanonicalFlowRecord.
        Returns None if record is invalid, header, or unparseable.
        """
        pass

    def normalize_batch(
        self, raw_records: List[Union[str, Dict[str, Any]]]
    ) -> List[CanonicalFlowRecord]:
        """
        Normalize a batch of raw records, filtering out skipped or unparseable items.
        """
        canonical_records: List[CanonicalFlowRecord] = []
        for record in raw_records:
            parsed = self.parse_raw_log_record(record)
            if parsed is not None:
                canonical_records.append(parsed)
        return canonical_records
