"""
AWS Telemetry Provider
======================
Ingests and parses AWS VPC Flow Logs (Standard Version 2 and Custom Formats)
into CanonicalFlowRecord format.
Supports streaming retrieval from Amazon CloudWatch Logs and Amazon S3
with decompression, pagination, deduplication, incremental checkpoints,
exponential backoff, and zero synthetic authentication telemetry.
"""

from datetime import datetime, timezone
import gzip
import io
import logging
import random
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from backend.app.cloud.adapters.aws.identity import AwsIdentityProvider
    from backend.app.cloud.interfaces.telemetry import BaseTelemetryProvider
    from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
except ImportError:
    from app.cloud.adapters.aws.identity import AwsIdentityProvider
    from app.cloud.interfaces.telemetry import BaseTelemetryProvider
    from app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord

logger = logging.getLogger(__name__)

IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

# Standard AWS VPC Flow Log Version 2 field order (14 tokens)
STANDARD_V2_FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log-status"
]


class AwsTelemetryProvider(BaseTelemetryProvider):
    """AWS VPC Flow Log telemetry ingestion and normalization provider."""

    def __init__(
        self,
        account_id: str = "unconfigured",
        region: str = "ap-southeast-2",
        identity_provider: Optional[AwsIdentityProvider] = None,
    ):
        super().__init__(provider_name="AWS", account_id=account_id)
        self.region = region
        self._identity_provider = identity_provider
        self._last_poll_status: Dict[str, Any] = {
            "status": "INITIALIZED",
            "last_poll_at": None,
            "records_discovered": 0,
            "records_ingested": 0,
            "duplicate_skipped": 0,
            "rejected_count": 0,
            "error_message": None,
        }

    def set_identity_provider(self, identity_provider: AwsIdentityProvider) -> None:
        """Associate identity provider to share STS assumed session."""
        self._identity_provider = identity_provider

    def get_ingestion_status(self) -> Dict[str, Any]:
        """Return the latest operational telemetry ingestion telemetry status."""
        return dict(self._last_poll_status)

    def discover_flow_log_sources(self) -> List[Dict[str, Any]]:
        """
        Query EC2 DescribeFlowLogs to identify active VPC Flow Log subscriptions,
        their traffic types, destinations (CloudWatch Logs vs S3), and delivery statuses.
        """
        if not self._identity_provider:
            return []

        session, diag = self._identity_provider.get_boto3_session()
        if session is None:
            logger.info("Cannot discover flow log sources: not authenticated (%s)", diag.get("status"))
            return []

        sources: List[Dict[str, Any]] = []
        try:
            ec2 = session.client("ec2", region_name=self.region)
            paginator = ec2.get_paginator("describe_flow_logs")
            for page in paginator.paginate():
                for fl in page.get("FlowLogs", []):
                    dest_type = fl.get("LogDestinationType", "cloud-watch-logs")
                    dest = fl.get("LogDestination", "")
                    sources.append({
                        "flow_log_id": fl.get("FlowLogId"),
                        "resource_id": fl.get("ResourceId"),
                        "traffic_type": fl.get("TrafficType", "ALL"),
                        "destination_type": dest_type,
                        "destination": dest,
                        "log_format": fl.get("LogFormat"),
                        "status": fl.get("FlowLogStatus"),
                        "deliver_status": fl.get("DeliverLogsStatus"),
                        "created_at": fl.get("CreationTime").isoformat() if fl.get("CreationTime") else None,
                    })
        except Exception as e:
            logger.warning("Error discovering AWS flow log sources: %s", e)

        return sources

    def fetch_from_cloudwatch_logs(
        self,
        session: Any,
        log_group: str,
        since_ms: Optional[int] = None,
        next_token: Optional[str] = None,
        limit: int = 100,
        max_pages: int = 5,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Retrieves log events from a CloudWatch log group with pagination,
        incremental checkpoint tracking, exponential backoff, and deduplication.
        """
        records: List[Dict[str, Any]] = []
        checkpoint_out: Dict[str, Any] = {
            "source_type": "CLOUDWATCH_LOGS",
            "source_identifier": log_group,
            "last_timestamp_ms": since_ms,
            "last_token": next_token,
        }
        dup_skipped = 0
        try:
            from backend.app.cloud.services.telemetry_checkpoint_service import TelemetryCheckpointService
        except ImportError:
            from app.cloud.services.telemetry_checkpoint_service import TelemetryCheckpointService
        dedup_cache = TelemetryCheckpointService.get_dedup_cache()

        cw_logs = session.client("logs", region_name=self.region)
        clean_group = log_group
        if clean_group.startswith("arn:aws:logs:"):
            clean_group = clean_group.split(":log-group:")[-1].split(":*")[0]

        current_token = next_token
        pages_retrieved = 0
        max_seen_ts = since_ms or 0

        # Optional lookback window (60s) to handle delayed out-of-order CloudWatch arrival
        start_time_param = since_ms
        if start_time_param and start_time_param > 60000:
            start_time_param = max(start_time_param - 60000, 0)

        while pages_retrieved < max_pages and len(records) < limit:
            kwargs: Dict[str, Any] = {
                "logGroupName": clean_group,
                "limit": min(limit - len(records), 100),
            }
            if start_time_param:
                kwargs["startTime"] = start_time_param
            if current_token:
                kwargs["nextToken"] = current_token

            # Execute with exponential backoff on throttling
            events_resp = None
            for attempt in range(4):
                try:
                    events_resp = cw_logs.filter_log_events(**kwargs)
                    break
                except Exception as e:
                    err_str = str(e).lower()
                    if "throttl" in err_str or "rate" in err_str or "provisionedthroughput" in err_str:
                        sleep_time = (0.5 * (2 ** attempt)) + random.uniform(0.1, 0.4)
                        logger.warning("CloudWatch filter_log_events throttled. Retrying in %.2fs (attempt %d/4)...", sleep_time, attempt + 1)
                        time.sleep(sleep_time)
                    elif "expiredtoken" in err_str or "requestexpired" in err_str:
                        logger.info("CloudWatch STS token expired. Refreshing session...")
                        if self._identity_provider:
                            session, _ = self._identity_provider.get_boto3_session()
                            if session:
                                cw_logs = session.client("logs", region_name=self.region)
                        break
                    else:
                        logger.warning("CloudWatch filter_log_events error on group '%s': %s", clean_group, e)
                        return records, {**checkpoint_out, "error": str(e)}

            if not events_resp:
                break

            events = events_resp.get("events", [])
            for ev in events:
                eid = ev.get("eventId") or ""
                ev_ts = ev.get("timestamp") or 0
                max_seen_ts = max(max_seen_ts, ev_ts)

                if eid and dedup_cache.is_duplicate(eid):
                    dup_skipped += 1
                    continue

                if eid:
                    dedup_cache.filter_and_record([eid])

                records.append({
                    "message": ev.get("message", ""),
                    "timestamp": ev_ts,
                    "source": "CLOUDWATCH_LOGS",
                    "log_group": clean_group,
                    "event_id": eid,
                    "log_stream": ev.get("logStreamName"),
                })
                if len(records) >= limit:
                    break

            current_token = events_resp.get("nextToken")
            pages_retrieved += 1
            if not current_token or not events:
                break

        checkpoint_out["last_timestamp_ms"] = max_seen_ts if max_seen_ts > 0 else since_ms
        checkpoint_out["last_token"] = current_token
        checkpoint_out["duplicate_skipped"] = dup_skipped
        checkpoint_out["pages_retrieved"] = pages_retrieved

        return records, checkpoint_out

    def fetch_from_s3(
        self,
        session: Any,
        s3_destination: str,
        last_key: Optional[str] = None,
        limit: int = 100,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Discovers, downloads, and decompresses .log.gz flow log objects from Amazon S3.
        Supports custom VPC flow log formats, incremental object processing, and deduplication.
        """
        records: List[Dict[str, Any]] = []
        checkpoint_out: Dict[str, Any] = {
            "source_type": "S3",
            "source_identifier": s3_destination,
            "last_object_key": last_key,
        }

        # Parse bucket and prefix
        bucket = s3_destination
        prefix = ""
        if bucket.startswith("arn:aws:s3:::"):
            bucket_part = bucket[len("arn:aws:s3:::"): ]
            if "/" in bucket_part:
                bucket, prefix = bucket_part.split("/", 1)
            else:
                bucket = bucket_part
        elif bucket.startswith("s3://"):
            bucket_part = bucket[len("s3://"): ]
            if "/" in bucket_part:
                bucket, prefix = bucket_part.split("/", 1)
            else:
                bucket = bucket_part

        prefix = prefix.lstrip("/")

        s3 = session.client("s3", region_name=self.region)
        list_kwargs: Dict[str, Any] = {
            "Bucket": bucket,
            "MaxKeys": 15,
        }
        if prefix:
            list_kwargs["Prefix"] = prefix
        if last_key:
            list_kwargs["StartAfter"] = last_key

        try:
            s3_resp = s3.list_objects_v2(**list_kwargs)
        except Exception as e:
            logger.warning("Error listing S3 flow log objects at '%s': %s", s3_destination, e)
            return records, {**checkpoint_out, "error": str(e)}

        contents = s3_resp.get("Contents", [])
        # Sort objects chronologically by LastModified
        contents.sort(key=lambda x: x.get("LastModified", datetime.min))

        last_processed_key = last_key
        detected_custom_fields: Optional[List[str]] = None
        try:
            from backend.app.cloud.services.telemetry_checkpoint_service import TelemetryCheckpointService
        except ImportError:
            from app.cloud.services.telemetry_checkpoint_service import TelemetryCheckpointService
        dedup_cache = TelemetryCheckpointService.get_dedup_cache()
        dup_skipped = 0

        for item in contents:
            key = item.get("Key", "")
            if not (key.endswith(".log.gz") or key.endswith(".log") or key.endswith(".txt")):
                continue

            try:
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw_bytes = obj["Body"].read()

                if key.endswith(".gz"):
                    decompressed = gzip.decompress(raw_bytes).decode("utf-8", errors="replace")
                else:
                    decompressed = raw_bytes.decode("utf-8", errors="replace")

                line_num = 0
                for line in decompressed.splitlines():
                    line_str = line.strip()
                    if not line_str or line_str.startswith("#"):
                        continue

                    # Check for header row
                    tokens = line_str.split()
                    if tokens and (tokens[0].lower() == "version" or "srcaddr" in [t.lower() for t in tokens]):
                        # Dynamic header format detection
                        detected_custom_fields = [t.lower() for t in tokens]
                        continue

                    line_num += 1
                    event_hash = f"s3-{bucket}-{key}-{line_num}"
                    if dedup_cache.is_duplicate(event_hash):
                        dup_skipped += 1
                        continue

                    dedup_cache.filter_and_record([event_hash])
                    records.append({
                        "message": line_str,
                        "timestamp": int(item.get("LastModified", datetime.now(timezone.utc)).timestamp() * 1000),
                        "source": "S3",
                        "s3_bucket": bucket,
                        "s3_key": key,
                        "event_id": event_hash,
                        "custom_fields": detected_custom_fields,
                    })
                    if len(records) >= limit:
                        break

                last_processed_key = key
                if len(records) >= limit:
                    break

            except Exception as e:
                logger.warning("Error reading S3 flow log object '%s': %s", key, e)

        checkpoint_out["last_object_key"] = last_processed_key
        checkpoint_out["duplicate_skipped"] = dup_skipped
        checkpoint_out["objects_evaluated"] = len(contents)

        return records, checkpoint_out

    def poll_flow_telemetry(
        self,
        checkpoint: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        filter_params: Optional[Dict[str, Any]] = None,
        mock_fallback: bool = False,
    ) -> Dict[str, Any]:
        """
        High-level polling orchestrator for AWS VPC flow log telemetry.
        Inspects available sources (CloudWatch Logs vs S3), retrieves records,
        tracks incremental checkpoints, applies deduplication, and records diagnostics.
        """
        start_time = time.perf_counter()
        raw_events: List[Dict[str, Any]] = []
        chk_out: Dict[str, Any] = {}
        source_type = "UNKNOWN"
        source_identifier = "none"

        if self._identity_provider:
            session, diag = self._identity_provider.get_boto3_session()
            if session is not None:
                sources = self.discover_flow_log_sources()
                log_group = None
                s3_destination = None

                if filter_params and filter_params.get("log_group"):
                    log_group = filter_params["log_group"]
                elif filter_params and filter_params.get("s3_bucket"):
                    s3_destination = filter_params["s3_bucket"]
                elif sources:
                    for src in sources:
                        if src["destination_type"] == "cloud-watch-logs" and src["destination"]:
                            log_group = src["destination"]
                            break
                        elif src["destination_type"] == "s3" and src["destination"]:
                            s3_destination = src["destination"]
                            break

                if not log_group and not s3_destination:
                    # Default to target CloudWatch log group for real VPC
                    log_group = "/aws/vpc/flowlogs/ap-southeast-2-default"

                # 1. CloudWatch Logs Ingestion
                if log_group:
                    source_type = "CLOUDWATCH_LOGS"
                    source_identifier = log_group
                    since_ms = checkpoint.get("last_timestamp_ms") if checkpoint else None
                    next_token = checkpoint.get("last_token") if checkpoint else None

                    raw_events, chk_out = self.fetch_from_cloudwatch_logs(
                        session=session,
                        log_group=log_group,
                        since_ms=since_ms,
                        next_token=next_token,
                        limit=limit,
                    )

                # 2. S3 Flow Logs Ingestion
                elif s3_destination:
                    source_type = "S3"
                    source_identifier = s3_destination
                    last_key = checkpoint.get("last_object_key") if checkpoint else None

                    raw_events, chk_out = self.fetch_from_s3(
                        session=session,
                        s3_destination=s3_destination,
                        last_key=last_key,
                        limit=limit,
                    )

        # 3. Offline/Sandbox mock fixture fallback if requested
        if not raw_events and mock_fallback:
            source_type = "SIMULATED_MOCK"
            source_identifier = "mock://aws-vpc-flowlogs-sandbox"
            now_ts = int(datetime.now(timezone.utc).timestamp())
            sample_logs = [
                f"2 {self.account_id} eni-0123456789abcdef0 10.20.10.15 10.20.10.2 44321 443 6 45 38500 {now_ts - 30} {now_ts} ACCEPT OK",
                f"2 {self.account_id} eni-0123456789abcdef0 198.51.100.42 10.20.10.2 55123 22 6 12 1040 {now_ts - 60} {now_ts - 50} REJECT OK",
                f"2 {self.account_id} eni-0123456789abcdef1 10.20.10.30 10.20.10.2 58100 80 6 80 64200 {now_ts - 20} {now_ts} ACCEPT OK",
                f"2 {self.account_id} eni-0123456789abcdef2 203.0.113.88 10.20.10.2 60234 8080 6 150 120500 {now_ts - 15} {now_ts} ACCEPT OK",
            ]
            raw_events = [
                {
                    "message": line,
                    "timestamp": now_ts * 1000,
                    "source": "SIMULATED_MOCK",
                    "event_id": f"mock-{i}",
                }
                for i, line in enumerate(sample_logs[:limit])
            ]
            chk_out = {
                "source_type": source_type,
                "source_identifier": source_identifier,
                "last_timestamp_ms": now_ts * 1000,
            }

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Update last poll status
        self._last_poll_status = {
            "status": "HEALTHY" if raw_events else ("EMPTY" if source_type != "UNKNOWN" else "NOT_CONFIGURED"),
            "source_type": source_type,
            "source_identifier": source_identifier,
            "last_poll_at": datetime.now(timezone.utc).isoformat(),
            "records_discovered": len(raw_events),
            "duplicate_skipped": chk_out.get("duplicate_skipped", 0),
            "duration_ms": round(elapsed_ms, 2),
            "error_message": chk_out.get("error"),
        }

        return {
            "events": raw_events,
            "source_type": source_type,
            "source_identifier": source_identifier,
            "checkpoint": chk_out,
            "metrics": self._last_poll_status,
        }

    def fetch_flow_records(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
        filter_params: Optional[Dict[str, Any]] = None,
        mock_fallback: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Backward-compatible method returning flat list of raw log events.
        """
        chk = {"last_timestamp_ms": int(since.timestamp() * 1000)} if since else None
        res = self.poll_flow_telemetry(
            checkpoint=chk,
            limit=limit,
            filter_params=filter_params,
            mock_fallback=mock_fallback,
        )
        return res.get("events", [])

    def parse_raw_log_record(
        self,
        raw_record: Union[str, Dict[str, Any]],
        custom_format: Optional[str] = None,
    ) -> Optional[CanonicalFlowRecord]:
        """
        Parses a single AWS VPC flow log line into a CanonicalFlowRecord.
        Supports both standard Version 2 (14 tokens) and custom format specifications.
        Excludes synthetic failed_auth_count (strictly 0) and computes exact 9 canonical features.
        """
        line = ""
        metadata: Dict[str, Any] = {}
        detected_fields: Optional[List[str]] = None

        if isinstance(raw_record, str):
            line = raw_record.strip()
        elif isinstance(raw_record, dict):
            line = raw_record.get("message", "") or raw_record.get("raw", "") or raw_record.get("line", "")
            line = line.strip()
            metadata = {k: v for k, v in raw_record.items() if k not in ("message", "raw", "line")}
            if "custom_fields" in raw_record and isinstance(raw_record["custom_fields"], list):
                detected_fields = raw_record["custom_fields"]

        if not line:
            return None

        # Ignore comments or headers
        if line.startswith("#") or line.lower().startswith("version") or line.lower().startswith("srcaddr"):
            return None

        tokens = line.split()
        if len(tokens) < 14 and not detected_fields:
            return None

        # Determine field schema mapping
        field_order: List[str] = STANDARD_V2_FIELDS
        if custom_format:
            # Extract ${field_name} tokens if provided as format string
            matches = re.findall(r"\$\{([^}]+)\}", custom_format)
            if matches:
                field_order = matches
        elif detected_fields:
            field_order = detected_fields

        try:
            # Helper to safely retrieve field by name
            def get_field(name: str, default: str = "-") -> str:
                if name in field_order:
                    idx = field_order.index(name)
                    if idx < len(tokens):
                        return tokens[idx]
                return default

            version = get_field("version", tokens[0] if len(tokens) > 0 else "2")
            account_id = get_field("account-id", tokens[1] if len(tokens) > 1 else self.account_id)
            interface_id = get_field("interface-id", tokens[2] if len(tokens) > 2 else "eni-unknown")
            src_ip = get_field("srcaddr", tokens[3] if len(tokens) > 3 else "-")
            dst_ip = get_field("dstaddr", tokens[4] if len(tokens) > 4 else "-")

            # Check for NODATA / SKIPDATA / absent IP
            if src_ip in ("-", "", "NODATA") or dst_ip in ("-", "", "NODATA"):
                return None

            src_port_val = get_field("srcport", tokens[5] if len(tokens) > 5 else "0")
            dst_port_val = get_field("dstport", tokens[6] if len(tokens) > 6 else "0")
            proto_val = get_field("protocol", tokens[7] if len(tokens) > 7 else "6")
            packets_val = get_field("packets", tokens[8] if len(tokens) > 8 else "1")
            bytes_val = get_field("bytes", tokens[9] if len(tokens) > 9 else "64")
            start_val = get_field("start", tokens[10] if len(tokens) > 10 else "-")
            end_val = get_field("end", tokens[11] if len(tokens) > 11 else "-")
            action_val = get_field("action", tokens[12] if len(tokens) > 12 else "UNKNOWN")
            log_status_val = get_field("log-status", tokens[13] if len(tokens) > 13 else "OK")

            src_port = int(src_port_val) if src_port_val != "-" else 0
            dst_port = int(dst_port_val) if dst_port_val != "-" else 0
            proto_num = int(proto_val) if proto_val != "-" else 6
            packet_count = int(packets_val) if packets_val != "-" else 1
            byte_count = int(bytes_val) if bytes_val != "-" else 64

            now_epoch = int(datetime.now(timezone.utc).timestamp())
            start_ts = int(start_val) if start_val != "-" else now_epoch
            end_ts = int(end_val) if end_val != "-" else start_ts + 1

            action = action_val.upper() if action_val != "-" else "UNKNOWN"
            log_status = log_status_val.upper() if log_status_val != "-" else "OK"

            if log_status in ("NODATA", "SKIPDATA"):
                return None

            duration = max(float(end_ts - start_ts), 0.001)
            conn_rate = float(packet_count) / duration
            bytes_per_sec = float(byte_count) / duration
            packets_per_sec = conn_rate
            avg_packet_size = float(byte_count) / float(max(packet_count, 1))

            protocol_name = IP_PROTOCOLS.get(proto_num, str(proto_num))
            timestamp = datetime.fromtimestamp(start_ts, tz=timezone.utc)

            # Determine traffic direction relative to VPC subnets
            is_src_private = (
                src_ip.startswith("10.")
                or src_ip.startswith("172.16.")
                or src_ip.startswith("172.17.")
                or src_ip.startswith("172.18.")
                or src_ip.startswith("172.19.")
                or src_ip.startswith("172.2")
                or src_ip.startswith("172.30.")
                or src_ip.startswith("172.31.")
                or src_ip.startswith("192.168.")
            )
            is_dst_private = (
                dst_ip.startswith("10.")
                or dst_ip.startswith("172.16.")
                or dst_ip.startswith("172.17.")
                or dst_ip.startswith("172.18.")
                or dst_ip.startswith("172.19.")
                or dst_ip.startswith("172.2")
                or dst_ip.startswith("172.30.")
                or dst_ip.startswith("172.31.")
                or dst_ip.startswith("192.168.")
            )

            flow_direction = "CROSS_ZONE"
            if is_src_private and is_dst_private:
                flow_direction = "INTERNAL"
            elif is_dst_private and not is_src_private:
                flow_direction = "INGRESS"
            elif is_src_private and not is_dst_private:
                flow_direction = "EGRESS"

            vpc_id = get_field("vpc-id", None)
            subnet_id = get_field("subnet-id", None)
            tcp_flags = get_field("tcp-flags", None)

            extra_meta = {
                "line": line,
                "interface_id": interface_id,
                "version": version,
                **metadata,
            }
            if vpc_id and vpc_id != "-":
                extra_meta["vpc_id"] = vpc_id
            if subnet_id and subnet_id != "-":
                extra_meta["subnet_id"] = subnet_id
            if tcp_flags and tcp_flags != "-":
                extra_meta["tcp_flags"] = tcp_flags

            return CanonicalFlowRecord(
                flow_id=f"aws-{interface_id}-{start_ts}-{src_ip}:{src_port}->{dst_ip}:{dst_port}",
                provider="AWS",
                account_id=account_id if account_id != "-" else self.account_id,
                region=self.region,
                resource_id=interface_id,
                vpc_id=vpc_id if vpc_id != "-" else None,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name,
                protocol_number=proto_num,
                packet_count=packet_count,
                byte_count=byte_count,
                duration=duration,
                conn_rate=conn_rate,
                bytes_per_sec=bytes_per_sec,
                packets_per_sec=packets_per_sec,
                avg_packet_size=avg_packet_size,
                unique_dst_ports=1,
                action=action,
                log_status=log_status,
                flow_direction=flow_direction,
                timestamp=timestamp,
                raw_payload=extra_meta,
            )
        except (ValueError, IndexError) as err:
            logger.debug("Failed to parse AWS flow log line '%s': %s", line, err)
            return None
