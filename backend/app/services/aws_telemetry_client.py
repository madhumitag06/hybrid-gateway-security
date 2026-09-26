"""
Read-Only AWS Telemetry Client
==============================
Provides safe, read-only retrieval of AWS VPC Flow Logs from Amazon CloudWatch Logs
or Amazon S3. In standard/default laboratory mode (AWS_FIXTURE), operates 100% offline
with zero credentials or AWS API calls.
"""

from typing import Any, Dict, List, Optional, Tuple
from backend.app.config import settings


class AwsTelemetryClient:
    """
    Read-only AWS Telemetry client wrapper.
    Guaranteed NOT to issue any resource-modifying, firewall, or security group API calls.
    """

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """
        Returns active AWS telemetry retrieval mode and configuration status.
        """
        return {
            "telemetry_mode": settings.aws_telemetry_mode,
            "region": settings.aws_region,
            "cloudwatch_log_group": settings.aws_cloudwatch_log_group,
            "is_read_only": True,
            "firewall_enforcement_enabled": False,
            "offline_fixture_mode_active": settings.aws_telemetry_mode == "AWS_FIXTURE",
        }

    @classmethod
    def fetch_cloudwatch_flow_logs(
        cls,
        log_group: Optional[str] = None,
        log_stream: Optional[str] = None,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
    ) -> Tuple[bool, List[str], str]:
        """
        Read-only retrieval of VPC flow log events from Amazon CloudWatch Logs.
        Returns: (success: bool, raw_lines: List[str], message: str)
        """
        if settings.aws_telemetry_mode == "AWS_FIXTURE":
            return (
                False,
                [],
                "AWS_FIXTURE mode is active. Live CloudWatch API calls are disabled. Use benchmark fixtures or switch to AWS_READ_ONLY mode.",
            )

        target_group = log_group or settings.aws_cloudwatch_log_group

        try:
            import boto3

            client = boto3.client("logs", region_name=settings.aws_region)
            kwargs: Dict[str, Any] = {"logGroupName": target_group, "limit": 100}
            if log_stream:
                kwargs["logStreamNames"] = [log_stream]
            if start_time:
                kwargs["startTime"] = start_time * 1000
            if end_time:
                kwargs["endTime"] = end_time * 1000

            response = client.filter_log_events(**kwargs)
            events = response.get("events", [])
            lines = [e.get("message", "").strip() for e in events if e.get("message")]

            return True, lines, f"Successfully retrieved {len(lines)} flow log records from CloudWatch log group '{target_group}'."

        except ImportError:
            return False, [], "boto3 library is not installed in the environment."
        except Exception as exc:
            return False, [], f"AWS CloudWatch read failed: {str(exc)}"

    @classmethod
    def fetch_s3_flow_logs(
        cls,
        bucket_name: str,
        prefix: str = "",
    ) -> Tuple[bool, List[str], str]:
        """
        Read-only retrieval of compressed or raw VPC flow log objects from Amazon S3.
        Returns: (success: bool, raw_lines: List[str], message: str)
        """
        if settings.aws_telemetry_mode == "AWS_FIXTURE":
            return (
                False,
                [],
                "AWS_FIXTURE mode is active. S3 API calls are disabled.",
            )

        try:
            import boto3
            import gzip
            from io import BytesIO
            from botocore.exceptions import BotoCoreError, ClientError

            s3 = boto3.client("s3", region_name=settings.aws_region)
            resp = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix, MaxKeys=5)
            contents = resp.get("Contents", [])
            if not contents:
                return True, [], f"No flow log objects found in bucket '{bucket_name}' with prefix '{prefix}'."

            lines: List[str] = []
            for obj_meta in contents:
                key = obj_meta["Key"]
                obj = s3.get_object(Bucket=bucket_name, Key=key)
                body = obj["Body"].read()

                # Handle gzipped S3 flow logs
                if key.endswith(".gz") or body.startswith(b"\x1f\x8b"):
                    decompressed = gzip.GzipFile(fileobj=BytesIO(body)).read().decode("utf-8")
                else:
                    decompressed = body.decode("utf-8")

                for line in decompressed.splitlines():
                    if line.strip():
                        lines.append(line.strip())

            return True, lines, f"Successfully retrieved {len(lines)} records from S3 bucket '{bucket_name}'."

        except ImportError:
            return False, [], "boto3 library is not installed."
        except (ClientError, BotoCoreError, Exception) as exc:
            return False, [], f"AWS S3 flow log read failed: {str(exc)}"
