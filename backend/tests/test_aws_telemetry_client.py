import sys
from unittest.mock import MagicMock, patch
from backend.app.config import settings
from backend.app.services.aws_telemetry_client import AwsTelemetryClient


def test_aws_telemetry_status_offline_default():
    """Verify default offline status reporting and read-only flags."""
    status = AwsTelemetryClient.get_status()

    assert status["is_read_only"] is True
    assert status["firewall_enforcement_enabled"] is False
    assert status["telemetry_mode"] == "AWS_FIXTURE"
    assert status["offline_fixture_mode_active"] is True


def test_cloudwatch_fetch_in_fixture_mode_returns_disabled_message():
    """Verify live CloudWatch calls are blocked with an informative message in AWS_FIXTURE mode."""
    success, lines, msg = AwsTelemetryClient.fetch_cloudwatch_flow_logs()

    assert success is False
    assert len(lines) == 0
    assert "AWS_FIXTURE mode is active" in msg


def test_mocked_cloudwatch_fetch_success():
    """Verify CloudWatch log retrieval with mocked boto3 client."""
    mock_boto3 = MagicMock()
    mock_logs_client = MagicMock()
    mock_boto3.client.return_value = mock_logs_client
    mock_logs_client.filter_log_events.return_value = {
        "events": [
            {"message": "2 123456789012 eni-001 10.100.1.5 10.100.2.10 5000 80 6 10 500 1710000000 1710000005 ACCEPT OK"},
            {"message": "2 123456789012 eni-001 10.100.1.5 10.100.2.10 5001 80 6 15 750 1710000005 1710000010 ACCEPT OK"},
        ]
    }

    with patch.object(settings, "aws_telemetry_mode", "AWS_READ_ONLY"):
        with patch.dict(sys.modules, {"boto3": mock_boto3, "botocore.exceptions": MagicMock()}):
            success, lines, msg = AwsTelemetryClient.fetch_cloudwatch_flow_logs(
                log_group="/aws/vpc/flow-logs",
                start_time=1710000000,
                end_time=1710000010,
            )

            assert success is True
            assert len(lines) == 2
            assert "Successfully retrieved 2" in msg


def test_mocked_cloudwatch_fetch_client_error_graceful_handling():
    """Verify graceful error reporting when boto3 encounters ClientError or missing credentials."""
    mock_boto3 = MagicMock()
    mock_logs_client = MagicMock()
    mock_boto3.client.return_value = mock_logs_client
    mock_logs_client.filter_log_events.side_effect = Exception("AccessDenied: User is not authorized")

    with patch.object(settings, "aws_telemetry_mode", "AWS_READ_ONLY"):
        with patch.dict(sys.modules, {"boto3": mock_boto3, "botocore.exceptions": MagicMock()}):
            success, lines, msg = AwsTelemetryClient.fetch_cloudwatch_flow_logs()

            assert success is False
            assert len(lines) == 0
            assert "AWS CloudWatch read failed" in msg
            assert "AccessDenied" in msg
