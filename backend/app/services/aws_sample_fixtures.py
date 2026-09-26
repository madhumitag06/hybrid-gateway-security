"""
AWS VPC Flow Log Sample Fixture Generator & Manager
===================================================
Generates deterministic, benchmark AWS VPC Flow Log test files for offline testing,
automated regression, and dashboard demonstration without AWS accounts or network access.
"""

from pathlib import Path
from typing import List
from backend.app.schemas.aws_flow import AwsVpcSampleFixtureInfo

AWS_FIXTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "sample_vpc_logs"


def generate_aws_port_scan_fixture(filepath: Path) -> int:
    """
    Simulates a rapid reconnaissance port scan across 60 destination ports within an AWS VPC.
    Format: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
    """
    lines = []
    account_id = "123456789012"
    interface_id = "eni-0a1b2c3d4e5f67890"
    src_ip = "192.168.10.55"  # On-prem scanner
    dst_ip = "10.100.1.50"    # AWS VPC instance
    base_start = 1710000000
    protocol = 6  # TCP

    target_ports = list(range(20, 80))  # 60 ports probed in under 1 second

    for idx, dport in enumerate(target_ports):
        sport = 49152 + idx
        start = base_start
        end = base_start + 1
        lines.append(
            f"2 {account_id} {interface_id} {src_ip} {dst_ip} {sport} {dport} {protocol} 2 120 {start} {end} REJECT OK"
        )

    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def generate_aws_traffic_spike_fixture(filepath: Path) -> int:
    """
    Simulates a volumetric burst towards an AWS VPC web service on port 80.
    """
    lines = []
    account_id = "123456789012"
    interface_id = "eni-0a1b2c3d4e5f67891"
    src_ip = "198.51.100.22"  # External / Cloud IP
    dst_ip = "10.100.1.80"    # AWS VPC instance
    base_start = 1710000100
    protocol = 6  # TCP

    # 1500 packets across a short 2.0-second interval
    lines.append(
        f"2 {account_id} {interface_id} {src_ip} {dst_ip} 45000 80 {protocol} 1500 1350000 {base_start} {base_start + 2} ACCEPT OK"
    )

    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def generate_aws_benign_transit_fixture(filepath: Path) -> int:
    """
    Simulates standard benign hybrid cloud HTTPS application transit.
    """
    lines = []
    account_id = "123456789012"
    interface_id = "eni-0a1b2c3d4e5f67892"
    src_ip = "192.168.1.100"  # On-prem client
    dst_ip = "10.100.2.10"    # AWS VPC database/API
    base_start = 1710000200
    protocol = 6  # TCP

    lines.append(
        f"2 {account_id} {interface_id} {src_ip} {dst_ip} 52100 443 {protocol} 45 32000 {base_start} {base_start + 5} ACCEPT OK"
    )

    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def ensure_aws_sample_fixtures() -> List[AwsVpcSampleFixtureInfo]:
    """
    Ensures that default AWS VPC flow log benchmark fixtures exist on disk and returns their metadata.
    """
    AWS_FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    fixtures = [
        {
            "sample_id": "aws-port-scan-recon",
            "name": "AWS VPC Port Scan Reconnaissance",
            "filename": "aws_port_scan_recon_fixture.log",
            "description": "Multi-port reconnaissance probe across 25 destination ports targeting AWS VPC instance.",
            "generator": generate_aws_port_scan_fixture,
            "expected_threat": "PORT_SCAN",
        },
        {
            "sample_id": "aws-traffic-spike-burst",
            "name": "AWS VPC Volumetric HTTP Burst",
            "filename": "aws_volumetric_burst_fixture.log",
            "description": "Sudden 1500-packet throughput saturation event towards AWS VPC web service port 80.",
            "generator": generate_aws_traffic_spike_fixture,
            "expected_threat": "TRAFFIC_SPIKE",
        },
        {
            "sample_id": "aws-benign-transit",
            "name": "AWS VPC Benign Hybrid Transit",
            "filename": "aws_benign_transit_fixture.log",
            "description": "Standard TLS/HTTPS hybrid transit communication complying with expected baseline distributions.",
            "generator": generate_aws_benign_transit_fixture,
            "expected_threat": "BENIGN",
        },
    ]

    results: List[AwsVpcSampleFixtureInfo] = []

    for f in fixtures:
        target_path = AWS_FIXTURE_DIR / f["filename"]
        if not target_path.exists() or target_path.stat().st_size == 0:
            rec_count = f["generator"](target_path)
        else:
            rec_count = len([l for l in target_path.read_text(encoding="utf-8").splitlines() if l.strip()])

        size_bytes = target_path.stat().st_size if target_path.exists() else 0

        results.append(
            AwsVpcSampleFixtureInfo(
                sample_id=f["sample_id"],
                name=f["name"],
                filename=f["filename"],
                description=f["description"],
                record_count=rec_count,
                expected_threat=f["expected_threat"],
                file_size_bytes=size_bytes,
                telemetry_source="AWS_VPC_FLOW_LOG_FIXTURE",
            )
        )

    return results


def list_sample_fixtures() -> List[AwsVpcSampleFixtureInfo]:
    """Alias for ensure_aws_sample_fixtures."""
    return ensure_aws_sample_fixtures()


class SampleFixtureDetails:
    def __init__(self, info: AwsVpcSampleFixtureInfo, raw_content: str):
        self.info = info
        self.sample_id = info.sample_id
        self.name = info.name
        self.filename = info.filename
        self.description = info.description
        self.record_count = info.record_count
        self.expected_threat = info.expected_threat
        self.raw_content = raw_content


def get_sample_fixture(sample_id: str):
    """Returns sample fixture info and raw content."""
    samples = ensure_aws_sample_fixtures()
    for s in samples:
        if s.sample_id == sample_id:
            path = AWS_FIXTURE_DIR / s.filename
            if path.exists():
                return SampleFixtureDetails(s, path.read_text(encoding="utf-8"))
    return None

