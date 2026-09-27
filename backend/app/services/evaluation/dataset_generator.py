"""
Evaluation Benchmark Dataset Generator
=======================================
Generates deterministic, ground-truth-labeled synthetic evaluation scenarios
across all 5 threat categories, operational edge cases, borderline flows,
and allowlisted administrative traffic using a fixed pseudo-random seed.
"""

import random
from typing import List, Optional
from backend.app.schemas.evaluation import BenchmarkScenario, SuiteNameType
from backend.app.schemas.predict import NetworkFlowRequest


class EvaluationDatasetGenerator:
    """
    Produces structured, reproducible test scenario suites for quantitative evaluation.
    """

    RANDOM_SEED: int = 42

    @classmethod
    def generate_suite(
        cls,
        suite_name: SuiteNameType = "FULL_BENCHMARK",
        sample_count: int = 200,
        seed: Optional[int] = None,
    ) -> List[BenchmarkScenario]:
        """
        Generates a deterministic list of BenchmarkScenario items for the requested suite.
        """
        rng = random.Random(seed if seed is not None else cls.RANDOM_SEED)
        scenarios: List[BenchmarkScenario] = []

        if suite_name == "BENIGN_SUITE":
            for i in range(sample_count):
                scenarios.append(cls._gen_benign(i, rng))
        elif suite_name == "RECON_SUITE":
            for i in range(sample_count):
                scenarios.append(cls._gen_port_scan(i, rng))
        elif suite_name == "BRUTE_FORCE_SUITE":
            for i in range(sample_count):
                scenarios.append(cls._gen_brute_force(i, rng))
        elif suite_name == "VOLUMETRIC_SUITE":
            for i in range(sample_count):
                scenarios.append(cls._gen_traffic_spike(i, rng))
        elif suite_name == "EVASION_BORDERLINE_SUITE":
            for i in range(sample_count):
                if i % 3 == 0:
                    scenarios.append(cls._gen_borderline_flow(i, rng))
                elif i % 3 == 1:
                    scenarios.append(cls._gen_allowlist_admin(i, rng))
                else:
                    scenarios.append(cls._gen_slow_recon(i, rng))
        else:  # FULL_BENCHMARK
            # Balanced distribution across classes and edge cases:
            # 30% Benign (including allowlisted), 20% Port Scan (fast & slow),
            # 20% Brute Force, 15% Traffic Spike, 10% Suspicious Transfer, 5% Borderline
            for i in range(sample_count):
                mod = i % 20
                if mod in [0, 1, 2, 3, 4]:
                    scenarios.append(cls._gen_benign(i, rng))
                elif mod == 5:
                    scenarios.append(cls._gen_allowlist_admin(i, rng))
                elif mod in [6, 7, 8]:
                    scenarios.append(cls._gen_port_scan(i, rng))
                elif mod == 9:
                    scenarios.append(cls._gen_slow_recon(i, rng))
                elif mod in [10, 11, 12, 13]:
                    scenarios.append(cls._gen_brute_force(i, rng))
                elif mod in [14, 15, 16]:
                    scenarios.append(cls._gen_traffic_spike(i, rng))
                elif mod in [17, 18]:
                    scenarios.append(cls._gen_suspicious_transfer(i, rng))
                else:
                    scenarios.append(cls._gen_borderline_flow(i, rng))

        return scenarios[:sample_count]

    @classmethod
    def _gen_benign(cls, idx: int, rng: random.Random) -> BenchmarkScenario:
        packets = rng.randint(15, 60)
        bytes_val = packets * rng.randint(400, 1200)
        duration = round(rng.uniform(1.0, 5.0), 2)
        rate = round(packets / duration, 2)
        dst_port = rng.choice([80, 443, 8080, 8443, 53])

        return BenchmarkScenario(
            scenario_id=f"scn-benign-{idx+1:04d}",
            ground_truth_class="BENIGN",
            expected_policy_intent="ALLOW",
            description="Standard interactive TLS/HTTP web browsing within normal statistical limits.",
            is_borderline=False,
            is_allowlisted=False,
            source_ip=f"192.168.1.{rng.randint(10, 200)}",
            destination_ip="10.100.0.1",
            flow=NetworkFlowRequest(
                packet_count=packets,
                byte_count=bytes_val,
                duration=duration,
                conn_rate=rate,
                dst_port=dst_port,
                unique_dst_ports=1,
                failed_auth_count=0,
            ),
        )

    @classmethod
    def _gen_allowlist_admin(cls, idx: int, rng: random.Random) -> BenchmarkScenario:
        packets = rng.randint(20, 50)
        bytes_val = packets * 300
        duration = round(rng.uniform(2.0, 8.0), 2)
        rate = round(packets / duration, 2)

        return BenchmarkScenario(
            scenario_id=f"scn-allowlist-{idx+1:04d}",
            ground_truth_class="BENIGN",
            expected_policy_intent="ALLOW",
            description="Legitimate administrative SSH session originating from protected management CIDR (192.168.1.1).",
            is_borderline=False,
            is_allowlisted=True,
            source_ip="192.168.1.1",  # Matches default management allowlist
            destination_ip="10.100.2.5",
            flow=NetworkFlowRequest(
                packet_count=packets,
                byte_count=bytes_val,
                duration=duration,
                conn_rate=rate,
                dst_port=22,
                unique_dst_ports=1,
                failed_auth_count=0,
            ),
        )

    @classmethod
    def _gen_port_scan(cls, idx: int, rng: random.Random) -> BenchmarkScenario:
        ports_count = rng.randint(25, 90)
        packets = rng.randint(2, 6)
        bytes_val = packets * 60
        duration = round(rng.uniform(0.04, 0.2), 3)
        rate = round(rng.uniform(90.0, 200.0), 2)
        dst_port = rng.choice([80, 8080, 443, 22, 3389, 8443])

        return BenchmarkScenario(
            scenario_id=f"scn-recon-fast-{idx+1:04d}",
            ground_truth_class="PORT_SCAN",
            expected_policy_intent="BLOCK",
            description="High-frequency multi-port reconnaissance probing numerous destination ports in rapid succession.",
            is_borderline=False,
            is_allowlisted=False,
            source_ip=f"192.168.1.{rng.randint(70, 99)}",
            destination_ip="10.100.4.12",
            flow=NetworkFlowRequest(
                packet_count=packets,
                byte_count=bytes_val,
                duration=duration,
                conn_rate=rate,
                dst_port=dst_port,
                unique_dst_ports=ports_count,
                failed_auth_count=0,
            ),
        )

    @classmethod
    def _gen_slow_recon(cls, idx: int, rng: random.Random) -> BenchmarkScenario:
        ports_count = rng.randint(18, 45)
        packets = rng.randint(2, 4)
        bytes_val = packets * 60
        duration = round(rng.uniform(1.5, 4.0), 2)
        rate = round(rng.uniform(2.0, 8.0), 2)  # Low rate designed to evade static connection rate threshold (<100)
        dst_port = rng.choice([80, 443, 8080])

        return BenchmarkScenario(
            scenario_id=f"scn-recon-slow-{idx+1:04d}",
            ground_truth_class="PORT_SCAN",
            expected_policy_intent="BLOCK",
            description="Low-rate stealth reconnaissance scanning multiple ports while keeping connection rate below static firewall thresholds.",
            is_borderline=False,
            is_allowlisted=False,
            source_ip=f"192.168.1.{rng.randint(110, 140)}",
            destination_ip="10.100.4.12",
            flow=NetworkFlowRequest(
                packet_count=packets,
                byte_count=bytes_val,
                duration=duration,
                conn_rate=rate,
                dst_port=dst_port,
                unique_dst_ports=ports_count,
                failed_auth_count=0,
            ),
        )

    @classmethod
    def _gen_brute_force(cls, idx: int, rng: random.Random) -> BenchmarkScenario:
        failed_auth = rng.randint(8, 25)
        packets = rng.randint(25, 60)
        bytes_val = packets * rng.randint(180, 300)
        duration = round(rng.uniform(1.2, 3.5), 2)
        rate = round(packets / duration, 2)
        dst_port = rng.choice([22, 3389, 21, 8080])

        return BenchmarkScenario(
            scenario_id=f"scn-bruteforce-{idx+1:04d}",
            ground_truth_class="BRUTE_FORCE",
            expected_policy_intent="BLOCK",
            description="Repetitive authentication failure surge on authentication service port indicating credential brute force.",
            is_borderline=False,
            is_allowlisted=False,
            source_ip=f"203.0.113.{rng.randint(20, 80)}",
            destination_ip="10.100.2.18",
            flow=NetworkFlowRequest(
                packet_count=packets,
                byte_count=bytes_val,
                duration=duration,
                conn_rate=rate,
                dst_port=dst_port,
                unique_dst_ports=1,
                failed_auth_count=failed_auth,
            ),
        )

    @classmethod
    def _gen_traffic_spike(cls, idx: int, rng: random.Random) -> BenchmarkScenario:
        packets = rng.randint(3500, 6000)
        bytes_val = packets * rng.randint(800, 1400)
        duration = round(rng.uniform(3.0, 6.0), 2)
        rate = round(packets / duration, 2)
        dst_port = rng.choice([80, 443, 8080])

        return BenchmarkScenario(
            scenario_id=f"scn-spike-{idx+1:04d}",
            ground_truth_class="TRAFFIC_SPIKE",
            expected_policy_intent="RESTRICT",
            description="Volumetric packet flood surge concentrating heavy throughput towards single destination endpoint.",
            is_borderline=False,
            is_allowlisted=False,
            source_ip=f"198.51.100.{rng.randint(10, 50)}",
            destination_ip="10.100.1.44",
            flow=NetworkFlowRequest(
                packet_count=packets,
                byte_count=bytes_val,
                duration=duration,
                conn_rate=rate,
                dst_port=dst_port,
                unique_dst_ports=1,
                failed_auth_count=0,
            ),
        )

    @classmethod
    def _gen_suspicious_transfer(cls, idx: int, rng: random.Random) -> BenchmarkScenario:
        packets = rng.randint(1000, 2000)
        bytes_val = packets * rng.randint(1200, 1800)
        duration = round(rng.uniform(90.0, 180.0), 2)
        rate = round(packets / duration, 2)
        dst_port = rng.choice([8443, 9000, 443])

        return BenchmarkScenario(
            scenario_id=f"scn-transfer-{idx+1:04d}",
            ground_truth_class="SUSPICIOUS_TRANSFER",
            expected_policy_intent="RESTRICT",
            description="Sustained long-duration large volume data stream exhibiting exfiltration transfer patterns.",
            is_borderline=False,
            is_allowlisted=False,
            source_ip=f"192.168.1.{rng.randint(150, 199)}",
            destination_ip="10.100.4.12",
            flow=NetworkFlowRequest(
                packet_count=packets,
                byte_count=bytes_val,
                duration=duration,
                conn_rate=rate,
                dst_port=dst_port,
                unique_dst_ports=1,
                failed_auth_count=0,
            ),
        )

    @classmethod
    def _gen_borderline_flow(cls, idx: int, rng: random.Random) -> BenchmarkScenario:
        # Borderline flows: alternating between ambiguous benign and sub-threshold threat patterns testing confidence gating
        is_threat_pattern = (idx % 2 == 1)
        if is_threat_pattern:
            packets = rng.randint(10, 16)
            bytes_val = packets * rng.randint(90, 120)
            duration = round(rng.uniform(0.6, 1.2), 2)
            rate = round(rng.uniform(25.0, 45.0), 2)
            dst_port = rng.choice([8080, 8443, 22])
            failed_auth = 2 if dst_port == 22 else 0
            unique_ports = rng.randint(8, 16) if dst_port != 22 else 1
            gt = "PORT_SCAN" if unique_ports > 1 else ("BRUTE_FORCE" if failed_auth > 0 else "BENIGN")
        else:
            packets = rng.randint(8, 14)
            bytes_val = packets * rng.randint(80, 140)
            duration = round(rng.uniform(0.7, 1.4), 2)
            rate = round(packets / duration, 2)
            dst_port = rng.choice([8080, 8443, 3000])
            failed_auth = 0
            unique_ports = rng.randint(3, 7)
            gt = "BENIGN"

        return BenchmarkScenario(
            scenario_id=f"scn-borderline-{idx+1:04d}",
            ground_truth_class=gt,
            expected_policy_intent="MONITOR",
            description="Ambiguous flow with borderline statistical features designed to test confidence gating.",
            is_borderline=True,
            is_allowlisted=False,
            source_ip=f"192.0.2.{rng.randint(50, 70)}",
            destination_ip="10.100.3.20",
            flow=NetworkFlowRequest(
                packet_count=packets,
                byte_count=bytes_val,
                duration=duration,
                conn_rate=rate,
                dst_port=dst_port,
                unique_dst_ports=unique_ports,
                failed_auth_count=failed_auth,
            ),
        )
