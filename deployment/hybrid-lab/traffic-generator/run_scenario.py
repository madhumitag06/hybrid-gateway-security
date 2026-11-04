"""
CLI Runner for Controlled Hybrid-Cloud Traffic Scenarios
========================================================
Usage inside `traffic-generator` container:
  python3 /app/run_scenario.py --scenario all
  python3 /app/run_scenario.py --scenario benign
  python3 /app/run_scenario.py --scenario port_scan
  python3 /app/run_scenario.py --scenario traffic_spike
  python3 /app/run_scenario.py --scenario suspicious_transfer
  python3 /app/run_scenario.py --scenario containment
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from scenarios.scenario_benign import execute_scenario_benign
from scenarios.scenario_brute_force import execute_scenario_brute_force
from scenarios.scenario_containment import execute_scenario_containment
from scenarios.scenario_port_scan import execute_scenario_port_scan
from scenarios.scenario_suspicious_transfer import execute_scenario_suspicious_transfer
from scenarios.scenario_traffic_spike import execute_scenario_traffic_spike

DEFAULT_OUTPUT_DIR = Path(os.getenv("LAB_TELEMETRY_DIR", "/var/lib/hybrid-lab/telemetry"))

SCENARIO_DISPATCH = {
    "1": execute_scenario_benign,
    "benign": execute_scenario_benign,
    "2": execute_scenario_port_scan,
    "port_scan": execute_scenario_port_scan,
    "3": execute_scenario_traffic_spike,
    "traffic_spike": execute_scenario_traffic_spike,
    "4": execute_scenario_suspicious_transfer,
    "suspicious_transfer": execute_scenario_suspicious_transfer,
    "5": execute_scenario_containment,
    "containment": execute_scenario_containment,
    "6": execute_scenario_brute_force,
    "brute_force": execute_scenario_brute_force,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute isolated hybrid-cloud traffic scenario")
    parser.add_argument(
        "--scenario",
        default="benign",
        help="Scenario to run: benign (1), port_scan (2), traffic_spike (3), suspicious_transfer (4), containment (5), brute_force (6), or all",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Telemetry output directory",
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    key = args.scenario.strip().lower()

    results: List[Dict[str, Any]] = []
    if key == "all":
        for name in ["benign", "port_scan", "brute_force", "traffic_spike", "suspicious_transfer", "containment"]:
            res = SCENARIO_DISPATCH[name](output_dir=out_dir)
            results.append(res)
    elif key in SCENARIO_DISPATCH:
        res = SCENARIO_DISPATCH[key](output_dir=out_dir)
        results.append(res)
    else:
        raise SystemExit(
            f"Unknown scenario '{args.scenario}'. Valid choices: {sorted(list(SCENARIO_DISPATCH.keys())) + ['all']}"
        )

    print(json.dumps({"executed_scenarios": len(results), "results": results}, indent=2))


if __name__ == "__main__":
    main()

