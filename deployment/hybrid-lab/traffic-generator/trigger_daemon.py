"""
Trigger Daemon for Hybrid-Cloud Traffic Scenarios
=================================================
Watches /var/lib/hybrid-lab/telemetry/triggers/ for .req files.
Executes requested scenario and writes .res file.
"""
import json
import os
from pathlib import Path
import time
import traceback

from scenarios.scenario_benign import execute_scenario_benign
from scenarios.scenario_brute_force import execute_scenario_brute_force
from scenarios.scenario_containment import execute_scenario_containment
from scenarios.scenario_port_scan import execute_scenario_port_scan
from scenarios.scenario_suspicious_transfer import execute_scenario_suspicious_transfer
from scenarios.scenario_traffic_spike import execute_scenario_traffic_spike

TELEMETRY_DIR = Path(os.getenv("LAB_TELEMETRY_DIR", "/var/lib/hybrid-lab/telemetry"))
TRIGGERS_DIR = TELEMETRY_DIR / "triggers"

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


def main():
    TRIGGERS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[+] Traffic trigger daemon active on {TRIGGERS_DIR}")
    while True:
        try:
            req_files = list(TRIGGERS_DIR.glob("*.req"))
            for req_file in req_files:
                res_file = req_file.with_suffix(".res")
                if res_file.exists():
                    continue
                try:
                    data = json.loads(req_file.read_text(encoding="utf-8"))
                    scenario_name = data.get("scenario", "benign").strip().lower()
                    print(f"[*] Executing scenario trigger: {scenario_name}")
                    if scenario_name == "all":
                        results = []
                        for name in [
                            "benign",
                            "port_scan",
                            "brute_force",
                            "traffic_spike",
                            "suspicious_transfer",
                            "containment",
                        ]:
                            res = SCENARIO_DISPATCH[name](output_dir=TELEMETRY_DIR)
                            results.append(res)
                        output = {"success": True, "scenario": "all", "results": results}
                    elif scenario_name in SCENARIO_DISPATCH:
                        res = SCENARIO_DISPATCH[scenario_name](output_dir=TELEMETRY_DIR)
                        output = {"success": True, "scenario": scenario_name, "results": [res]}
                    else:
                        output = {"success": False, "error": f"Unknown scenario: {scenario_name}"}
                except Exception as ex:
                    output = {"success": False, "error": str(ex), "trace": traceback.format_exc()}

                res_file.write_text(json.dumps(output, indent=2), encoding="utf-8")
                try:
                    req_file.unlink()
                except Exception:
                    pass
        except Exception as e:
            print(f"[!] Error in trigger loop: {e}")
        time.sleep(0.5)


if __name__ == "__main__":
    main()

