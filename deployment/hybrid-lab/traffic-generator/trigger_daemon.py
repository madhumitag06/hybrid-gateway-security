"""
Trigger Daemon for Hybrid-Cloud Traffic Scenarios
=================================================
Watches /var/lib/hybrid-lab/telemetry/triggers/ for .req files.
Maintains daemon heartbeat, tracks execution states (RUNNING, COMPLETED, FAILED),
executes requested scenarios safely within isolated lab subnets, and writes .res files.
"""

from datetime import datetime, timezone
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
HEARTBEAT_FILE = TRIGGERS_DIR / ".daemon_heartbeat.json"

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


def update_heartbeat() -> None:
    """Updates daemon liveness heartbeat file for health reporting and trigger coordinators."""
    try:
        data = {
            "pid": os.getpid(),
            "heartbeat_at": datetime.now(timezone.utc).isoformat(),
            "timestamp": time.time(),
            "status": "ONLINE",
        }
        temp_file = HEARTBEAT_FILE.with_suffix(".tmp")
        temp_file.write_text(json.dumps(data), encoding="utf-8")
        try:
            os.chmod(temp_file, 0o666)
        except Exception:
            pass
        temp_file.replace(HEARTBEAT_FILE)
    except Exception:
        pass


def main():
    TRIGGERS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(TRIGGERS_DIR, 0o777)
    except Exception:
        pass
    update_heartbeat()
    print(f"[+] Traffic trigger daemon active on {TRIGGERS_DIR}")
    last_hb_time = time.time()

    while True:
        try:
            # Heartbeat update every 2 seconds
            if time.time() - last_hb_time >= 2.0:
                update_heartbeat()
                last_hb_time = time.time()

            req_files = list(TRIGGERS_DIR.glob("*.req"))
            for req_file in req_files:
                res_file = req_file.with_suffix(".res")
                run_file = req_file.with_suffix(".run")

                if res_file.exists():
                    continue

                scenario_name = "benign"
                try:
                    data = json.loads(req_file.read_text(encoding="utf-8"))
                    scenario_name = data.get("scenario", "benign").strip().lower()

                    # Record running state
                    run_payload = {
                        "status": "RUNNING",
                        "scenario": scenario_name,
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "pid": os.getpid(),
                    }
                    tmp_run = run_file.with_suffix(".tmp")
                    tmp_run.write_text(json.dumps(run_payload), encoding="utf-8")
                    try:
                        os.chmod(tmp_run, 0o666)
                    except Exception:
                        pass
                    tmp_run.replace(run_file)
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
                        output = {
                            "success": True,
                            "status": "COMPLETED",
                            "scenario": "all",
                            "results": results,
                            "completed_at": datetime.now(timezone.utc).isoformat(),
                        }
                    elif scenario_name in SCENARIO_DISPATCH:
                        res = SCENARIO_DISPATCH[scenario_name](output_dir=TELEMETRY_DIR)
                        output = {
                            "success": True,
                            "status": "COMPLETED",
                            "scenario": scenario_name,
                            "results": [res],
                            "completed_at": datetime.now(timezone.utc).isoformat(),
                        }
                    else:
                        output = {
                            "success": False,
                            "status": "FAILED",
                            "error": f"Unknown scenario: {scenario_name}",
                            "completed_at": datetime.now(timezone.utc).isoformat(),
                        }
                except Exception as ex:
                    output = {
                        "success": False,
                        "status": "FAILED",
                        "scenario": scenario_name,
                        "error": str(ex),
                        "trace": traceback.format_exc(),
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                    }

                # Write response atomically
                tmp_res = res_file.with_suffix(".tmp")
                tmp_res.write_text(json.dumps(output, indent=2), encoding="utf-8")
                try:
                    os.chmod(tmp_res, 0o666)
                except Exception:
                    pass
                tmp_res.replace(res_file)

                # Clean up .req and .run markers
                run_file.unlink(missing_ok=True)
                req_file.unlink(missing_ok=True)

        except Exception as e:
            print(f"[!] Error in trigger loop: {e}")

        time.sleep(0.3)


if __name__ == "__main__":
    main()
