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
import threading
import time
import traceback
from typing import Any, Dict, List, Optional, Set, Tuple
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler

from scenarios.scenario_benign import execute_scenario_benign
from scenarios.scenario_brute_force import execute_scenario_brute_force
from scenarios.scenario_containment import execute_scenario_containment
from scenarios.scenario_port_scan import execute_scenario_port_scan
from scenarios.scenario_suspicious_transfer import execute_scenario_suspicious_transfer
from scenarios.scenario_traffic_spike import execute_scenario_traffic_spike

TELEMETRY_DIR = Path(os.getenv("LAB_TELEMETRY_DIR", "/var/lib/hybrid-lab/telemetry"))
TRIGGERS_DIR = TELEMETRY_DIR / "triggers"
HEARTBEAT_FILE = TRIGGERS_DIR / ".daemon_heartbeat.json"
DAEMON_START_TIME = time.time()
DAEMON_INITIALIZED = False
ACTIVE_LOCK = threading.Lock()
CURRENT_EXECUTION: Dict[str, Any] = {"active": False, "scenario": None, "started_at": None, "count": 0}

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


class TriggerHTTPHandler(BaseHTTPRequestHandler):
    """Multi-threaded dual-transport HTTP trigger listener on 0.0.0.0:8002 for fast, reliable scenario execution."""

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path in ("/health", "/status", "/"):
            with ACTIVE_LOCK:
                curr = dict(CURRENT_EXECUTION)
            
            if not DAEMON_INITIALIZED:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "INITIALIZING",
                    "ready": False,
                    "service": "hybrid-lab-traffic-generator",
                    "uptime_seconds": round(time.time() - DAEMON_START_TIME, 1),
                }).encode("utf-8"))
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            payload = {
                "status": "ONLINE",
                "ready": True,
                "service": "hybrid-lab-traffic-generator",
                "uptime_seconds": round(time.time() - DAEMON_START_TIME, 1),
                "is_executing": curr.get("active", False),
                "current_scenario": curr.get("scenario"),
                "total_scenarios_executed": curr.get("count", 0),
                "supported_scenarios": [
                    "benign", "port_scan", "traffic_spike",
                    "suspicious_transfer", "containment", "brute_force", "all"
                ],
                "timestamp": time.time(),
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()

    def do_POST(self):
        if self.path.startswith("/run"):
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            scenario_name = data.get("scenario", "benign").strip().lower()
            run_id = data.get("run_id", f"http_run_{scenario_name}_{int(time.time())}")

            # Validate scenario
            valid_scenarios = list(SCENARIO_DISPATCH.keys()) + ["all"]
            if scenario_name not in valid_scenarios:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                err_resp = {
                    "status": "INVALID_SCENARIO",
                    "success": False,
                    "run_id": run_id,
                    "scenario": scenario_name,
                    "error": f"Scenario '{scenario_name}' is not recognized. Valid choices: {sorted(list(set(SCENARIO_DISPATCH.keys())))}",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
                self.wfile.write(json.dumps(err_resp, indent=2).encode("utf-8"))
                return

            # Check concurrency / command rejected
            with ACTIVE_LOCK:
                if CURRENT_EXECUTION["active"]:
                    self.send_response(409)
                    self.send_header("Content-Type", "application/json")
                    self._send_cors_headers()
                    self.end_headers()
                    rej_resp = {
                        "status": "COMMAND_REJECTED",
                        "success": False,
                        "run_id": run_id,
                        "scenario": scenario_name,
                        "error": f"Scenario '{CURRENT_EXECUTION.get('scenario')}' is already executing in this daemon. Concurrency is bounded to 1 scenario.",
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                    }
                    self.wfile.write(json.dumps(rej_resp, indent=2).encode("utf-8"))
                    return

                CURRENT_EXECUTION["active"] = True
                CURRENT_EXECUTION["scenario"] = scenario_name
                CURRENT_EXECUTION["started_at"] = time.time()
                CURRENT_EXECUTION["count"] += 1

            ack_time = datetime.now(timezone.utc).isoformat()
            print(f"[*] HTTP request acknowledged to execute scenario: {scenario_name} (run_id: {run_id})")

            try:
                if scenario_name == "all":
                    results = []
                    for name in [
                        "benign", "port_scan", "brute_force",
                        "traffic_spike", "suspicious_transfer", "containment"
                    ]:
                        res = SCENARIO_DISPATCH[name](output_dir=TELEMETRY_DIR)
                        results.append(res)
                    output = {
                        "success": True,
                        "status": "COMPLETED",
                        "run_id": run_id,
                        "scenario": "all",
                        "results": results,
                        "acknowledged_at": ack_time,
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                    }
                elif scenario_name in SCENARIO_DISPATCH:
                    res = SCENARIO_DISPATCH[scenario_name](output_dir=TELEMETRY_DIR)
                    output = {
                        "success": True,
                        "status": "COMPLETED",
                        "run_id": run_id,
                        "scenario": scenario_name,
                        "results": [res],
                        "acknowledged_at": ack_time,
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                    }
                else:
                    output = {
                        "success": False,
                        "status": "INVALID_SCENARIO",
                        "run_id": run_id,
                        "error": f"Unknown scenario: {scenario_name}",
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                    }
                self.send_response(200 if output.get("success") else 400)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(output, indent=2).encode("utf-8"))
            except Exception as ex:
                err_payload = {
                    "success": False,
                    "status": "EXECUTION_FAILED",
                    "run_id": run_id,
                    "scenario": scenario_name,
                    "error": str(ex),
                    "acknowledged_at": ack_time,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(err_payload, indent=2).encode("utf-8"))
            finally:
                with ACTIVE_LOCK:
                    CURRENT_EXECUTION["active"] = False
                    CURRENT_EXECUTION["scenario"] = None
        else:
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()

    def log_message(self, format, *args):
        pass


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
    global DAEMON_INITIALIZED
    TRIGGERS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(TRIGGERS_DIR, 0o777)
    except Exception:
        pass
    update_heartbeat()

    # Start multi-threaded dual-transport HTTP trigger listener on port 8002
    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", 8002), TriggerHTTPHandler)
        http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        http_thread.start()
        DAEMON_INITIALIZED = True
        print("[+] Multi-threaded HTTP scenario trigger listener active on 0.0.0.0:8002")
    except Exception as e:
        print(f"[!] Warning: Could not bind HTTP trigger listener on port 8002: {e}")

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
