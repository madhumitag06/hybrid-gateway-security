"""
Virtual Hybrid-Cloud Router Control & Telemetry Agent
=====================================================
Runs exclusively inside the isolated `lab-router` container on the internal management
interface (10.30.10.2:8099).

Responsibilities:
  1. Reports real IPv4 forwarding state, interface mapping, and iptables telemetry counters.
  2. Executes bounded packet capture (tcpdump) across the On-Prem <-> Cloud VPC boundary,
     saving PCAPs and capture metadata to the shared Docker volume.
  3. Enforces optional, strictly validated containment rules inside `lab-router`'s
     isolated `HYBRID_LAB_CONTAINMENT` iptables chain (never touching Windows host firewall).
"""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

MGMT_BIND_HOST = os.getenv("ROUTER_MGMT_BIND", "0.0.0.0")
MGMT_BIND_PORT = int(os.getenv("ROUTER_MGMT_PORT", os.getenv("ROUTER_AGENT_PORT", "8099")))
TELEMETRY_ROOT = Path(os.getenv("LAB_TELEMETRY_DIR", os.getenv("TELEMETRY_DIR", "/var/lib/hybrid-lab/telemetry")))
PCAP_DIR = TELEMETRY_ROOT / "pcaps"
META_DIR = TELEMETRY_ROOT / "metadata"

ALLOWED_LAB_NETS = [
    ipaddress.ip_network("10.10.10.0/24"),
    ipaddress.ip_network("10.20.10.0/24"),
]
PROTECTED_IPS = {
    "10.10.10.1",
    "10.10.10.2",
    "10.20.10.1",
    "10.20.10.2",
    "10.30.10.1",
    "10.30.10.2",
    "10.30.10.5",
    "10.30.10.10",
    "10.30.10.15",
    "10.30.10.20",
}

_lock = threading.RLock()
_active_rules: Dict[str, Dict[str, Any]] = {}


def is_valid_lab_target(ip_str: str) -> bool:
    if not ip_str or ip_str in PROTECTED_IPS:
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in ALLOWED_LAB_NETS)
    except ValueError:
        return False


def _build_rule_spec(target_ip: str, action: str, target_port: Optional[Any]) -> List[str]:
    spec = ["-s", target_ip.strip()]
    if action == "Restrict":
        effective_port = int(target_port) if target_port is not None and int(target_port) > 0 else 8080
        spec.extend(["-p", "tcp", "--dport", str(effective_port)])
    spec.extend(["-j", "DROP"])
    return spec


def _canonical_spec(target_ip: str, action: str, target_port: Optional[Any]) -> tuple:
    return tuple(_build_rule_spec(target_ip, action, target_port))


def _is_spec_referenced(spec_tuple: tuple, now_epoch: Optional[float] = None) -> bool:
    check_epoch = now_epoch if now_epoch is not None else time.time()
    for r_info in _active_rules.values():
        exp_epoch = float(r_info.get("expires_epoch", 0.0))
        if exp_epoch <= check_epoch:
            continue
        other_spec = _canonical_spec(
            str(r_info.get("target_ip", "")),
            str(r_info.get("action", "Block")),
            r_info.get("target_port"),
        )
        if other_spec == spec_tuple:
            return True
    return False


def _remove_iptables_spec(spec: List[str]) -> int:
    removed_count = 0
    del_cmd = ["iptables", "-D", "HYBRID_LAB_CONTAINMENT"] + spec
    for _ in range(20):
        res = subprocess.run(del_cmd, capture_output=True, text=True, check=False, timeout=3)
        if res.returncode != 0:
            break
        removed_count += 1
    return removed_count


def _reap_expired_rules() -> List[str]:
    now_epoch = time.time()
    expired_ids: List[str] = []
    expired_specs: List[tuple] = []
    with _lock:
        for r_id, r_info in list(_active_rules.items()):
            exp_epoch = float(r_info.get("expires_epoch", now_epoch + 300))
            if now_epoch >= exp_epoch:
                _active_rules.pop(r_id, None)
                spec_tuple = _canonical_spec(
                    str(r_info.get("target_ip", "")),
                    str(r_info.get("action", "Block")),
                    r_info.get("target_port"),
                )
                expired_specs.append(spec_tuple)
                expired_ids.append(r_id)

        for spec_tuple in dict.fromkeys(expired_specs):
            if not _is_spec_referenced(spec_tuple, now_epoch=now_epoch):
                _remove_iptables_spec(list(spec_tuple))

    return expired_ids


def _reap_expired_rules_loop() -> None:
    while True:
        try:
            _reap_expired_rules()
        except Exception:
            pass
        time.sleep(2.0)


def get_router_telemetry() -> Dict[str, Any]:
    _reap_expired_rules()
    ip_fwd = "0"
    try:
        ip_fwd = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8").strip()
    except Exception:
        pass

    interfaces_env = {}
    env_path = Path("/run/hybrid-router/interfaces.env")
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                interfaces_env[k.strip()] = v.strip()

    try:
        ipt_out = subprocess.check_output(
            ["iptables", "-L", "HYBRID_LAB_TELEMETRY", "-v", "-n", "-x"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=3,
        )
    except Exception as exc:
        ipt_out = f"unavailable: {exc}"

    try:
        containment_out = subprocess.check_output(
            ["iptables", "-L", "HYBRID_LAB_CONTAINMENT", "-v", "-n", "-x"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=3,
        )
    except Exception as exc:
        containment_out = f"unavailable: {exc}"

    with _lock:
        active_list = list(_active_rules.values())

    return {
        "status": "online",
        "service": "lab-router",
        "ip_forward_enabled": ip_fwd == "1",
        "interfaces": interfaces_env,
        "subnets": {
            "on_premises": "10.10.10.0/24 (gateway 10.10.10.2)",
            "cloud_vpc": "10.20.10.0/24 (gateway 10.20.10.2)",
            "management": "10.30.10.0/24 (control 10.30.10.2)",
        },
        "active_containment_rules": active_list,
        "telemetry_chain_counters": ipt_out,
        "containment_chain_counters": containment_out,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def apply_or_remove_firewall_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    _reap_expired_rules()
    operation = str(payload.get("operation", "ADD")).upper()
    rule_id = str(payload.get("rule_id", "rule-lab"))
    target_ip = str(payload.get("target_ip", "")).strip()
    action = str(payload.get("action", "Block"))
    target_port = payload.get("target_port")
    ttl_seconds = int(payload.get("ttl_seconds", 300))

    if not is_valid_lab_target(target_ip):
        return {
            "success": False,
            "error": f"Refused: target_ip '{target_ip}' is outside allowed virtual lab workload subnets.",
        }

    with _lock:
        if operation == "ADD":
            if ttl_seconds <= 0:
                return {
                    "success": False,
                    "error": f"Refused: rule '{rule_id}' has non-positive ttl_seconds ({ttl_seconds}); expired rules cannot be installed.",
                }
            if action not in ("Block", "Restrict"):
                return {
                    "success": True,
                    "operation": "SKIPPED",
                    "note": f"Action '{action}' does not install a blocking rule.",
                }
            effective_port = (
                int(target_port)
                if (action == "Restrict" and target_port is not None and int(target_port) > 0)
                else (8080 if action == "Restrict" else None)
            )
            spec = _build_rule_spec(target_ip, action, effective_port)
            chk_cmd = ["iptables", "-C", "HYBRID_LAB_CONTAINMENT"] + spec
            ins_cmd = ["iptables", "-I", "HYBRID_LAB_CONTAINMENT", "1"] + spec
            chk_res = subprocess.run(chk_cmd, capture_output=True, text=True, check=False, timeout=3)
            installed_new = False
            if chk_res.returncode != 0:
                subprocess.run(ins_cmd, check=False, timeout=3)
                installed_new = True
            now_dt = datetime.now(timezone.utc)
            now_epoch = time.time()
            _active_rules[rule_id] = {
                "rule_id": rule_id,
                "target_ip": target_ip,
                "action": action,
                "target_port": effective_port,
                "ttl_seconds": ttl_seconds,
                "applied_at": now_dt.isoformat(),
                "expires_epoch": now_epoch + ttl_seconds,
                "canonical_spec": list(spec),
                "cmd": " ".join(ins_cmd),
            }
            return {
                "success": True,
                "operation": "ADD",
                "installed_new_iptables_rule": installed_new,
                "rule": _active_rules[rule_id],
            }

        elif operation == "REMOVE":
            rule_info = _active_rules.pop(rule_id, None)
            eff_action = str(rule_info.get("action", action)) if rule_info else action
            eff_port = (
                rule_info.get("target_port")
                if rule_info
                else (target_port if eff_action == "Restrict" else None)
            )
            spec = _build_rule_spec(target_ip, eff_action, eff_port)
            spec_tuple = tuple(spec)
            still_referenced = _is_spec_referenced(spec_tuple)
            removed_copies = 0
            if not still_referenced:
                removed_copies = _remove_iptables_spec(spec)
            return {
                "success": True,
                "operation": "REMOVE",
                "removed": rule_info,
                "still_referenced": still_referenced,
                "iptables_entries_removed": removed_copies,
            }

    return {"success": False, "error": f"Unsupported operation '{operation}'"}


def run_bounded_capture(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes a bounded tcpdump capture on the router's interfaces for hybrid traffic
    between 10.10.10.0/24 and 10.20.10.0/24.
    """
    scenario = str(payload.get("scenario", "manual_capture")).replace("/", "_").replace("\\", "_")
    max_packets = min(max(int(payload.get("max_packets", 500)), 10), 5000)
    duration_sec = min(max(int(payload.get("duration_seconds", 8)), 1), 60)

    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    META_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"router_{scenario}_{ts}.pcap"
    pcap_path = PCAP_DIR / pcap_filename

    capture_if = "eth0"
    env_path = Path("/run/hybrid-router/interfaces.env")
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("ONPREM_IF=") and line.split("=", 1)[1].strip():
                capture_if = line.split("=", 1)[1].strip()
                break

    bpf_filter = "(net 10.10.10.0/24 and net 10.20.10.0/24)"
    cmd = [
        "timeout",
        str(duration_sec),
        "tcpdump",
        "-i",
        capture_if,
        "-nn",
        "-U",
        "-c",
        str(max_packets),
        "-w",
        str(pcap_path),
        bpf_filter,
    ]

    start_ts = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = round(time.time() - start_ts, 2)
    size_bytes = pcap_path.stat().st_size if pcap_path.exists() else 0

    meta = {
        "scenario": scenario,
        "pcap_filename": pcap_filename,
        "pcap_path": str(pcap_path),
        "capture_source": "lab-router-tcpdump",
        "bpf_filter": bpf_filter,
        "max_packets": max_packets,
        "duration_seconds": elapsed,
        "file_size_bytes": size_bytes,
        "stdout_stderr": (proc.stdout or "") + "\n" + (proc.stderr or ""),
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    meta_path = META_DIR / f"{pcap_filename}.meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


class RouterAgentHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, data: Dict[str, Any]) -> None:
        raw = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path in ("/health", "/api/health"):
            ip_fwd = "0"
            try:
                ip_fwd = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8").strip()
            except Exception:
                pass
            self._send_json(
                200,
                {
                    "status": "online",
                    "service": "lab-router",
                    "ip_forward_enabled": ip_fwd == "1",
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                },
            )
        elif self.path in ("/api/status", "/"):
            self._send_json(200, get_router_telemetry())
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        length = min(int(self.headers.get("Content-Length", "0")), 65536)
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = {}

        if self.path == "/api/firewall/rules":
            res = apply_or_remove_firewall_rule(body)
            self._send_json(200 if res.get("success") else 400, res)
        elif self.path in ("/api/capture", "/api/capture/pcap"):
            res = run_bounded_capture(body)
            self._send_json(200, res)
        else:
            self._send_json(404, {"error": "Unknown endpoint"})


def main() -> None:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    META_DIR.mkdir(parents=True, exist_ok=True)
    reaper = threading.Thread(target=_reap_expired_rules_loop, daemon=True)
    reaper.start()
    server = HTTPServer((MGMT_BIND_HOST, MGMT_BIND_PORT), RouterAgentHandler)
    print(f"[+] lab-router control agent listening on {MGMT_BIND_HOST}:{MGMT_BIND_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()

