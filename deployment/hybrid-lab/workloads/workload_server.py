"""
Virtual Hybrid-Cloud Workload & Service Endpoint Emulator
=========================================================
Runs inside isolated on-premises (10.10.10.0/24) and simulated cloud VPC (10.20.10.0/24)
containers to provide real HTTP and TCP service endpoints across the virtual gateway.
"""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import threading
import time
from typing import List

NODE_NAME = os.getenv("NODE_NAME", "hybrid-workload")
NODE_ZONE = os.getenv("NODE_ZONE", "ON_PREMISE")
NODE_ROLE = os.getenv("NODE_ROLE", "application-workload")
NODE_IP = os.getenv("NODE_IP", "0.0.0.0")
HTTP_PORT_RAW = os.getenv("HTTP_PORT", "8080")
TCP_PORTS_RAW = os.getenv("TCP_PORTS", "")
SERVICE_PORTS_RAW = os.getenv("SERVICE_PORTS", "")
HEALTH_FILE = Path("/tmp/workload_healthy")

_running = True


class HybridWorkloadHTTPHandler(BaseHTTPRequestHandler):
    server_version = "HybridLabWorkload/1.0"

    def log_message(self, format: str, *args) -> None:
        print(
            f"[{NODE_NAME}][HTTP:{self.server.server_port}] "
            f"{self.client_address[0]}:{self.client_address[1]} - {format % args}"
        )

    def _send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Hybrid-Node", NODE_NAME)
        self.send_header("X-Hybrid-Zone", NODE_ZONE)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._send_json(
            200,
            {
                "status": "online",
                "node_name": NODE_NAME,
                "node_zone": NODE_ZONE,
                "node_role": NODE_ROLE,
                "node_ip": NODE_IP,
                "listening_port": self.server.server_port,
                "client_ip": self.client_address[0],
                "path": self.path,
                "simulated_environment": True,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            },
        )

    def do_POST(self) -> None:
        content_len = min(int(self.headers.get("Content-Length", "0")), 2 * 1024 * 1024)
        data = self.rfile.read(content_len) if content_len > 0 else b""
        self._send_json(
            200,
            {
                "status": "received",
                "node_name": NODE_NAME,
                "node_zone": NODE_ZONE,
                "bytes_received": len(data),
                "client_ip": self.client_address[0],
                "listening_port": self.server.server_port,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            },
        )


def _start_http_listener(port: int) -> None:
    server = HTTPServer(("0.0.0.0", port), HybridWorkloadHTTPHandler)
    print(f"[+] [{NODE_NAME}] HTTP service listening on 0.0.0.0:{port} ({NODE_ZONE})")
    server.serve_forever()


def _start_tcp_db_listener(port: int) -> None:
    """
    Lightweight TCP responder for simulated database / binary ports (e.g., 5432).
    Accepts bounded connections and returns a deterministic banner without resource leaks.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(32)
    print(f"[+] [{NODE_NAME}] TCP service listening on 0.0.0.0:{port} ({NODE_ZONE})")

    while _running:
        try:
            conn, addr = sock.accept()
            conn.settimeout(3.0)
            try:
                _ = conn.recv(4096)
                banner = json.dumps(
                    {
                        "service": NODE_NAME,
                        "zone": NODE_ZONE,
                        "role": NODE_ROLE,
                        "port": port,
                        "client": addr[0],
                        "note": "Simulated Cloud VPC Private Database Endpoint",
                    }
                ).encode("utf-8")
                conn.sendall(banner + b"\n")
            except Exception:
                pass
            finally:
                conn.close()
        except Exception:
            time.sleep(0.1)


def parse_ports(raw: str) -> List[int]:
    ports: List[int] = []
    for part in raw.split(","):
        p = part.strip()
        if p.isdigit():
            val = int(p)
            if 1 <= val <= 65535:
                ports.append(val)
    return ports


def main() -> None:
    combined_raw = ",".join(filter(None, [HTTP_PORT_RAW, TCP_PORTS_RAW, SERVICE_PORTS_RAW]))
    ports = sorted(list(set(parse_ports(combined_raw))))
    for port in ports:
        if port in (5432, 3306, 6379):
            t = threading.Thread(target=_start_tcp_db_listener, args=(port,), daemon=True)
        else:
            t = threading.Thread(target=_start_http_listener, args=(port,), daemon=True)
        t.start()

    HEALTH_FILE.write_text(
        json.dumps(
            {
                "node": NODE_NAME,
                "zone": NODE_ZONE,
                "role": NODE_ROLE,
                "ip": NODE_IP,
                "ports": ports,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    print(f"[+] [{NODE_NAME}] Ready. Active ports: {ports if ports else 'client-only'}")

    def _handle_sig(signum, frame):
        global _running
        _running = False

    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)

    while _running:
        time.sleep(2.0)


if __name__ == "__main__":
    main()

