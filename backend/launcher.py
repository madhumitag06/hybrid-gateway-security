"""
Standalone Backend Server Launcher & Infrastructure Orchestrator
===============================================================
Entry point for running the Adaptive AI-Powered Security Gateway backend,
supporting single-click PyInstaller standalone execution with Docker service
orchestration, database verification, dynamic port fallback, and browser launch.
"""

import argparse
import multiprocessing
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Optional, Tuple
import webbrowser

# -----------------------------------------------------------------------------
# 1. Windows Runtime DLL & OpenSSL Configuration (Must run before SSL imports)
# -----------------------------------------------------------------------------
def _configure_runtime_environment():
    """Configures DLL search paths and validates OpenSSL runtime dependencies."""
    is_frozen = getattr(sys, "frozen", False)
    if is_frozen:
        # In PyInstaller onedir mode, dependencies reside in sys._MEIPASS (_internal)
        bundle_dir = getattr(sys, "_MEIPASS", None)
        if not bundle_dir:
            bundle_dir = str(Path(sys.executable).resolve().parent / "_internal")

        bundle_path = Path(bundle_dir)
        if bundle_path.is_dir():
            # Python 3.8+ Windows DLL loading directory
            if hasattr(os, "add_dll_directory"):
                try:
                    os.add_dll_directory(str(bundle_path))
                except Exception as e:
                    print(f"[!] Warning: Failed to add bundle DLL directory: {e}")

            # Prepend bundle directory to PATH for C-extension transitive DLL search
            current_path = os.environ.get("PATH", "")
            if str(bundle_path) not in current_path:
                os.environ["PATH"] = str(bundle_path) + os.pathsep + current_path

    # Verify Python SSL runtime availability
    try:
        import ssl
        import _ssl  # noqa: F401
    except ImportError as ssl_err:
        print("==================================================================")
        print("[X] FATAL ERROR: Python SSL module failed to initialize!")
        print(f"    Detail: {ssl_err}")
        print("    Required libraries: libcrypto-3.dll, libssl-3.dll, _ssl.pyd")
        print("==================================================================")
        raise


_configure_runtime_environment()

# Ensure workspace root is in sys.path when invoked directly
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

import uvicorn
from backend.app.config import settings, get_env_file_path, get_frontend_dist_dir


def find_workspace_root() -> Path:
    """Discovers the active project root directory across development and frozen environments."""
    env_ws = os.getenv("WORKSPACE_ROOT")
    if env_ws and Path(env_ws).is_dir():
        return Path(env_ws).resolve()

    if getattr(sys, "frozen", False):
        exe_path = Path(sys.executable).resolve()
        for parent in [exe_path.parent, exe_path.parent.parent, exe_path.parent.parent.parent]:
            if (parent / "docker-compose.yml").is_file():
                return parent

    source_root = Path(__file__).resolve().parent.parent
    if (source_root / "docker-compose.yml").is_file():
        return source_root

    return Path.cwd().resolve()


def check_docker_engine() -> bool:
    """Verifies whether Docker Desktop daemon is accessible."""
    try:
        res = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=4,
        )
        return res.returncode == 0
    except Exception:
        return False


def get_container_info(container_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (status, health) for a container, or (None, None) if not found."""
    try:
        res = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode == 0 and res.stdout.strip():
            parts = res.stdout.strip().split("|")
            status = parts[0]
            health = parts[1] if len(parts) > 1 else "none"
            return status, health
    except Exception:
        pass
    return None, None


def wait_for_container_healthy(
    container_name: str, max_timeout_s: float = 15.0, interval_s: float = 1.0
) -> bool:
    """Polls container health until healthy, running (if no healthcheck), or timeout."""
    deadline = time.time() + max_timeout_s
    while time.time() < deadline:
        status, health = get_container_info(container_name)
        if status == "running":
            if health in ("healthy", "none"):
                return True
        time.sleep(interval_s)
    return False


def orchestrate_docker_infrastructure(workspace_root: Path, skip_docker: bool = False):
    """
    Verifies and starts required supporting Docker services:
    1. PostgreSQL database (gateway-postgres via docker-compose.yml)
    2. Hybrid-Lab traffic-generator (hybrid-lab-traffic-generator via deployment/hybrid-lab/compose.yaml)
    """
    if skip_docker:
        print("[*] Docker orchestration skipped by CLI configuration.")
        return

    print("[*] Checking Docker Desktop...")
    if not check_docker_engine():
        print("==================================================================")
        print("[!] NOTICE: Docker Desktop is not running or not accessible.")
        print("    - PostgreSQL persistence: Using configured fallback or local DB.")
        print("    - Traffic generator & Hybrid lab: Offline.")
        print("    - Offline PCAP ingestion, XGBoost V2 model inference, and CloudWatch")
        print("      read-only integrations remain fully operational.")
        print("    To enable live PostgreSQL persistence and attack simulation, launch Docker Desktop.")
        print("==================================================================")
        return

    print("[+] Docker Desktop is active.")
    root_compose = workspace_root / "docker-compose.yml"
    lab_compose = workspace_root / "deployment" / "hybrid-lab" / "compose.yaml"

    # 1. PostgreSQL (gateway-postgres)
    print("[*] Starting required infrastructure...")
    pg_status, pg_health = get_container_info("gateway-postgres")
    if pg_status != "running" and root_compose.is_file():
        print("[*] Launching PostgreSQL container ('gateway-postgres')...")
        try:
            subprocess.run(
                ["docker", "compose", "-f", str(root_compose), "up", "-d", "db"],
                cwd=str(workspace_root),
                capture_output=True,
                text=True,
                timeout=30,
            )
        except Exception as e:
            print(f"[!] Warning: Could not start PostgreSQL container via docker compose: {e}")

    print("[*] Waiting for PostgreSQL readiness...")
    if wait_for_container_healthy("gateway-postgres", max_timeout_s=15.0):
        print("[+] PostgreSQL container 'gateway-postgres' is ready (port 5434).")
    else:
        print("[!] PostgreSQL container did not report healthy within timeout. Connecting to backend...")

    # 2. Traffic Generator (hybrid-lab-traffic-generator)
    tg_status, tg_health = get_container_info("hybrid-lab-traffic-generator")
    if tg_status != "running" and lab_compose.is_file():
        print("[*] Launching traffic-generator container ('hybrid-lab-traffic-generator')...")
        try:
            subprocess.run(
                ["docker", "compose", "-f", str(lab_compose), "up", "-d", "traffic-generator"],
                cwd=str(workspace_root),
                capture_output=True,
                text=True,
                timeout=45,
            )
        except Exception as e:
            print(f"[!] Warning: Could not start traffic-generator container: {e}")

    print("[*] Waiting for traffic-generator readiness...")
    if wait_for_container_healthy("hybrid-lab-traffic-generator", max_timeout_s=15.0):
        print("[+] Traffic generator 'hybrid-lab-traffic-generator' is ready (port 8002).")
    else:
        print("[!] Traffic generator is still initializing or offline (hybrid lab will indicate status).")


def acquire_server_socket(host: str, preferred_port: int) -> Tuple[socket.socket, int]:
    """
    Attempts to bind and listen on the preferred port.
    If occupied, automatically discovers and binds to an available fallback port.
    Returns the active listening socket and the bound port number.
    """
    candidate_ports = [preferred_port]
    for fallback in [8080, 8081, 8000, 8001, 8888, 8889]:
        if fallback not in candidate_ports:
            candidate_ports.append(fallback)

    last_error = None
    for port in candidate_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            sock.listen(2048)
            return sock, port
        except OSError as e:
            last_error = e
            try:
                sock.close()
            except Exception:
                pass
            continue

    raise RuntimeError(
        f"Unable to bind to any candidate ports ({candidate_ports}) on {host}. "
        f"Last error: {last_error}"
    )


def launch_browser(url: str, delay: float = 1.2):
    """Opens the application URL in the user's default browser on a background thread."""
    if os.getenv("NO_BROWSER", "").lower() in ("1", "true", "yes"):
        print("[*] Automatic browser launch skipped (NO_BROWSER configured).")
        return

    def _open():
        time.sleep(delay)
        try:
            print(f"[*] Opening application URL in default browser...")
            webbrowser.open(url)
        except Exception as err:
            print(f"[!] Notice: Could not launch browser automatically: {err}")
            print(f"[*] Please open your browser and navigate to: {url}")

    thread = threading.Thread(target=_open, name="browser-launcher", daemon=True)
    thread.start()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Adaptive AI-Powered Security Gateway Backend Server"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=settings.host,
        help=f"Host address to bind to (default: {settings.host})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.port,
        help=f"Port number to bind to (default: {settings.port})",
    )
    parser.add_argument(
        "--env-file",
        type=str,
        default=None,
        help="Path to external .env configuration file",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        default=False,
        help="Do not open default web browser automatically upon startup",
    )
    parser.add_argument(
        "--no-docker",
        action="store_true",
        default=False,
        help="Skip automatic Docker Desktop service orchestration",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{settings.app_name} v{settings.app_version}",
    )
    return parser.parse_args()


def main():
    # Required for Windows multiprocessing/freeze support
    multiprocessing.freeze_support()

    args = parse_args()

    if args.no_browser:
        os.environ["NO_BROWSER"] = "1"

    if args.env_file:
        env_resolved = str(Path(args.env_file).resolve())
        os.environ["ENV_FILE"] = env_resolved
        # Re-instantiate settings with explicit env file override
        import backend.app.config
        backend.app.config.settings = backend.app.config.Settings()

    is_frozen = getattr(sys, "frozen", False)
    reload_enabled = False if is_frozen else settings.debug
    workspace_root = find_workspace_root()

    print("==================================================================")
    print(f" {settings.app_name} v{settings.app_version}")
    print("==================================================================")
    print("[*] Initializing packaged runtime...")
    print(f"[*] Mode: {'Standalone Executable' if is_frozen else 'Standard Python (Development)'}")
    print(f"[*] Workspace Root: {workspace_root}")
    print(f"[*] Environment file: {get_env_file_path()}")
    print(f"[*] Database target: {settings.database_url.split('@')[-1] if '@' in settings.database_url else settings.database_url}")
    print(f"[*] ML Artifacts directory: {settings.ml_artifacts_dir}")

    # Orchestrate Docker dependencies if available
    orchestrate_docker_infrastructure(workspace_root, skip_docker=args.no_docker)

    # Locate frontend distribution
    frontend_dir = get_frontend_dist_dir()
    if frontend_dir and (frontend_dir / "index.html").is_file():
        print(f"[*] Serving frontend assets: {frontend_dir}")
    else:
        print("[!] Frontend distribution: 'dist/index.html' not found (API only mode).")

    # Import FastAPI application (triggers model loading and database initialization in lifespan)
    print("[*] Loading ML models...")
    print("[*] Initializing application database...")
    from backend.app.main import app

    # Acquire and pre-bind server socket to eliminate port race conditions and bind crashes
    print("[*] Binding application port...")
    server_sock, active_port = acquire_server_socket(args.host, args.port)
    if active_port != args.port:
        print(f"[!] Target port {args.port} on {args.host} is occupied by another process.")
        print(f"[*] Automatically bound available fallback port: {active_port}")

    dashboard_host = "localhost" if args.host in ("0.0.0.0", "127.0.0.1") else args.host
    app_url = f"http://{dashboard_host}:{active_port}"

    print("==================================================================")
    print(f"[*] Opening application URL: {app_url}")
    print(f"[*] Unified Gateway Dashboard: {app_url}")
    print("==================================================================")
    print("[*] Gateway Server is listening. Press Ctrl+C in this console to stop.")
    print("==================================================================")

    # Launch browser automatically
    launch_browser(app_url, delay=1.2)

    config = uvicorn.Config(
        app=app,
        host=args.host,
        port=active_port,
        reload=reload_enabled,
        log_level="info",
        access_log=True,
        lifespan="on",
    )
    server = uvicorn.Server(config=config)

    try:
        server.run(sockets=[server_sock])
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Gateway server received shutdown signal.")
    finally:
        print("[*] Cleaning up gateway resources and sockets...")
        try:
            server_sock.close()
        except Exception:
            pass
        print("[*] Gateway server stopped cleanly.")


if __name__ == "__main__":
    try:
        main()
    except Exception as fatal_err:
        print(f"\n[X] FATAL ERROR DURING STARTUP: {fatal_err}")
        import traceback
        traceback.print_exc()
        if getattr(sys, "frozen", False):
            try:
                input("\nPress Enter to exit...")
            except Exception:
                pass
        sys.exit(1)
