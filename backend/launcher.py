"""
Standalone Backend Server Launcher
==================================
Entry point for running the Adaptive AI-Powered Security Gateway backend,
supporting both standard CLI invocation and packaged PyInstaller standalone execution.
"""

import argparse
import multiprocessing
import os
from pathlib import Path
import sys

# Ensure workspace root is in sys.path when invoked directly
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

import socket
import uvicorn
from backend.app.config import settings, get_env_file_path


def is_port_available(host: str, port: int) -> bool:
    """Pre-flight check to verify if a socket can be bound on host:port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            s.bind((host, port))
            return True
    except OSError:
        return False


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
        "--version",
        action="version",
        version=f"{settings.app_name} v{settings.app_version}",
    )
    return parser.parse_args()


def main():
    # Required for Windows multiprocessing/freeze support
    multiprocessing.freeze_support()

    args = parse_args()

    if args.env_file:
        env_resolved = str(Path(args.env_file).resolve())
        os.environ["ENV_FILE"] = env_resolved
        # Re-instantiate settings with explicit env file override
        import backend.app.config
        backend.app.config.settings = backend.app.config.Settings()

    # In packaged production executable, reload must be disabled
    is_frozen = getattr(sys, "frozen", False)
    reload_enabled = False if is_frozen else settings.debug

    # Import app
    from backend.app.main import app

    print("==================================================================")
    print(f" {settings.app_name} v{settings.app_version}")
    print("==================================================================")
    print(f"[*] Binding host: {args.host}:{args.port}")
    print(f"[*] Environment file: {get_env_file_path()}")
    print(f"[*] Mode: {'Standalone Executable' if is_frozen else 'Standard Python'}")
    print(f"[*] Database: {settings.database_url.split('@')[-1] if '@' in settings.database_url else settings.database_url}")
    print(f"[*] ML Artifacts: {settings.ml_artifacts_dir}")
    print("==================================================================")

    target_port = args.port
    if not is_port_available(args.host, target_port):
        print(f"[!] WARNING: Target port {target_port} on {args.host} is occupied by another process or container!")
        fallback_port = 8080 if target_port == 8000 else target_port + 1
        if is_port_available(args.host, fallback_port):
            print(f"[*] Automatically selecting available fallback port {fallback_port}...")
            target_port = fallback_port
        else:
            print(f"[!] Warning: Fallback port {fallback_port} also occupied.")

    dashboard_host = "localhost" if args.host in ("0.0.0.0", "127.0.0.1") else args.host
    print(f"[*] Unified Gateway Dashboard: http://{dashboard_host}:{target_port}")
    print("==================================================================")

    try:
        uvicorn.run(
            app,
            host=args.host,
            port=target_port,
            reload=reload_enabled,
            log_level="info",
            access_log=True,
        )
    except OSError as e:
        err_msg = str(e).lower()
        if "10048" in err_msg or "already in use" in err_msg or "address already in use" in err_msg:
            fallback_port = 8080 if target_port == 8000 else target_port + 1
            print(f"[!] Notice: Port {target_port} is occupied by another process or container.")
            print(f"[*] Launching on fallback port {fallback_port} (http://{args.host}:{fallback_port})...")
            uvicorn.run(
                app,
                host=args.host,
                port=fallback_port,
                reload=reload_enabled,
                log_level="info",
                access_log=True,
            )
        else:
            raise


if __name__ == "__main__":
    main()
