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

import uvicorn
from backend.app.config import settings, get_env_file_path


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
        os.environ["ENV_FILE"] = str(Path(args.env_file).resolve())

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

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=reload_enabled,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
