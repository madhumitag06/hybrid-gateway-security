# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Build Specification
===============================
Packages the Adaptive AI-Powered Security Gateway backend into a standalone executable.
Includes pre-trained ML artifacts, FastAPI application routers, database drivers, and scikit-learn.
"""

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None
WORKSPACE_ROOT = Path(os.path.abspath(".")).resolve()

# 1. Collect Data Files
datas = [
    (str(WORKSPACE_ROOT / "ml" / "models"), "ml/models"),
    (str(WORKSPACE_ROOT / "backend" / "alembic"), "backend/alembic"),
]

# 2. Collect Hidden Imports
hidden_imports = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespans",
    "uvicorn.lifespans.on",
    "pydantic",
    "pydantic_settings",
    "pydantic_settings.sources",
    "pydantic_settings.sources.providers",
    "pydantic_settings.sources.providers.env",
    "sqlalchemy",
    "sqlalchemy.dialects.postgresql",
    "psycopg",
    "psycopg_binary",
    "scapy",
    "scapy.layers.inet",
    "scapy.layers.l2",
    "sklearn",
    "sklearn.ensemble",
    "sklearn.tree",
    "sklearn.preprocessing",
    "joblib",
    "shap",
    "numpy",
    "scipy",
    "bcrypt",
    "jwt",
    "backend",
    "backend.app",
    "backend.app.main",
    "backend.app.config",
    "backend.app.core.security",
    "backend.app.db.session",
    "backend.app.db.base",
    "backend.app.models",
    "backend.app.models.user",
    "backend.app.models.event",
    "backend.app.models.rule",
    "backend.app.models.evaluation",
    "backend.app.models.analytics",
    "backend.app.services.auth_service",
    "backend.app.services.ml_service",
    "backend.app.services.enforcement_service",
    "backend.app.services.dashboard_service",
    "backend.app.services.policy_engine",
    "backend.app.services.ingestion_service",
    "backend.app.services.copilot_service",
    "backend.app.services.aws_telemetry_client",
    "backend.app.repositories.user_repo",
    "backend.app.api.deps",
    "backend.app.api.health",
    "backend.app.api.v1.auth",
    "backend.app.api.v1.predict",
    "backend.app.api.v1.events",
    "backend.app.api.v1.ingest",
    "backend.app.api.v1.enforcement",
    "backend.app.api.v1.hybrid",
    "backend.app.api.v1.analytics",
    "backend.app.api.v1.evaluation",
    "backend.app.api.v1.dashboard",
]

a = Analysis(
    [str(WORKSPACE_ROOT / "backend" / "launcher.py")],
    pathex=[str(WORKSPACE_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "IPython", "jupyter"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AdaptiveSecurityGateway",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="AdaptiveSecurityGateway",
)
