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
    (str(WORKSPACE_ROOT / "dist"), "dist"),
    (str(WORKSPACE_ROOT / "ml" / "models"), "ml/models"),
    (str(WORKSPACE_ROOT / "backend" / "alembic"), "backend/alembic"),
    (str(WORKSPACE_ROOT / "backend" / "app" / "data"), "backend/app/data"),
]
datas += collect_data_files("shap")

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
    "fastapi",
    "fastapi.middleware",
    "fastapi.middleware.cors",
    "fastapi.staticfiles",
    "starlette",
    "starlette.concurrency",
    "starlette.middleware",
    "starlette.middleware.cors",
    "starlette.responses",
    "starlette.staticfiles",
    "pydantic",
    "pydantic_settings",
    "pydantic_settings.sources",
    "pydantic_settings.sources.providers",
    "pydantic_settings.sources.providers.env",
    "sqlalchemy",
    "sqlalchemy.dialects.postgresql",
    "psycopg",
    "psycopg_binary",
    "httpx",
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
    "multipart",
    "python_multipart",
]

# Collect all backend.app, ml, and shap submodules dynamically
hidden_imports += collect_submodules("backend.app")
hidden_imports += collect_submodules("ml")
hidden_imports += collect_submodules("shap")

# Ensure unique entries
hidden_imports = sorted(list(set(hidden_imports)))

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
