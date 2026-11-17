# Executable Build & Synchronization Policy

## Mandatory Policy Statement
> **"Any frontend or backend source change requires a fresh production frontend build and PyInstaller executable rebuild before the task is considered complete."**

Under no circumstances should the project report a feature, fix, or enhancement as complete without verifying that the standalone Windows distribution (`AdaptiveSecurityGateway.exe`) has been regenerated and validated against the latest frontend bundles and backend logic.

---

## 1. Triggers Requiring Rebuild

The executable must be rebuilt whenever ANY of the following are modified:
1. **Frontend React components, pages, or views** (`src/**/*.tsx`, `src/**/*.ts`)
2. **Frontend styling or themes** (`src/**/*.css`)
3. **Frontend production assets** (`dist/**`)
4. **Backend Python code** (`backend/app/**/*.py`)
5. **FastAPI routing or endpoints** (`backend/app/api/**/*.py`)
6. **Authentication or user management** (`backend/app/services/auth_service.py`, `models/user.py`)
7. **Machine learning models or inference pipelines** (`ml/**/*.py`, `backend/app/services/ml_service.py`)
8. **Explainability or SHAP pipelines** (`backend/app/services/explainability_service.py`)
9. **Adaptive policy engine & rules** (`backend/app/services/policy_engine.py`)
10. **Database schemas or migrations** (`backend/alembic/**`, `backend/app/models/**`)
11. **Packaging specifications or environment configurations** (`AdaptiveSecurityGateway.spec`, `.env`)

---

## 2. Standard Automated Build Pipeline

Execute the master 17-point build script from the project root:

```powershell
powershell -ExecutionPolicy Bypass -File backend/build_exe.ps1
```

### The 17-Point Verification Sequence:
1. **Dependency Verification**: Confirms presence of Python virtual environment, PyInstaller, and Node dependencies.
2. **Frontend Dependencies**: Validates `node_modules` integrity.
3. **TypeScript Compilation**: Executes `npx tsc -b` with zero type errors.
4. **Production Build**: Executes `npm run build` to generate hashed bundles in `dist/`.
5. **HTML Integrity**: Validates `dist/index.html` presence and title tag.
6. **Asset Verification**: Verifies compiled `index-[hash].js` and `index-[hash].css`.
7. **Backend Testing**: Runs unit test suites (`pytest backend/tests/test_predict_api.py -q`).
8. **Lint Verification**: Executes `npm run lint` (`oxlint`) with zero errors.
9. **Safe Backup**: Preserves existing `AdaptiveSecurityGateway` in `AdaptiveSecurityGateway_backup` before overwriting.
10. **Process Safety**: Kills running instances to release Windows DLL/file locks (`_bcrypt.pyd`).
11. **PyInstaller Execution**: Compiles frozen bundle via `AdaptiveSecurityGateway.spec`.
12. **Data Bundling**: Bundles ML model pickles, Alembic migrations, database seeds, and frontend `dist/`.
13. **Frozen Resource Path Validation**: Ensures paths resolve via `sys._MEIPASS` or `_internal/dist`.
14. **Asset Matching**: Verifies that the JS and CSS hashes inside `_internal/dist/assets/` match the latest `dist/` build.
15. **File Metadata**: Inspects executable size (~35 MB) and LastWriteTime timestamp.
16. **CLI Self-Test**: Runs `AdaptiveSecurityGateway.exe --version` to confirm binary functionality.
17. **Build Report Generation**: Emits structured confirmation of build success.

---

## 3. Location of Build Artifacts

| Component | Path |
|---|---|
| **Standalone Executable** | `backend/executable/AdaptiveSecurityGateway/AdaptiveSecurityGateway.exe` |
| **Bundled Frontend Assets** | `backend/executable/AdaptiveSecurityGateway/_internal/dist/` |
| **Preserved Safety Backup** | `backend/executable/AdaptiveSecurityGateway_backup/` |
| **Packaging Spec** | `AdaptiveSecurityGateway.spec` |
| **Build Automation Script** | `backend/build_exe.ps1` |

---

## 4. Safety Guarantees
- **Never delete safety backups**: The previous executable is backed up to `AdaptiveSecurityGateway_backup/` and preserved.
- **Data Preservation**: Database records, Docker containers, volumes, PCAP files, and trained ML model artifacts are never wiped or reset during packaging.
- **Fail-Safe Rollback**: If PyInstaller or asset checks fail, the build script automatically restores the previous working executable from the backup.

