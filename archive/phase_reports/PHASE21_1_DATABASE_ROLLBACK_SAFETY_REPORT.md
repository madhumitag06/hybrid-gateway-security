# Phase 21.1 — Database Rollback & Schema Migration Safety Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `madhumitag06/hybrid-gateway-security`  
**Branch:** `main`  
**Baseline Commit:** `f472588bb35c45031a8a28dec2d19d626ea58daf`  
**Execution Mode:** Controlled Migration Remediation & Non-Destructive Isolated Verification  
**Date:** November 16, 2026  

---

## 1. Executive Summary

During Phase 21 production acceptance analysis, an asymmetry was identified in Alembic revision `004_consolidated_enterprise_schema.py`:
- In `upgrade()`, table creation was guarded by inspection logic: if a table already existed (e.g. from an earlier bootstrap or initial schema), `op.create_table` was skipped.
- In `downgrade()`, however, the revision unconditionally executed `op.drop_table` for every table in its target list, regardless of whether revision `004` had created the table or whether it pre-existed.

In a rollback scenario on a database where enterprise tables were already present before applying revision `004`, this asymmetry would result in catastrophic data loss, deleting pre-existing tables and their production records.

Phase 21.1 designed, implemented, and empirically verified a zero-data-loss ownership tracking mechanism within Alembic revision `004`. All testing was executed against isolated disposable SQLite databases without impacting the production PostgreSQL database.

---

## 2. Root Cause Analysis & Vulnerability Mechanics

### 2.1 The Asymmetric Ownership Flaw
In the original implementation of `004_consolidated_enterprise_schema.py`:
```python
# Flawed upgrade pattern:
for table_name in target_tables:
    if table_name not in existing_tables:
        op.create_table(table_name, ...)

# Flawed downgrade pattern:
for table_name in reversed(target_tables):
    if table_name in current_tables:
        op.drop_table(table_name)  # Drops even if 004 did NOT create it!
```
Under this flaw:
1. If a production environment had tables created prior to revision `004` (such as `policy_audit_logs`, created in revision `001_initial_schema.py`), revision `004` skipped creating them during `upgrade()`.
2. If an administrator subsequently issued `alembic downgrade -1` (or downgraded to revision `003`), revision `004`'s `downgrade()` would drop `policy_audit_logs` and all associated audit records, corrupting the compliance trail.

---

## 3. Remediated Architecture: Dynamic Ownership Tracking

To eliminate the rollback destruction vulnerability while preserving idempotency, revision `004` was re-engineered to track table creation ownership dynamically via a dedicated internal tracking table: `_alembic_004_created_tables`.

### 3.1 Upgrade Implementation
```python
def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = set(insp.get_table_names())

    # Create internal tracking table if it does not exist
    if "_alembic_004_created_tables" not in existing_tables:
        op.create_table(
            "_alembic_004_created_tables",
            sa.Column("table_name", sa.String(64), primary_key=True),
        )

    # Track only newly created tables
    for table_name in target_tables:
        if table_name not in existing_tables:
            op.create_table(table_name, ...)
            op.execute(
                sa.text(
                    "INSERT INTO _alembic_004_created_tables (table_name) VALUES (:tbl)"
                ).bindparams(tbl=table_name)
            )
```

### 3.2 Downgrade Implementation
```python
def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing_tables = set(insp.get_table_names())

    # Query ownership table
    tables_to_drop = set()
    if "_alembic_004_created_tables" in existing_tables:
        result = bind.execute(sa.text("SELECT table_name FROM _alembic_004_created_tables")).fetchall()
        tables_to_drop = {row[0] for row in result}

    # Drop only tables that revision 004 created
    for table_name in reversed(target_tables):
        if table_name in existing_tables and table_name in tables_to_drop:
            op.drop_table(table_name)

    # Clean up tracking table
    if "_alembic_004_created_tables" in existing_tables:
        op.drop_table("_alembic_004_created_tables")
```

---

## 4. Empirical Test Verification

The ownership tracking logic was rigorously tested across three disposable database scenarios using `pytest` and direct Alembic CLI execution.

### Scenario 1: Clean Database Lifecycle (001 -> 004 -> 003)
- **Initial State**: Empty SQLite database initialized from revision base.
- **Upgraded to `004`**:
  - `policy_audit_logs` created in revision `001`.
  - Exactly 8 enterprise tables created by revision `004`: `users`, `active_enforcement_rules`, `shadow_predictions`, `cloud_accounts`, `cloud_network_resources`, `cloud_telemetry_checkpoints`, `adaptive_learning_feedbacks`, `adaptive_training_runs`.
  - `_alembic_004_created_tables` logged exactly 8 created tables.
- **Downgraded to `003`**:
  - Exactly the 8 tables created by revision `004` were dropped.
  - `policy_audit_logs` (created in revision `001`) was **preserved intact**.
  - Internal tracking table `_alembic_004_created_tables` was cleanly dropped.
- **Result**: **PASS**.

### Scenario 2: Fully Pre-Existing Enterprise Schema with Data
- **Initial State**: Pre-populated SQLite database containing all 9 tables with test records prior to running revision `004`.
- **Upgraded to `004`**:
  - Revision `004` inspected existing tables, recognized all 9 tables as pre-existing, and skipped `op.create_table` for all 9.
  - `_alembic_004_created_tables` logged 0 created tables.
- **Downgraded to `003`**:
  - Revision `004` queried `_alembic_004_created_tables` (empty set).
  - 0 tables were dropped.
  - All 9 pre-existing tables and 100% of their test data remained intact.
- **Result**: **PASS**.

### Scenario 3: Partial Pre-Existence with Mixed Ownership
- **Initial State**: Database where 3 tables (`users`, `active_enforcement_rules`, `policy_audit_logs`) pre-existed with sensitive operational records, while the remaining 6 tables did not exist.
- **Upgraded to `004`**:
  - 3 pre-existing tables skipped.
  - Exactly 6 new tables created and recorded in `_alembic_004_created_tables`.
- **Downgraded to `003`**:
  - Exactly the 6 newly created tables were dropped.
  - The 3 pre-existing tables and their operational records remained completely untouched.
- **Result**: **PASS**.

---

## 5. Live Production PostgreSQL Protection

- In accordance with Phase 21.1 safety constraints, no downgrade or destructive queries were run against the live PostgreSQL database (`hybrid_gateway_db` on port 5434).
- Live PostgreSQL migration status remains at revision `004` (head).
- The modified revision file is fully forward-compatible and guarantees that any future rollbacks in staging or production environments will adhere to safe ownership boundaries.

---

## 6. Verification Status

| Test Scenario | Scope | Expected Behavior | Observed Behavior | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | Clean DB | Drop only tables created by 004; preserve 001 tables | 8 tables dropped; `policy_audit_logs` preserved | **VERIFIED** |
| **Scenario 2** | Pre-existing All | 0 tables dropped; 100% data preservation | 0 tables dropped; all rows preserved | **VERIFIED** |
| **Scenario 3** | Partial Pre-existence | Drop only newly created tables; preserve pre-existing | 6 tables dropped; 3 pre-existing preserved | **VERIFIED** |
| **Live DB Safety** | Live PostgreSQL | Zero destructive operations | Untouched, running at head | **VERIFIED** |
