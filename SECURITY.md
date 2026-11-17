# Adaptive AI-Powered Security Gateway for Hybrid Cloud
## Enterprise Security Architecture, Cryptography & Threat Policy

**Version:** 1.0.0 (Production Release Candidate)  
**Security Standard:** NIST SP 800-53 Rev. 5 / OWASP Top 10:2021 Compliant  
**Security Posture:** Hardened Defense-in-Depth with AES-256-GCM Envelope Encryption  

---

# 1. Security Philosophy & Principles

The Adaptive Security Gateway is built upon three non-negotiable architectural tenets:
1. **Zero-Trust Multi-Cloud Telemetry**: All incoming network flow records are treated as untrusted and validated against strict schema boundaries before entering normalization pipelines.
2. **Cryptographic Protection of Secrets at Rest**: Cloud credentials, access tokens, and private keys are never stored in plaintext and never printed to log outputs.
3. **Strict Non-Mutating Cloud Visibility**: Probing cloud infrastructure (AWS, GCP, Azure) is strictly read-only. The gateway will never alter remote cloud security groups, modify IAM policies, or destroy cloud infrastructure.

---

# 2. Cryptographic Architecture

### 2.1 AES-256-GCM Envelope Credential Vault
- **Algorithm**: Advanced Encryption Standard in Galois/Counter Mode (`AES-256-GCM`).
- **Key Length**: 256 bits (32 bytes).
- **Initialization Vector (IV)**: 12-byte cryptographically secure random nonce generated per encryption event via `os.urandom(12)`. Nonces are never reused.
- **Authentication Tag**: 16-byte MAC tag verifying both confidentiality and integrity of the ciphertext.
- **Key Derivation (KDF)**: HKDF-SHA256 with constant context salt `hybrid-gateway-cloud-vault-v1` to derive subkeys from `CLOUD_CREDENTIAL_ENCRYPTION_KEY`.
- **Database Isolation**: The `cloud_credential_vault` table (Alembic revision `005`) stores only the IV, Auth Tag, Key Version, and Ciphertext. The unencrypted metadata resides separately in `cloud_accounts`.

### 2.2 User Authentication & JWT Session Security
- **Password Storage**: Passwords are salted and hashed using `bcrypt` (12 rounds).
- **Access Tokens**: Short-lived JSON Web Tokens (15-minute lifetime) signed with HMAC-SHA256.
- **Refresh Tokens**: Opaque random UUID tokens stored with database expiration timestamps. Replay detection revokes compromised sessions immediately.
- **RBAC Authorization**:
  - `admin`: Full administrative control, cloud onboarding, credential rotation, system reconfiguration.
  - `analyst`: Threat investigation, ML explainability inspection, scenario triggers, manual rule revocation.
  - `user`: Read-only dashboard inspection and telemetry observation.

---

# 3. Containment & Automated Defense Controls

### 3.1 Execution Modes
| Mode | Action Behavior | Safety Guarantee |
|---|---|---|
| `DRY_RUN` | Simulated Containment | Host network configurations and packet filters are never touched. All actions are logged and visualized safely. |
| `SANDBOX` | Containerized Isolation | Isolation rules are applied strictly within the isolated Docker bridge network. |
| `LIVE` | Active Enforcement | Deterministic packet drop or null-route applied via iptables / Linux netfilter. |

### 3.2 Time-To-Live (TTL) Automatic Rule Culling
To prevent permanent network partition or administrative lockout:
- Every active enforcement rule carries an explicit Time-To-Live (TTL) integer in seconds.
- A background worker polls active containment rules every 5 seconds.
- Rules whose `expires_at <= current_timestamp` are immediately decommissioned and transitioned to `EXPIRED`.

---

# 4. Threat Model & Mitigation Matrix (STRIDE)

| Threat Category | Potential Attack Vector | Platform Mitigation |
|---|---|---|
| **Spoofing** | Attacker impersonates gateway API or user | JWT authentication with HMAC-SHA256; STS ExternalId verification on AWS AssumeRole. |
| **Tampering** | Manipulation of flow logs or model weights | SHA-256 telemetry deduplication cache; model artifact checksum validation at startup. |
| **Repudiation** | User denies triggering attack scenario or rule | Immutable audit ledger logging all user actions, logins, rule creation, and rotation events. |
| **Information Disclosure** | Cloud credentials leaked via logs or errors | AES-256-GCM vault; credentials masked in API responses (`••••••••`); strict log redaction. |
| **Denial of Service** | Flow flood exhausting database connections | Asynchronous batch ingestion; micro-benchmarked feature extractors; connection pooling. |
| **Elevation of Privilege** | Standard user attempts account onboarding | Endpoint-level role-based access control (`require_role("admin")`). |

---

# 5. Vulnerability Disclosure & Audit Policy

To report security concerns or potential vulnerabilities:
1. Contact the Security Response Team privately.
2. Do not file public GitHub issues for security vulnerabilities.
3. Provide full reproduction steps, affected versions, and a proof of concept.
