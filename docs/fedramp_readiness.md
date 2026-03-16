# FedRAMP Readiness Assessment

This document outlines NanoMask's current compliance posture relative to NIST SP 800-53 Rev. 5 control families, identifies controls that NanoMask satisfies natively versus controls that are the responsibility of the deploying organization, and describes the path to FedRAMP authorization.

---

## Authorization Path

### FedRAMP Tailored (Li-SaaS) vs. Moderate

NanoMask is a self-hosted software product, not a hosted SaaS offering. FedRAMP authorization applies when NanoMask is deployed as part of a cloud service offering by a Cloud Service Provider (CSP).

| Path | Applicability | Notes |
|------|--------------|-------|
| **FedRAMP Tailored (Li-SaaS)** | If NanoMask is offered as a low-impact SaaS add-on | Reduced control baseline; faster authorization |
| **FedRAMP Moderate** | If NanoMask processes CUI or moderate-impact data | Full 325-control baseline; 3PA required |
| **Self-hosted (no FedRAMP)** | If the agency deploys NanoMask in their own ATO boundary | NanoMask inherits the agency's existing ATO; no separate FedRAMP package needed |

**Recommended initial path**: Self-hosted deployment within an agency's existing ATO boundary. The agency evaluates NanoMask as a component, not a standalone cloud service. This avoids the cost and timeline of a full FedRAMP authorization while still requiring the controls documented below.

---

## NIST SP 800-53 Control Family Mapping

### Legend

- ✅ **NanoMask provides**: The software natively implements or directly supports this control.
- 🔶 **Shared responsibility**: NanoMask provides features that support the control, but the deploying organization must configure and operate them.
- ❌ **Customer provides**: The control is entirely the responsibility of the deploying organization or infrastructure.

---

### AC — Access Control

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| AC-2 | Account management | ❌ Customer | NanoMask does not manage user accounts. Admin API uses a shared token. |
| AC-3 | Access enforcement | 🔶 Shared | Admin API: Bearer token auth, IP allowlist, read-only mode, rate limiting. Proxy: no client auth (by design). |
| AC-6 | Least privilege | 🔶 Shared | Admin read-only mode, dedicated admin listener, mutation rate limiting. Container runs as non-root (UID 65534). |
| AC-7 | Unsuccessful login attempts | 🔶 Shared | Admin mutation rate limiter returns HTTP 429. No account lockout (single token model). |
| AC-17 | Remote access | ❌ Customer | Network-level controls (firewall, VPN, service mesh) are external to NanoMask. |

### AU — Audit And Accountability

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| AU-2 | Audit events | ✅ NanoMask | Structured NDJSON logging: request lifecycle, redaction events, admin mutations, response forwarding mode. |
| AU-3 | Content of audit records | ✅ NanoMask | Timestamps, session IDs, event types, stages, match types, field paths, action types, outcome. PHI values never logged. |
| AU-6 | Audit review, analysis, reporting | ❌ Customer | NanoMask emits structured logs; SIEM integration, review, and alerting are the customer's responsibility. |
| AU-8 | Time stamps | ✅ NanoMask | Nanosecond-precision timestamps in every log line. |
| AU-9 | Protection of audit information | ❌ Customer | Log file permissions, log pipeline security, and retention are external to NanoMask. |
| AU-12 | Audit generation | ✅ NanoMask | Configurable via `--audit-log`. Per-request cap at 256 events to prevent log flooding. |

### CA — Assessment, Authorization, And Monitoring

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| CA-2 | Control assessments | ❌ Customer | Customer performs control assessments as part of their ATO process. |
| CA-7 | Continuous monitoring | 🔶 Shared | NanoMask exposes `/metrics` (Prometheus), `/healthz`, `/readyz`. Customer integrates with monitoring stack. |
| CA-8 | Penetration testing | 🔶 Shared | Internal assessment completed (see [pentest_findings.md](pentest_findings.md)). External assessment recommended before production. |

### CM — Configuration Management

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| CM-2 | Baseline configuration | 🔶 Shared | NanoMask provides documented defaults. Customer defines production baseline per deployment. |
| CM-6 | Configuration settings | ✅ NanoMask | All settings configurable via CLI flags and environment variables with strict precedence. |
| CM-7 | Least functionality | ✅ NanoMask | Optional features (patterns, schema, TLS, admin API) are disabled by default. Zero external dependencies. |
| CM-8 | System component inventory | ✅ NanoMask | SBOM generated via CycloneDX. Attached to release artifacts. |

### IA — Identification And Authentication

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| IA-2 | Identification and authentication | 🔶 Shared | Admin API: Bearer token with constant-time comparison. SSO/RBAC planned (NMV3-011). |
| IA-5 | Authenticator management | ❌ Customer | Token generation, rotation, and storage are the customer's responsibility. |

### PE — Physical And Environmental Protection

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| PE-* | All physical controls | ❌ Customer | NanoMask is software. Physical security is the deploying environment's responsibility. |

### PS — Personnel Security

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| PS-* | All personnel controls | ❌ Customer | Personnel screening, termination procedures, and access agreements are organizational controls. |

### RA — Risk Assessment

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| RA-3 | Risk assessment | 🔶 Shared | STRIDE-based threat model maintained in [threat_model.md](threat_model.md). Customer integrates with their risk framework. |
| RA-5 | Vulnerability monitoring and scanning | ✅ NanoMask | Container image scanned with Trivy on every CI run (zero critical/high tolerance). |

### SA — System And Services Acquisition

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| SA-11 | Developer testing | ✅ NanoMask | 250+ automated tests, fuzz targets, security HTTP tests, compatibility matrix, proof harness. |
| SA-22 | Unsupported system components | ✅ NanoMask | Zero external dependencies. Zig toolchain version pinned. |

### SC — System And Communications Protection

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| SC-7 | Boundary protection | 🔶 Shared | NanoMask enforces trust boundaries (ingress/egress/admin). Network-level boundaries are the customer's responsibility. |
| SC-8 | Transmission confidentiality and integrity | ✅ NanoMask | TLS 1.3 on upstream; ingress TLS via hardened proxy or built-in. |
| SC-12 | Cryptographic key establishment and management | 🔶 Shared | HMAC-SHA256 for HASH mode. Key rotation is manual. KMS integration planned (NMV3-013). |
| SC-13 | Cryptographic protection | ✅ NanoMask | AES-128-GCM-SHA256, X25519, ECDSA P-256, Ed25519. Not FIPS 140-2 validated. |
| SC-28 | Protection of information at rest | ✅ NanoMask | NanoMask does not persist PHI. In-memory only during transaction processing. |

### SI — System And Information Integrity

| Control | Description | Responsibility | NanoMask Implementation |
|---------|-------------|----------------|------------------------|
| SI-2 | Flaw remediation | 🔶 Shared | Security CI pipeline. Customer applies updates. |
| SI-3 | Malicious code protection | ✅ NanoMask | Static binary from `scratch` image. No shell, no package manager, no writable OS layer. |
| SI-4 | System monitoring | 🔶 Shared | Prometheus metrics, structured logs, health endpoints. Customer integrates with monitoring. |
| SI-10 | Information input validation | ✅ NanoMask | Strict HTTP parser, body size limits, admin body cap, JSON parsing hardened against adversarial input. |

---

## Gap Analysis

### Gaps Requiring Resolution For FedRAMP Moderate

| Gap | Control Family | Mitigation Path | Target Ticket |
|-----|----------------|-----------------|---------------|
| No SSO/RBAC — single shared admin token | AC, IA | SSO and role-based access controls | NMV3-011 |
| No external key management | SC-12 | KMS/HSM integration for HASH key and TLS certs | NMV3-013 |
| No automated key rotation | SC-12 | Key rotation procedure and automation | NMV3-013 |
| No FIPS 140-2 validated cryptography | SC-13 | Use ingress TLS with FIPS-validated proxy (NGINX Plus, Envoy FIPS) or pursue Zig crypto module validation | Future |
| No mTLS on listener | SC-8 | Mutual TLS support for zero-trust service mesh | NMV3-013 |
| Built-in TLS not externally audited | SC-13 | Commission external review or restrict production to ingress-terminated TLS only | NMV3-013 |
| No SIEM export or OTel integration | AU, SI-4 | OpenTelemetry traces/logs, syslog forwarding | NMV3-012 |

### Controls NanoMask Satisfies Without Gaps

AU-2, AU-3, AU-8, AU-12, CM-6, CM-7, CM-8, RA-5, SA-11, SA-22, SC-8 (upstream), SC-28, SI-3, SI-10.

---

## Revision History

| Date | Change |
|------|--------|
| 2026-03-13 | Initial FedRAMP readiness assessment (NMV3-005) |
