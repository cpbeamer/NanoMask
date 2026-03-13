# NanoMask Customer Security Packet

This document is the consolidated security reference for NanoMask evaluators, procurement teams, and security reviewers. It summarizes the product's architecture, hardening guidance, trust boundaries, audit capabilities, secrets handling, and known limitations in one place.

For the full technical design, see [architecture.md](architecture.md). For the STRIDE-based analysis, see [threat_model.md](threat_model.md). For test findings, see [pentest_findings.md](pentest_findings.md).

---

## 1. Architecture Summary

### What NanoMask Is

NanoMask is a high-throughput HTTP reverse proxy that de-identifies PII/PHI in request bodies before they leave the network and restores pseudonymized values in responses. It is a single static binary with zero runtime dependencies, built in Zig 0.15.2.

### Deployment Topologies

| Topology | Description | Listener TLS |
|----------|-------------|--------------|
| **Gateway** | Shared Kubernetes Service behind an Ingress controller | Ingress-terminated (recommended) |
| **Sidecar** | Per-pod co-located with the application | Not needed (localhost only) |
| **Edge / Air-gapped** | Bare-metal or VM without a load balancer | Built-in TLS 1.3 |

### Data Flow

```
Client → [TLS Termination] → NanoMask (:8081) → [TLS 1.3] → Upstream API

Request path:  Header parse → Body read → Redaction pipeline → Forward
Response path: Body read → Restore (unmask/unhash) → Relay to client
```

### Redaction Pipeline

1. **Stage 1**: SIMD SSN scan — in-place digit masking (~16 GB/s)
2. **Stage 2**: Aho-Corasick entity masking — dictionary name → alias (~260 MB/s)
3. **Stage 3**: Myers' fuzzy matching — OCR/variant name → alias (~193 MB/s)
4. **Pattern library** (optional): Email, phone, credit card, IP, healthcare IDs
5. **Schema-aware JSON** (optional): Per-field KEEP, REDACT, SCAN, HASH actions

---

## 2. Hardening Guidance

### Recommended Production Configuration

| Control | Recommendation | Flag / Env Var |
|---------|----------------|----------------|
| **Admin authentication** | Always set an admin token | `--admin-token` / `NANOMASK_ADMIN_TOKEN` |
| **Admin isolation** | Use a dedicated admin listener on a loopback address | `--admin-listen-address 127.0.0.1:9091` |
| **IP allowlist** | Restrict admin access to known IPs | `--admin-allowlist` |
| **Read-only mode** | Prevent runtime entity mutations in sensitive environments | `--admin-read-only` |
| **Mutation rate limit** | Cap admin mutation bursts | `--admin-mutation-rate-limit` (default 60/min) |
| **Listener TLS** | Terminate at a hardened ingress tier (NGINX, Envoy, ALB) | See [tls_strategy.md](tls_strategy.md) |
| **Upstream TLS** | Always enable for public APIs | `--target-tls` |
| **Connection limit** | Cap concurrent connections to prevent exhaustion | `--max-connections` (default 128) |
| **Body size limit** | Bound request body size | `--max-body-size` (default 10 MB) |
| **Log level** | Use `info` or `warn` in production to avoid PII in debug logs | `--log-level info` |
| **Audit logging** | Enable for compliance evidence | `--audit-log` |

### Container Security

| Control | Status |
|---------|--------|
| Base image | `scratch` — zero OS packages, zero CVEs from base |
| Non-root execution | `USER 65534:65534` (nobody:nogroup) |
| Static binary | Fully static musl link, no shared library loading |
| Health check | Built-in `--healthcheck` mode (no curl/wget in scratch) |
| Image signing | `cosign` keyless via GitHub OIDC |
| SBOM | CycloneDX via `trivy` / `syft`, attached to each release |

### Supply Chain

| Control | Status |
|---------|--------|
| External dependencies | Zero (empty `build.zig.zon` dependencies block) |
| Build reproducibility | Zig cross-compilation is deterministic for a given toolchain version |
| Binary signing | `minisign` signatures published alongside binaries |
| CI enforcement | Format check, build, compatibility matrix, security scan on every PR |

---

## 3. Network Boundary Explanation

NanoMask defines three trust boundaries (see [threat_model.md](threat_model.md)):

### TB-1: Ingress (Client → NanoMask)

- **Untrusted**. NanoMask accepts HTTP requests from any client.
- Proxy endpoints have no client authentication by design — auth headers (`Authorization`, `Cookie`) are forwarded to the upstream as-is.
- The admin API is separated from the proxy surface: Bearer token auth, IP allowlist, optional dedicated listener, read-only mode, and rate limiting.
- Hop-by-hop headers (`Connection`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive`) are stripped. All end-to-end headers are forwarded.

### TB-2: Egress (NanoMask → Upstream)

- **Trusted** (the upstream API is within the trust boundary).
- Upstream TLS uses `std.http.Client` with system or custom CA bundles.
- NanoMask does not validate or modify upstream response content beyond alias/hash restoration.

### TB-3: Filesystem

- Entity files and schema files are read from the local filesystem.
- Entity files support hot-reload via poll-based file watching with RCU snapshot swap.
- File permissions are the sole protection against tampering. No integrity checking is performed on entity or schema files.

### What NanoMask Does NOT Inspect

- NanoMask does not perform OCR, PDF parsing, image analysis, or archive extraction.
- Binary content types (`application/pdf`, `image/*`, `audio/*`, `video/*`, `application/octet-stream`) are bypassed or rejected, never transformed.
- NanoMask does not authenticate end-user identity. It forwards auth headers to the upstream.

---

## 4. Logging And Audit Behavior

### Structured Logging

NanoMask outputs NDJSON (newline-delimited JSON) to stderr or a configurable log file. Every log line contains `ts`, `level`, `session_id`, and `msg`.

Key lifecycle events: `request_received`, `upstream_forwarded`, `response_sent`.

### Audit Events

When `--audit-log` is enabled, NanoMask emits:

| Event Type | Trigger | Fields |
|------------|---------|--------|
| `redaction_audit` | SSN match, entity mask, fuzzy match, pattern match, schema action | `stage`, `match_type`, `original_length`, `replacement_type`, `offset` or `field_path`, `confidence` (fuzzy) |
| `admin_audit` | Entity add, remove, replace, reload | `action`, `version`, `count` |

**Sensitive values are never written to the audit log.** Only metadata (lengths, offsets, action types) is recorded.

### Audit Caps

To prevent noisy payloads from overwhelming operators, NanoMask caps audit emission at **256 events per request**. When exceeded, an `audit_event_cap_reached` warning is logged.

Streaming audit payloads are capped at **1 MB** to bound memory usage.

---

## 5. Secrets And Key Handling

| Secret | Storage | Notes |
|--------|---------|-------|
| Admin token | CLI flag or env var | Never logged. Compared using constant-time equality. |
| HASH HMAC key | CLI flag, env var, or file | 64-character hex string. Used for deterministic pseudonymization. In-memory reverse map enables response-path restore. |
| TLS cert / key | PEM files on filesystem | Used only for built-in TLS mode. Ingress-terminated TLS delegates key management to the ingress tier / cert-manager. |

### Key Handling Practices

- No secrets are hardcoded in source. Verified by grep in the [security review checklist](security_review_checklist.md).
- HASH key rotation is manual (restart with new key). Automated rotation is planned for NMV3-013.
- External KMS/HSM integration is planned for NMV3-013.
- Admin token must be explicitly configured when `--admin-api` is enabled. Anonymous admin mode is not supported.

---

## 6. Known Limitations And Compensating Controls

| Limitation | Risk | Compensating Control |
|------------|------|---------------------|
| Redaction is best-effort for unstructured text | Novel PII formats not in the pattern library may pass through | Use schema-aware mode with `default_action: REDACT` for strongest posture; add custom entity lists; enable all pattern library flags |
| Built-in TLS not externally audited | Buyer anxiety during security reviews | **Recommended**: use ingress-terminated TLS (Option A). Built-in TLS is for dev/edge/air-gapped only. |
| Single cipher suite (AES-128-GCM-SHA256) on built-in TLS | Clients must support this specific suite | All modern TLS 1.3 clients support AES-128-GCM. Use ingress TLS for broader compatibility. |
| HASH restore uses in-memory reverse map | If attacker obtains HASH key, all pseudonyms are reversible | Protect HASH key via file permissions, secrets management, and network isolation. Key rotation planned (NMV3-013). |
| Entity alias cap at 702 per session | Large identity sets exceed the alias namespace | Planned removal in NMV3-015. Use schema HASH mode for high-cardinality identifier sets. |
| No client authentication on proxy endpoints | Any client can send requests | By design — NanoMask forwards auth to upstream. Use network-level controls (firewall, service mesh, mTLS at ingress) to restrict proxy access. |
| File-based entity/schema integrity | Local attacker with write access can modify files | Protect via filesystem permissions, read-only container mounts, and Kubernetes ConfigMap/Secret resources. |
| Debug log level may leak payload fragments | PII could appear in debug logs | Use `info` or `warn` in production. Never run `debug` with real PHI. |
| No OCSP/CRL on built-in TLS | Revoked certificates are not detected | Use ingress-terminated TLS with OCSP stapling. |

---

## Document References

| Document | Path | Description |
|----------|------|-------------|
| Architecture | [architecture.md](architecture.md) | Full technical design |
| Threat model | [threat_model.md](threat_model.md) | STRIDE analysis with trust boundaries |
| TLS strategy | [tls_strategy.md](tls_strategy.md) | Production TLS decision and topologies |
| Pentest findings | [pentest_findings.md](pentest_findings.md) | Assessment findings and closure status |
| Release signing | [release_signing.md](release_signing.md) | SBOM and binary/image signing workflow |
| Security checklist | [security_review_checklist.md](security_review_checklist.md) | Per-release verification checklist |
| HIPAA BAA template | [hipaa_baa_template.md](hipaa_baa_template.md) | Draft Business Associate Agreement |
| FedRAMP readiness | [fedramp_readiness.md](fedramp_readiness.md) | NIST 800-53 control mapping and gap analysis |

---

## Revision History

| Date | Change |
|------|--------|
| 2026-03-13 | Initial customer security packet (NMV3-005) |
