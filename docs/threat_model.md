# NanoMask Threat Model

This document provides a STRIDE-based threat model for NanoMask, covering all trust boundaries, data flows, and deployment surfaces. It is a living document and should be reviewed with every release (see [security_review_checklist.md](security_review_checklist.md)).

## System Overview

NanoMask is a privacy-firewall reverse proxy that intercepts HTTP traffic, scans for PII/PHI (SSN, names, emails, phone numbers, credit cards, IP addresses, healthcare identifiers), and redacts or pseudonymizes matches before forwarding to upstream APIs. It exposes a REST admin API for runtime entity management and supports TLS on both the listener and upstream legs.

### Trust Boundaries

```
┌────────────────────────────────┐
│         Client (Untrusted)     │
└────────────┬───────────────────┘
             │ HTTP/TLS
    ─────────┼──────────── TB-1: Ingress boundary
             ▼
┌────────────────────────────────┐
│         NanoMask Proxy         │
│  ┌──────────┐  ┌────────────┐  │
│  │ Redaction │  │ Admin API  │  │
│  │ Pipeline  │  │ (/_admin/) │  │
│  └──────────┘  └────────────┘  │
│  ┌──────────┐  ┌────────────┐  │
│  │  Schema   │  │  Entity    │  │
│  │  Engine   │  │  Store     │  │
│  └──────────┘  └────────────┘  │
└────────────┬───────────────────┘
             │ HTTP/TLS
    ─────────┼──────────── TB-2: Egress boundary
             ▼
┌────────────────────────────────┐
│      Upstream API (Trusted)    │
└────────────────────────────────┘

         ┌─────────────┐
         │  Entity File │ ◄── TB-3: Filesystem boundary
         └─────────────┘
         ┌─────────────┐
         │  Schema File │ ◄── TB-3
         └─────────────┘
```

---

## STRIDE Analysis

### TB-1: Ingress Boundary (Client → NanoMask)

#### Spoofing

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| S-1 | Attacker impersonates a legitimate client | Admin API requires Bearer token with constant-time comparison; IP allowlist restricts admin access | Proxy endpoints have no client authentication (by design — auth headers are forwarded to upstream). Admin token must be configured explicitly; default is unauthenticated. |
| S-2 | Attacker forges `X-ZPG-Entities` header to manipulate per-request entity maps | None — header is trusted | Low risk: worst case is the attacker controls which names get redacted in their own request. The header does not affect other sessions. |

#### Tampering

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| T-1 | Request smuggling via CL/TE conflicts | Zig's `std.http.Server` uses a strict request parser; does not support `Transfer-Encoding: chunked` on the ingress side | Low. Standard library parser rejects ambiguous framing. Test coverage added in `security_http_tests.zig`. |
| T-2 | Header injection via CR/LF in header values | `std.http.Server` rejects bare CR/LF in header values during parsing | Low. Verified by adversarial tests. |
| T-3 | Null bytes in headers or URI | `std.http.Server` treats null bytes as invalid | Low. |

#### Repudiation

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| R-1 | Client denies sending a request that contained PII | Structured audit log records redaction events with session IDs, timestamps, and field-level detail | Audit log integrity depends on file permissions and log pipeline security (out of scope for the binary). |

#### Information Disclosure

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| I-1 | PII leaks to upstream due to redaction bypass | Multi-stage pipeline (SIMD SSN, Aho-Corasick exact, Myers fuzzy, pattern library, schema-aware JSON); schema `default_action` controls unknown fields | Redaction is best-effort for unstructured text. Novel PII formats not in the pattern library may pass through. Schema-aware mode with `default_action: redact` is the strongest posture. |
| I-2 | Error messages or logs expose PII | Logger sanitizes body content; errors return generic JSON messages | Debug-level logs in development mode could leak payload fragments. Production should use `info` or `warn` log level. |
| I-3 | Timing side-channels on admin token | `constantTimeEql` used for Bearer token comparison | Low. Token length is leaked (standard practice). |

#### Denial of Service

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| D-1 | Connection exhaustion | Atomic connection counter with configurable cap (default 128) | Attacker can exhaust the cap and block legitimate clients. Consider SYN cookies or an external rate limiter at the ingress tier. |
| D-2 | Oversized request body | `max_body_size` config (default capped); admin API body capped at 1 MB | Memory usage is bounded. Streaming payloads are subject to the 1 MB audit cap. |
| D-3 | Slowloris / slow-read attacks | Per-connection thread with configurable timeouts (`upstream_connect_timeout_ms`, `upstream_read_timeout_ms`) | Thread-per-connection model means slow clients hold a thread. Mitigate with connection cap and external load balancer timeouts. |

#### Elevation of Privilege

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| E-1 | Attacker accesses admin API to mutate entity lists | Bearer token auth, IP allowlist, read-only mode, mutation rate limiter, dedicated admin listener option | If admin token is not configured, admin API is unauthenticated. Production deployments MUST set `--admin-token`. |

---

### TB-2: Egress Boundary (NanoMask → Upstream)

#### Tampering

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| T-4 | MITM on upstream connection | TLS 1.3 with system or custom CA bundle; `--tls-no-system-ca` + `--ca-file` for internal PKI | If `--target-tls` is not set, upstream traffic is plaintext. Operator must configure TLS explicitly. |
| T-5 | Response tampering by compromised upstream | None — upstream is in the trust boundary | Out of scope. NanoMask trusts the upstream API response. |

#### Information Disclosure

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| I-4 | Redacted payload is re-identified via HASH pseudonyms | HMAC-SHA256 with configurable key; key can be sourced from file | In-memory reverse map enables response-path restore. If the attacker obtains the HASH key, all pseudonyms are reversible. Key rotation is manual. |
| I-5 | Entity alias mapping leaks identity correlation | Aliases are session-scoped and deterministic within a request | An observer who sees both original and aliased traffic can correlate. This is inherent to pseudonymization — documented limitation. |

---

### TB-3: Filesystem Boundary

#### Tampering

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| T-6 | Attacker modifies entity file to suppress redaction | File watcher uses RCU snapshot swap; atomic temp-file + rename for admin API sync | File permissions are the only protection. A local attacker with write access to the entity file can remove names. |
| T-7 | Attacker modifies schema file to change redaction policy | Schema loaded at startup only (no hot-reload) | Lower risk than entity file since schema is not hot-reloaded. Still depends on file permissions. |

#### Denial of Service

| # | Threat | Existing Mitigation | Residual Risk |
|---|--------|-------------------|---------------|
| D-4 | Attacker replaces entity file with very large content | Entity set rebuilds Aho-Corasick automaton (O(n) in pattern count); 256-entry child arrays per trie node | Very large entity files could cause high memory usage during rebuild. Entity limit cap (702) is a partial mitigation but is per-session, not per-file. |

---

### Deployment Surface

#### Container Security

| Control | Status |
|---------|--------|
| Base image | `scratch` — zero CVEs from OS packages |
| Non-root execution | `USER 65534:65534` (nobody:nogroup) |
| Static binary | Fully static musl link, no shared library loading |
| Health check | Built-in `--healthcheck` mode (no curl/wget needed in scratch) |
| Image signing | Planned (`cosign` keyless via GitHub OIDC) |
| SBOM | Planned (`trivy sbom` / `syft` against the image) |

#### Supply Chain

| Control | Status |
|---------|--------|
| External dependencies | Zero (empty `build.zig.zon` dependencies block) |
| Build reproducibility | Zig cross-compilation is deterministic for a given toolchain version |
| Package fingerprint | `build.zig.zon` contains a stable fingerprint (`0xa3717543b57a2b5b`) |
| CI enforcement | Format check, build, compatibility matrix on every PR |

---

## Recommended Controls (Not Yet Implemented)

| ID | Recommendation | Priority | Ticket |
|----|---------------|----------|--------|
| RC-1 | Require `--admin-token` when `--admin-api` is enabled (fail-closed) | P0 | NMV3-004 |
| RC-2 | Add request-scoped rate limiting at the proxy ingress (not just admin) | P1 | NMV3-017 |
| RC-3 | Add external key management integration for HASH key | P1 | NMV3-013 |
| RC-4 | Add key rotation workflow and documentation | P1 | NMV3-013 |
| RC-5 | Add mutual TLS (mTLS) for zero-trust service-to-service | P1 | NMV3-013 |
| RC-6 | Run long-duration fuzzing in a dedicated CI/scheduler | P2 | — |
| RC-7 | Add audit log integrity verification (checksums or append-only) | P2 | NMV3-012 |

---

## Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-03-13 | NMV3-004 | Initial STRIDE threat model |
| 2026-03-13 | NMV3-005 | Added cross-reference to [pentest_findings.md](pentest_findings.md) and [security_packet.md](security_packet.md) |
