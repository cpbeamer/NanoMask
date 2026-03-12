# NanoMask Production TLS Strategy

## Summary

NanoMask supports TLS encryption on both the **listener** (client → NanoMask) and **upstream** (NanoMask → API) legs of the proxy pipeline. This document describes the recommended production architecture, the supported alternative, and the decision rationale.

## Recommended Architecture: Ingress-Terminated TLS (Option A)

For production deployments, **terminate listener-side TLS at a hardened ingress tier** and run NanoMask as a plaintext HTTP service behind it.

```
┌─────────┐     TLS 1.2/1.3      ┌──────────────────┐      HTTP       ┌──────────┐     TLS 1.3     ┌──────────┐
│  Client  │ ──────────────────→ │  Ingress / LB     │ ──────────────→ │ NanoMask │ ─────────────→ │ Upstream │
│          │                      │  (NGINX, Envoy,   │   (localhost    │          │  (--target-tls) │  API     │
│          │                      │   ALB, Traefik)   │    or cluster)  │          │                 │          │
└─────────┘                      └──────────────────┘                  └──────────┘                 └──────────┘
```

### Why This Is Recommended

| Concern                  | Ingress-Terminated TLS                          | Built-in TLS                                      |
|--------------------------|------------------------------------------------|---------------------------------------------------|
| **Cipher coverage**      | Full suite (TLS 1.2 + 1.3, all modern ciphers) | AES-128-GCM-SHA256 only                           |
| **Certificate management** | Automated via cert-manager, ACM, Let's Encrypt | Manual PEM file mounting                          |
| **OCSP / CRL**           | Supported                                       | Not implemented                                   |
| **Client certificate (mTLS)** | Supported                                  | Not implemented                                   |
| **Security audit scope** | Battle-tested, widely audited components        | Custom implementation (1,059 LOC, not externally audited) |
| **FIPS 140-2**           | Available in NGINX Plus, Envoy FIPS builds      | Not certified                                     |
| **Compliance posture**   | Buyer-friendly — known quantity                 | Requires explanation during security reviews       |
| **Performance**          | Mature TLS offload with hardware acceleration   | Zig stdlib crypto (fast, but software-only)        |

### Deployment Topologies

#### Gateway Mode (Recommended for Shared Infrastructure)

```yaml
# Ingress terminates TLS, forwards HTTP to NanoMask Service
Ingress (TLS) → Service (ClusterIP:8081) → NanoMask Pod(s) → Upstream API (TLS)
```

NanoMask listens on `0.0.0.0:8081` (HTTP). The Ingress controller handles certificate provisioning, rotation, and cipher negotiation. See `examples/standalone-deployment.yaml` for a complete manifest.

#### Sidecar Mode (Recommended for Per-Pod Isolation)

```yaml
# App and NanoMask share localhost; Ingress terminates TLS at the pod boundary
Ingress (TLS) → Pod [ App → localhost:8081 → NanoMask ] → Upstream API (TLS)
```

NanoMask listens on `127.0.0.1:8081` (HTTP, pod-local only). TLS is unnecessary on the listener side because traffic never leaves the pod network namespace. See `examples/sidecar-pod.yaml`.

### Reference Ingress Controllers

| Controller        | TLS Termination | cert-manager Integration | Notes                              |
|-------------------|-----------------|-------------------------|------------------------------------|
| NGINX Ingress     | ✅               | ✅                       | Most common, well-documented       |
| Envoy / Istio     | ✅               | ✅                       | Service mesh, mTLS built-in        |
| AWS ALB           | ✅               | Via ACM                  | Managed, no self-hosted controller |
| Traefik           | ✅               | ✅                       | Auto Let's Encrypt                 |
| HAProxy Ingress   | ✅               | ✅                       | High-performance option            |

---

## Supported Alternative: Built-in TLS (Option B)

NanoMask includes a built-in TLS 1.3 server implementation for scenarios where an external ingress tier is unavailable or impractical.

### When to Use Built-in TLS

- **Development and testing** — quick local HTTPS without infrastructure setup
- **Edge deployments** — bare-metal or VM environments without a load balancer
- **Air-gapped environments** — where installing additional software is restricted
- **Evaluation and demos** — fast setup for proof-of-concept work

### Configuration

```bash
# Enable listener-side TLS
nanomask --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem

# Enable upstream TLS with custom CA
nanomask --target-tls --ca-file /path/to/ca.pem --tls-no-system-ca
```

| Flag                  | Environment Variable          | Description                                    |
|-----------------------|-------------------------------|------------------------------------------------|
| `--tls-cert <path>`   | `NANOMASK_TLS_CERT`          | PEM certificate for listener TLS               |
| `--tls-key <path>`    | `NANOMASK_TLS_KEY`           | PEM private key for listener TLS               |
| `--target-tls`        | `NANOMASK_TARGET_TLS`        | Enable TLS for upstream connections             |
| `--ca-file <path>`    | `NANOMASK_CA_FILE`           | Custom CA bundle PEM for upstream verification  |
| `--tls-no-system-ca`  | `NANOMASK_TLS_NO_SYSTEM_CA`  | Suppress system CA bundle (use with `--ca-file`)|

### Technical Details

The built-in TLS module implements:
- **Protocol**: TLS 1.3 (RFC 8446)
- **Key exchange**: X25519 (ECDHE)
- **Cipher suite**: AES-128-GCM-SHA256
- **Signature algorithms**: ECDSA P-256 (secp256r1), Ed25519
- **Certificate format**: PEM-encoded X.509 (DER payload)

### Known Limitations

| Limitation                     | Impact                                                    |
|-------------------------------|-----------------------------------------------------------|
| Single cipher suite            | Clients must support AES-128-GCM-SHA256                   |
| No TLS 1.2 fallback           | Older clients that only speak TLS 1.2 cannot connect      |
| No client certificate auth    | Mutual TLS (mTLS) is not available on the listener        |
| No OCSP stapling              | Certificate revocation checking is not supported          |
| No session resumption          | Every connection performs a full handshake                 |
| 8 KB max certificate DER      | Large certificate chains may be rejected                  |
| Not externally audited         | The implementation has not undergone a third-party review |

---

## Upstream TLS (NanoMask → Upstream API)

Upstream TLS uses Zig's `std.http.Client` with the system or custom CA bundle. This leg is **not** affected by the listener TLS strategy decision — it works identically regardless of whether the listener uses built-in TLS, ingress-terminated TLS, or plaintext HTTP.

```
NanoMask  ──[TLS 1.3 via std.http.Client]──→  api.openai.com:443
```

- **Default**: System CA bundle is loaded automatically on first HTTPS request
- **Custom CA**: `--ca-file` loads a specific CA PEM for internal PKI or GovCloud
- **Self-signed upstream**: Combine `--ca-file` with `--tls-no-system-ca`

---

## Security Considerations

1. **In-transit encryption is always recommended** — use either ingress-terminated TLS or built-in TLS; do not expose NanoMask over plaintext HTTP in production.
2. **Upstream TLS should always be enabled** when connecting to public LLM APIs (`--target-tls`).
3. **Certificate rotation** is handled by the ingress tier or cert-manager in Option A. For Option B, reload the NanoMask process after replacing cert/key files.
4. **Audit logging** records whether TLS was active on each connection via structured startup logs.
