<p align="center">
  <h1 align="center">🛡️ NanoMask</h1>
  <p align="center"><strong>Wire-speed PII/PHI redaction proxy — pure Zig, zero dependencies</strong></p>
  <p align="center">
    <a href="#benchmarks">16+ GB/s SSN redaction</a> · <a href="#algorithms">3-stage privacy pipeline</a> · <a href="#quick-start">Single binary deploy</a>
  </p>
</p>

---

NanoMask is a high-throughput HTTP reverse proxy that **de-identifies protected health information (PHI)** in real time. It sits between your application and upstream services (LLMs, APIs, databases) and automatically redacts sensitive data from request bodies before they leave your network — then restores it in responses.

Built for **VA claims processing** and DoD environments where OCR-scanned clinical documents contain inconsistent patient name spellings, SSNs, and other PII that must never reach third-party services.

## Why NanoMask?

| Problem | NanoMask's Answer |
|---|---|
| SSNs in API payloads | SIMD-accelerated pattern scan at **16+ GB/s** (ReleaseFast) |
| Patient names in LLM prompts | Aho-Corasick automaton replaces names with aliases at **260 MB/s** |
| OCR misspellings (`J0hn Doe`, `JOHN E DOE`) | Myers' bit-vector fuzzy matching at **193 MB/s** |
| Per-request TCP overhead to upstream | Built-in connection pooling with keep-alive |
| Need Python/Java/Go runtime | **Single static binary**, zero runtime dependencies |

## Quick Start

### Prerequisites

- [Zig 0.15.2](https://ziglang.org/download/) (no other dependencies)

### Build & Run

```bash
# Build the proxy (ReleaseFast for production)
zig build -Doptimize=ReleaseFast

# Run with defaults (listens on :8081, forwards to httpbin.org:80)
zig build run

# Run with an entities file list
zig build run -- --entity-file entities.txt

# Run benchmarks (ReleaseFast, clean output on Windows)
zig build bench-all 2>$null

# Run the vendor compatibility suite and emit the matrix artifact
zig build compat-matrix -- compatibility/compatibility-matrix.json

# Run the full repo test suite
zig build test
```

### Configure

All settings are configurable via CLI flags or environment variables (see [Configuration](#configuration) below):

```bash
# Keep the proxy loopback-only for sidecar deployments
zig build run -- --listen-host 127.0.0.1 --target-host api.openai.com --target-port 443 --target-tls

# Bind on all pod/container interfaces for gateway mode
zig build run -- --listen-host 0.0.0.0 --target-host api.openai.com --target-port 443 --target-tls

# Forward to an upstream API over HTTPS with entity masking
zig build run -- --target-host api.openai.com --target-port 443 --target-tls --entity-file entities.txt

# Enable TLS on the listener side
zig build run -- --tls-cert cert.pem --tls-key key.pem --entity-file entities.txt

# Use environment variables (12-factor friendly)
NANOMASK_TARGET_HOST=api.internal NANOMASK_TARGET_PORT=443 zig build run
```

Or pass entity names per-request via HTTP header:

```bash
curl -X POST http://localhost:8081/api/chat \
  -H "X-ZPG-Entities: John Doe, Jane Smith" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Patient John Doe SSN 123-45-6789 was seen today"}'
```

The proxy transforms the outbound request to:

```json
{"prompt": "Patient Entity_A SSN ***-**-**** was seen today"}
```

And transparently restores `Entity_A` → `John Doe` in the upstream response.

### Payload Policy

NanoMask only performs inline privacy transforms on identity-encoded JSON and text payloads.

Supported inline redaction types:
- `application/json`
- `application/*+json`
- `application/x-ndjson`
- `text/plain`
- `text/*`

Bypass-by-default types:
- `multipart/form-data`
- `application/octet-stream`
- `application/pdf`
- `image/*`
- `audio/*`
- `video/*`

Everything else is treated as unsupported. By default, unsupported request bodies are rejected with `415 Unsupported Media Type`, while unsupported upstream responses are bypassed unless a response transform is required. You can override those defaults with `--unsupported-request-body-behavior` / `NANOMASK_UNSUPPORTED_REQUEST_BODY_BEHAVIOR` and `--unsupported-response-body-behavior` / `NANOMASK_UNSUPPORTED_RESPONSE_BODY_BEHAVIOR`.

NanoMask sends `Accept-Encoding: identity` upstream. If a compressed upstream response still arrives and NanoMask would need to unmask or unhash it, the proxy rejects that response instead of attempting to transform compressed bytes.

### Response Streaming

NanoMask now preserves end-to-end response headers by default and only strips hop-by-hop headers such as `Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, and `Upgrade`.

- `Set-Cookie`, `Cache-Control`, request IDs, rate-limit headers, and vendor metadata are forwarded downstream.
- `text/event-stream`, `application/x-ndjson`, and chunked upstream responses stay streamed to the client. NanoMask flushes each forwarded chunk so SSE and line-delimited output are not held until the upstream completes.
- Fixed-length responses that do not require a response transform keep a downstream `Content-Length`.
- Response unmasking for alias restoration stays incremental when the payload is inline-transformable and identity-encoded.
- HASH restore (`unhashJson`) still requires full JSON buffering. When that happens the proxy logs `response_mode="buffered"` with `buffer_reason="json_unhash"` so operators can see why streaming was disabled for that response.

The local mock-upstream compliance suite includes streamed SSE and NDJSON flows with inter-chunk delays and asserts that the first downstream chunk arrives before the full upstream response completes. That gives NanoMask a regression check for first-token latency on loopback without relying on an external vendor.
**Known limitation**: The compatibility matrix currently reports that Anthropic-style SSE streaming is collapsed into a single client chunk. The proxy forwards the data correctly, but incremental per-chunk flushing is not yet verified as arriving in separate reads for the SSE flow. Improving incremental flush fidelity is tracked as part of the NMV2-003 streaming follow-up.

## Algorithms

NanoMask runs a **3-stage privacy pipeline** on every request body. Each stage is optimized for a specific class of PII pattern, and they execute in sequence so that later stages only process text not already redacted by earlier ones.

### Stage 1: SIMD SSN Redaction (~16 GB/s)

**What it catches**: Social Security Numbers in `NNN-NN-NNNN` format.

**How it works**: A SIMD dash-scanning engine loads 16 bytes at a time via `@Vector(16, u8)` and builds a bitmask of all `-` positions. For each dash candidate, it checks if the surrounding bytes form a valid `XXX-XX-XXXX` digit pattern. Matched digits are replaced with `*` in-place with zero allocations.

```
Input:  "Patient SSN 123-45-6789 is active"
Output: "Patient SSN ***-**-**** is active"
```

**Why it's fast**: Dashes are rare in typical payloads, so most 16-byte windows are skipped entirely (one SIMD compare + mask check). A 3-byte scalar rewind after the SIMD loop ensures no SSN is missed at window boundaries. At ReleaseFast, the scan achieves ~16 GB/s on a single core.

**Streaming support**: `redactSsnChunked` processes data in arbitrarily-sized chunks for streaming proxy use. A 10-byte pending buffer defers output until the next chunk confirms no boundary-spanning SSN exists. Equivalent output to single-pass `redactSsn` — verified by a 1 MB fuzz-equivalence test.

**Source**: [`src/redact.zig`](src/redact.zig)

### Stage 2: Aho-Corasick Entity Masking (~260 MB/s)

**What it catches**: Exact occurrences of known patient/entity names.

**How it works**: At session initialization, all entity names are compiled into an **Aho-Corasick finite automaton** — a trie with failure links that enables simultaneous matching of all patterns in a single pass over the text. When a name is found, it's replaced with a deterministic alias (`Entity_A`, `Entity_B`, etc.).

```
Names:  ["John Doe", "Jane Smith"]
Input:  "Dr. visited John Doe and Jane Smith"
Output: "Dr. visited Entity_A and Entity_B"
```

**Key properties**:
- **O(n + m)** time complexity: linear in text length plus total matches, regardless of how many names are in the set
- **Bidirectional**: the same automaton is used in reverse to restore aliases → names in upstream responses
- **Per-request override**: the `X-ZPG-Entities` header can supply a different name set per request
- **Word-boundary aware**: only matches at word boundaries to avoid false positives inside longer words

**Source**: [`src/entity_mask.zig`](src/entity_mask.zig)

### Stage 3: Fuzzy Name Matching (~193 MB/s)

**What it catches**: OCR-corrupted and inconsistently formatted name variants that Stage 2's exact matching misses.

**The problem**: In scanned clinical documents, "John Doe" might appear as `J0hn Doe`, `JOHN E DOE`, `john`, `Mr. Doe`, or `John E. Doe`. Exact string matching leaks these variants.

**How it works**: A multi-layer pipeline that combines cheap pre-filters with an expensive but accurate edit-distance kernel:

#### Layer 1: Trigram Bloom Filter (zero allocation)

Each name variant is pre-compiled into a 128-bit bloom filter seeded with character trigrams (3-char substrings). Before any expensive comparison, the scanner builds a trigram fingerprint from the raw window bytes — lowercasing on the fly — and ANDs it with the variant's filter. If zero bits overlap, the window is guaranteed to not match. **This rejects ~95% of windows at near-zero cost.**

```
Variant "john doe" → trigrams: joh, ohn, hn_, _do, doe → u128 bitset
Window  "was seen" → trigrams: was, as_, s_s, _se, see, een → u128 bitset
Overlap: 0 bits → SKIP (no allocation, no distance computation)
```

#### Layer 2: Length Ratio Check (zero allocation)

If the trigram filter passes, a quick check ensures the raw window length is within 70% of the variant length. This catches cases where the trigram filter produces false positives due to hash collisions.

#### Layer 3: Myers' Bit-Vector Levenshtein with Ukkonen Cut-Off

For the small percentage of windows that pass both pre-filters, the scanner normalizes the window text (lowercase, strip punctuation, collapse whitespace) into a **stack buffer** (zero heap allocation), then computes the edit distance using **Myers' bit-vector algorithm**:

- Encodes the pattern as a set of 64-bit bitmasks (one per character)
- Processes the text character-by-character using bitwise operations
- Computes exact Levenshtein distance in **O(n)** time for patterns ≤ 64 characters
- **Ukkonen cut-off**: if the running score exceeds the maximum allowable distance at any column, the algorithm aborts early — most non-matching windows terminate after 2-3 characters

```
Variant: "john doe"  (8 chars, max_distance = 1 for 80% threshold)
Window:  "j0hn doe"  (8 chars)
Distance: 1 (one substitution: o→0)
Similarity: 1 - 1/8 = 0.875 ≥ 0.80 → MATCH → replace with alias
```

#### Name Variant Generation

For each entity name, the matcher generates multiple variants:
- **Full name**: `"john doe"` (normalized)
- **First name only**: `"john"` (if ≥ 3 characters)
- **Last name only**: `"doe"` (if ≥ 3 characters)

This ensures partial references like just `"Doe"` or `"John"` are also caught.

#### Gap-Aware Scanning

Stage 3 only scans the **gaps** between regions already masked by Stages 1 and 2. In practice, Stage 2 catches 90%+ of name occurrences exactly, so Stage 3 only processes the remaining fragments. This is a critical performance optimization.

**Source**: [`src/fuzzy_match.zig`](src/fuzzy_match.zig)

## Benchmarks

All benchmarks run with `zig build bench-all 2>$null` (ReleaseFast, single-threaded):

```
=== NanoMask Pipeline Benchmarks ===

Stage 1 | SIMD SSN Redaction  | 16,000 MB/s | 100 iter × 1 MB
Stage 2 | Aho-Corasick Mask   |    564 MB/s |  50 iter × 1 MB
Stage 3 | Myers' Fuzzy Match  |    212 MB/s |  10 iter × 256 KB
```

**Real-world throughput**: For a typical 50 KB clinical document, the entire 3-stage pipeline completes in **< 0.5 ms**. Network round-trip to the upstream (10-50 ms) dominates total latency.

**Optimization history**:
| Version | Stage 3 Throughput | Key Change |
|---|---|---|
| v1 (baseline) | 0.3 MB/s | Naive normalize + Levenshtein per window |
| v2 (+trigram filter) | 9.0 MB/s | 128-bit bloom filter rejects 95% of windows |
| v3 (+stack normalize + Ukkonen) | 193 MB/s | Zero-alloc normalization + early-exit distance |

## Architecture

```
Client ──► NanoMask Proxy (:8081) ──► Upstream API
              │
              ├─ Stage 1: SIMD SSN Redaction (in-place)
              ├─ Stage 2: Aho-Corasick Name → Alias
              ├─ Stage 3: Fuzzy Match OCR variants → Alias
              │
              ▼ (request body is now de-identified)
           Upstream
              │
              ▼ (response flows back)
              ├─ Unmask: Alias → Name (Aho-Corasick reverse)
              │
Client ◄──── Response with real names restored
```

**Threading model**: Thread-per-connection with atomic connection counter (default cap: 128). All handler threads share a single `std.http.Client` with a thread-safe, built-in connection pool (keep-alive, default 32 upstream connections).

See [`architecture.md`](architecture.md) for the full technical design and [`backlog.md`](backlog.md) for planned improvements.

## Project Structure

```
src/
├── main.zig                          # Entry point, server setup, thread management
├── root.zig                          # Module root for test discovery
├── bench.zig                         # Standalone benchmark runner
├── net/
│   ├── proxy.zig                     # HTTP proxy handler, pipeline orchestration
│   ├── body_policy.zig               # Content-type classification and body handling policy
│   └── http_util.zig                 # HTTP response helpers
├── redaction/
│   ├── redact.zig                    # Stage 1: SIMD SSN redaction
│   ├── entity_mask.zig               # Stage 2: Aho-Corasick entity masking/unmasking
│   └── fuzzy_match.zig               # Stage 3: Fuzzy name matching (Myers' + trigram filter)
├── patterns/
│   ├── scanner.zig                   # Unified single-pass pattern scanner
│   ├── email.zig                     # Email address redaction
│   ├── phone.zig                     # US phone number redaction
│   ├── credit_card.zig               # Credit card redaction (Luhn validation)
│   ├── ip_address.zig                # IPv4/IPv6 address redaction
│   └── healthcare.zig                # Healthcare ID redaction (MRN, ICD-10, Insurance)
├── schema/
│   ├── schema.zig                    # JSON schema parser for field-level redaction
│   ├── json_redactor.zig             # Schema-aware JSON body redactor
│   └── hasher.zig                    # HMAC-based deterministic pseudonymisation
├── entity/
│   ├── versioned_entity_set.zig      # RCU-managed entity set for hot-reload
│   └── file_watcher.zig              # Poll-based entity file watcher for hot-reload
├── infra/
│   ├── config.zig                    # CLI + env var configuration with precedence chain
│   └── logger.zig                    # Thread-safe structured JSON logger (NDJSON output)
├── admin/
│   └── admin.zig                     # REST API for entity management (/_admin/entities)
├── crypto/
│   └── tls.zig                       # TLS 1.3 server handshake, record layer, encrypted I/O
└── test/
    ├── compliance_suite.zig          # E2E compliance tests (SSN, entity, pattern, schema)
    ├── e2e_harness.zig               # E2E test harness (proxy round-trip helper)
    └── mock_upstream.zig             # Mock HTTP upstream for E2E testing
```

## Testing

```bash
# Run all 250+ tests
zig build test

# Run benchmarks (ReleaseFast, clean output on Windows)
zig build bench-all 2>$null

# Run only fuzzy match tests
zig test src/fuzzy_match.zig

# Run a specific test by name
zig test src/fuzzy_match.zig --test-filter "OCR corrupted"
```

## Configuration

NanoMask supports a strict configuration precedence:
`CLI Flag` (highest) > `Environment Variable` > `Compiled Default` (lowest)

| Setting | CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|---|
| Listen host | `--listen-host` | `NANOMASK_LISTEN_HOST` | `127.0.0.1` | Bind address for the proxy listener; use `0.0.0.0` for gateway mode or `::` for dual-stack IPv6 |
| Listen port | `--listen-port` | `NANOMASK_LISTEN_PORT` | `8081` | Port the proxy listens on |
| Target host | `--target-host` | `NANOMASK_TARGET_HOST` | `httpbin.org` | Upstream server hostname |
| Target port | `--target-port` | `NANOMASK_TARGET_PORT` | `80` | Upstream server port |
| Entity file | `--entity-file` | `NANOMASK_ENTITY_FILE` | none | Path to file containing entity aliases |
| Fuzzy threshold | `--fuzzy-threshold` | `NANOMASK_FUZZY_THRESHOLD`| `0.80` (80%) | Minimum similarity for fuzzy match |
| Max connections | `--max-connections` | `NANOMASK_MAX_CONNECTIONS`| `128` | Concurrent connection limit |
| Log level | `--log-level` | `NANOMASK_LOG_LEVEL` | `info` | Logging level (`debug`, `info`, `warn`, `error`) |
| Watch interval | `--watch-interval` | `NANOMASK_WATCH_INTERVAL` | `1000` | Entity file poll interval in ms |
| Admin API | `--admin-api` | `NANOMASK_ADMIN_API` | disabled | Enable `/_admin/entities` REST endpoints |
| Admin token | `--admin-token` | `NANOMASK_ADMIN_TOKEN` | none | Require Bearer token for admin endpoints |
| Entity sync | `--entity-file-sync` | `NANOMASK_ENTITY_FILE_SYNC` | disabled | Write API entity changes back to entity file |
| TLS certificate | `--tls-cert` | `NANOMASK_TLS_CERT` | none | PEM certificate file for TLS (requires `--tls-key`) |
| TLS private key | `--tls-key` | `NANOMASK_TLS_KEY` | none | PEM private key file for TLS (requires `--tls-cert`) |
| Target TLS | `--target-tls` | `NANOMASK_TARGET_TLS` | disabled | Enable HTTPS for upstream connections |
| Unsupported request bodies | `--unsupported-request-body-behavior` | `NANOMASK_UNSUPPORTED_REQUEST_BODY_BEHAVIOR` | `reject` | Behavior for unsupported or non-identity request bodies: `bypass` or `reject` |
| Unsupported response bodies | `--unsupported-response-body-behavior` | `NANOMASK_UNSUPPORTED_RESPONSE_BODY_BEHAVIOR` | `bypass` | Behavior for unsupported or non-identity response bodies when NanoMask would need to transform them |
| CA file | `--ca-file` | `NANOMASK_CA_FILE` | system CAs | Custom CA bundle PEM for upstream TLS verification |
| Suppress system CAs | `--tls-no-system-ca` | `NANOMASK_TLS_NO_SYSTEM_CA` | disabled | Suppress system CA bundle; use with `--ca-file` for self-signed certs |
| Log file | `--log-file` | `NANOMASK_LOG_FILE` | stderr | Write structured JSON logs to file (append mode) |
| Audit log | `--audit-log` | `NANOMASK_AUDIT_LOG` | disabled | Enable per-redaction audit events in log output |

*Note: Per-request `X-ZPG-Entities` header overrides the entity names loaded from the file or compiled defaults.*

> **Listener TLS**: When both `--tls-cert` and `--tls-key` are provided, NanoMask performs a full TLS 1.3 handshake on each accepted connection using AES-128-GCM-SHA256 with X25519 key exchange. The encrypted reader/writer wraps the raw socket transparently — the HTTP server and redaction pipeline operate on plaintext. Supports ECDSA P-256 and Ed25519 private keys in PKCS#8 PEM format.

> **Upstream TLS**: When `--target-tls` is enabled, NanoMask connects to the upstream server over HTTPS. By default the system CA bundle is used for certificate verification. Use `--ca-file` to specify a custom CA bundle (e.g., for internal PKI or GovCloud environments). Use `--tls-no-system-ca` to suppress the system CA bundle and rely solely on `--ca-file` for trust anchors (e.g., self-signed certificates).

### Structured Logging

NanoMask outputs newline-delimited JSON (NDJSON) to stderr by default. Each log line contains `ts`, `level`, `session_id`, and `msg` fields. Request lifecycle events include `request_received`, `upstream_forwarded`, and `response_sent`; payload decision logs also include `body_policy`, `content_type`, and `content_encoding`. Response forwarding logs now include `response_mode`, `buffer_reason`, and `flush_per_chunk` so operators can distinguish streamed pass-through traffic from intentionally buffered restore flows. Enable file output with `--log-file <path>` and audit events with `--audit-log`.

When `--audit-log` is enabled, NanoMask emits additional `event="redaction_audit"` lines for every SSN match, exact entity mask, fuzzy entity match, pattern-library match, and schema `REDACT`, `HASH`, or `SCAN` action. Audit events include `stage`, `match_type`, `original_length`, `replacement_type`, and either `offset` or `field_path`; fuzzy events also include `confidence`. Original sensitive values are never written to the audit log.

Example audit event:

```json
{"event":"redaction_audit","stage":"schema","match_type":"schema_hash","field_path":"internal_id","original_length":8,"replacement_type":"pseudonymized"}
```

To keep noisy payloads from overwhelming operators, NanoMask caps audit emission at 256 events per request and logs `audit_event_cap_reached` if additional events were dropped.

### Health and Metrics

`GET /healthz` is the liveness endpoint. It returns HTTP 200 with a JSON body:

```json
{"status":"ok","uptime_s":3600,"connections_active":5,"connections_total":1200,"version":"0.1.0"}
```

`GET /readyz` is the readiness endpoint. It returns HTTP 200 while NanoMask is ready to serve traffic and HTTP 503 when startup state or entity hot-reload health is broken.

```json
{"status":"ready","startup":"ok","entity_reload":"ok","entity_reload_success_total":3,"entity_reload_failure_total":0,"version":"0.1.0"}
```

`GET /metrics` exposes Prometheus text format on the same listener. The built-in series include:

- request totals
- end-to-end request latency histogram
- upstream latency histogram
- downstream response status counts
- request and response bytes processed
- redaction matches by stage
- active connections
- entity reload success and failure totals
- dropped structured log lines

Recommended probe split:

- Liveness: `/healthz`
- Readiness: `/readyz`
- Prometheus scrape: `/metrics`

Helm can add scrape annotations for the shared Service:

```yaml
metrics:
  enabled: true
  path: /metrics
```

Health endpoints are logged at `DEBUG` level only to avoid log noise.

## License

See [LICENSE](LICENSE) for details.
