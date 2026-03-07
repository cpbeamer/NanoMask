# NanoMask — Backlog

> **Status**: Phase 2 complete (3-stage pipeline + connection pooling ✅). Chunked SSN redaction (2.1) ✅ complete. Phase 3 Epics 1-2 (remaining tickets), Phase 4 (Production Readiness), and Phase 5 (Competitive Moat) are open.

---

## Phase 3 — Scalability

### Epic 1: IOCP / io_uring Event Loop

**Goal**: Replace `std.Thread.spawn` per connection with a `std.Io`-based event loop, scaling from 128 to 10,000+ concurrent connections.

**Context**: Zig 0.15.2 `std.Io` is the new cross-platform async I/O interface wrapping IOCP (Windows), io_uring (Linux), and kqueue (macOS). This is the idiomatic path forward.

#### 1.1 — Spike: `std.Io` event loop with accept + echo

**Type**: Research / Spike  
**Estimate**: 1 day  
**Depends on**: None

- Build a minimal TCP echo server using `std.Io` (non-blocking accept, read, write)
- Verify it compiles and runs on Windows (IOCP backend)
- Measure max concurrent connections vs. the current 128-thread model
- Document API surface, gotchas, and buffer ownership semantics

**Acceptance**: A standalone `spike_io.zig` that accepts 1,000+ concurrent connections and echoes data back.

---

#### 1.2 — Extract `ConnectionHandler` interface

**Type**: Refactor  
**Estimate**: 0.5 day  
**Depends on**: None (can start immediately)

- Extract `handleConnection` from `src/main.zig` into a `ConnectionHandler` struct with a well-defined interface
- Decouple `ThreadContext` from thread-specific assumptions (stack buffers)
- Pass read/write interfaces instead of raw `std.net.Server.Connection`

**Acceptance**: The existing thread-per-connection model works identically but the handler is decoupled from the threading model.

---

#### 1.3 — Implement `std.Io`-based accept loop

**Type**: Feature  
**Estimate**: 2 days  
**Depends on**: 1.1, 1.2

- Replace the `while (true) accept()` loop in `src/main.zig` with `std.Io`-based non-blocking accept
- Remove `std.Thread.spawn` and `active_connections` atomic counter
- Handle connection lifecycle (read head → process → write response → close) as I/O completion callbacks
- Configurable max connections (default 10,000)

**Acceptance**: `zig build run` starts the proxy in event-loop mode. Benchmark tool shows 1,000+ concurrent connections handled without thread exhaustion.

---

#### 1.4 — Graceful shutdown and connection draining

**Type**: Feature  
**Estimate**: 0.5 day  
**Depends on**: 1.3

- Handle `SIGINT` / `CTRL+C` to stop accepting new connections
- Drain in-flight connections before exiting
- Clean up GPA (currently unreachable due to infinite loop)

**Acceptance**: `Ctrl+C` triggers clean shutdown with "draining N connections" log message. No memory leaks.

---

### Epic 2: Streaming Chunked Redaction

**Goal**: Process request bodies in fixed-size chunks instead of buffering the entire payload. Critical for multi-MB clinical documents.

**⚠️ Risk**: Streaming complicates cross-chunk pattern matching. SSN patterns (11 chars) and name patterns can span chunk boundaries. The implementation must handle boundary overlaps correctly.

> ✅ **2.1 — Chunk-aware SSN redaction**: Complete. `redactSsnChunked()` is implemented in `src/redact.zig` with 4 tests including a 1 MB fuzz-equivalence verification.

> ✅ **2.2 — Chunk-aware Aho-Corasick masking**: Complete. `EntityMap.maskChunked()` processes overlapping boundaries seamlessly, achieving 567 MB/s throughput with a zero-allocation buffer and L2-cache compressed 64-character DFA node structure.

> ✅ **2.3 — Chunk-aware fuzzy matching**: Complete. `FuzzyMatcher.fuzzyRedactChunked()` processes multi-word boundary overlaps and translates local chunk coordinates with no performance penalty relative to raw baseline speeds (319 MB/s).

> ✅ **2.4 — Streaming proxy pipeline**: Complete. Implemented bidrectional streamed chunking and processing in `proxy.zig` and bound memory footprint to strictly < 64KB per connection.

---

#### 2.4 — Streaming proxy pipeline

**Type**: Feature  
**Estimate**: 1.5 days  
**Depends on**: 2.2, 2.3

- Replace full-body buffering in `src/proxy.zig` with a `while (read_chunk)` loop
- Each chunk flows through all three pipeline stages, then is written to the upstream immediately
- Use `Transfer-Encoding: chunked` for upstream when original content-length is unknown
- Track peak memory usage per connection (target: < 64 KB per connection vs. current full-body)

**Acceptance**: Proxy successfully handles a 10 MB request body with constant memory usage.

---

## Phase 4 — Production Readiness

> These items are **revenue blockers** — no paying customer can deploy NanoMask without them.

### Epic 3: Configuration Externalization

**Goal**: Remove all hardcoded config from source code. Ops teams must be able to configure the proxy without recompilation.

#### ✅ 3.1 — CLI argument parsing

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: None

- Create `src/config.zig` with a `Config` struct holding all runtime settings (listen port, target host/port, entity file path, fuzzy threshold, max connections, log level)
- Implement argument parser using `std.process.ArgIterator` — no external dependencies
- Support flags: `--listen-port <u16>`, `--target-host <string>`, `--target-port <u16>`, `--entity-file <path>`, `--fuzzy-threshold <f32>`, `--max-connections <u32>`, `--log-level <debug|info|warn|error>`
- Implement `--help` that prints formatted usage text with defaults and descriptions for every flag
- Validate all parsed values at startup: port ranges (1–65535), threshold (0.0–1.0), file existence for entity file
- Return clear, actionable error messages for invalid input (e.g., `error: --listen-port must be 1-65535, got '99999'`)
- Update `src/main.zig` to accept a `Config` struct instead of using `const` declarations
- Unit tests: valid parsing, missing values, out-of-range values, `--help` output, unknown flag handling

**Acceptance**: `zig-out/bin/nanomask --listen-port 9090 --target-host api.example.com --target-port 443` starts the proxy on port 9090 forwarding to `api.example.com:443`. `--help` prints complete usage. Invalid flags produce descriptive errors and exit with code 1.

---

#### ✅ 3.2 — Environment variable overrides

**Type**: Feature  
**Estimate**: 0.5 day  
**Depends on**: 3.1

- Read env vars via `std.process.getEnvVarOwned`: `NANOMASK_LISTEN_PORT`, `NANOMASK_TARGET_HOST`, `NANOMASK_TARGET_PORT`, `NANOMASK_ENTITY_FILE`, `NANOMASK_FUZZY_THRESHOLD`, `NANOMASK_MAX_CONNECTIONS`, `NANOMASK_LOG_LEVEL`
- Implement config precedence chain: CLI flag (highest) > env var > compiled default (lowest)
- Apply the same validation rules as CLI parsing (port ranges, threshold bounds, etc.)
- Log the resolved config source for each setting at startup (e.g., `listen_port=9090 (from CLI)`, `target_host=httpbin.org (default)`)
- Update README Configuration section with the full precedence table and all env var names
- Unit tests: env var override with no CLI flag, CLI flag overrides env var, invalid env var values

**Acceptance**: `NANOMASK_LISTEN_PORT=9090 zig build run` starts on port 9090. Adding `-- --listen-port 8080` overrides the env var. Startup log shows which source each config value came from.

---

#### 3.3 — Entity file loading

**Type**: Feature  
**Estimate**: 0.5 day  
**Depends on**: 3.1

- `--entity-file <path>` loads entity names from a newline-delimited text file (one name per line)
- Skip blank lines and lines starting with `#` (comments)
- Trim leading/trailing whitespace from each name
- Validate file exists and is readable at startup with clear error: `error: cannot open entity file '/path/to/file': FileNotFound`
- If no `--entity-file` and no `X-ZPG-Entities` header, proxy runs in SSN-only mode (no entity masking) — log a warning at startup
- Retain the existing `X-ZPG-Entities` header override — per-request headers take precedence over the file-loaded set
- Log entity count at startup: `loaded 47 entities from /etc/nanomask/entities.txt`
- Unit tests: file loading, comment skipping, whitespace trimming, missing file error, empty file handling, header override precedence

**Acceptance**: Proxy loads 100+ entities from file and masks them correctly in proxied requests. Per-request `X-ZPG-Entities` header still overrides the file-loaded set. Missing file produces a clear error at startup.

---

### Epic 4: TLS Support

**Goal**: Enable encrypted connections for GovCloud/HIPAA compliance. Without TLS, the proxy cannot be deployed in any regulated environment where data-in-transit encryption is mandated.

**Context**: HIPAA §164.312(e)(1) requires encryption of ePHI in transit. FedRAMP SC-8 requires confidentiality of transmitted information. NanoMask currently operates over plaintext HTTP, making it non-compliant by default.

#### 4.1 — TLS termination on the listener

**Type**: Feature  
**Estimate**: 2–3 days  
**Depends on**: 3.1 (needs `--tls-cert` and `--tls-key` CLI flags)

- Add CLI flags to `src/config.zig`: `--tls-cert <path>` (PEM certificate file) and `--tls-key <path>` (PEM private key file)
- Validate both flags are provided together — error if only one is given
- Wrap `std.net.Server` connection accept with `std.crypto.tls.Server` handshake
- If `std.crypto.tls.Server` is insufficient (Zig 0.15.2 TLS is still evolving), evaluate `iguanaTLS` or `bearssl-zig` as alternatives — document findings in a spike note
- When no cert/key provided, fall back to plaintext HTTP and log a warning: `WARNING: running without TLS — not suitable for production`
- Support TLS 1.2 and TLS 1.3 (reject TLS 1.1 and below)
- Ensure the TLS-wrapped reader/writer interfaces are compatible with the existing `std.http.Server` initialization (may require adapter layer)
- Test with self-signed certs generated via `openssl req -x509 -newkey rsa:2048`
- Benchmark: measure TLS handshake overhead per connection and throughput impact on the redaction pipeline

**Acceptance**: `curl https://localhost:8081/healthz --cacert ca.pem` returns a valid response over TLS 1.3. `openssl s_client -connect localhost:8081` shows the correct certificate chain. Without cert/key flags, proxy starts in plaintext mode with a warning.

---

#### 4.2 — TLS for upstream connections

**Type**: Feature  
**Estimate**: 1–2 days  
**Depends on**: 4.1

- Add CLI flag `--target-tls` (boolean) to enable HTTPS for upstream connections
- When enabled, configure `std.http.Client` to use TLS when connecting to the upstream host
- Use the system CA certificate bundle by default for certificate verification
- Add `--ca-file <path>` flag for custom CA bundles (common in GovCloud environments with internal PKI)
- Add `--tls-skip-verify` flag (off by default) for development/testing only — log a `CAUTION` warning when enabled
- Handle TLS handshake failures gracefully with descriptive error messages: `error: TLS handshake with upstream failed: CertificateVerifyFailed`
- Test against a real HTTPS endpoint (e.g., `https://httpbin.org/post`) and a self-signed upstream
- Unit tests: flag parsing, CA file loading, skip-verify warning

**Acceptance**: Proxy successfully forwards requests to `https://api.openai.com` with verified TLS. Custom CA file works for internal PKI. `--tls-skip-verify` logs a warning but connects to self-signed upstreams.

---

### Epic 5: Structured Logging & Audit Trail

**Goal**: Provide compliance-grade logging for HIPAA, FedRAMP, and ATO audits. Every proxied request must be traceable, and every redaction event must be auditable without leaking original PII values.

**Context**: HIPAA §164.312(b) requires audit controls. FedRAMP AU-2 requires auditable events. Current NanoMask has zero logging — unsafe for any regulated deployment.

#### 5.1 — Structured JSON log output

**Type**: Feature  
**Estimate**: 1.5 days  
**Depends on**: None

- Create `src/logger.zig` with a `Logger` struct supporting leveled output: `DEBUG`, `INFO`, `WARN`, `ERROR`
- Output format: newline-delimited JSON (one JSON object per line) for machine parseability
- Required fields per log entry:
  - `ts`: ISO 8601 timestamp with millisecond precision
  - `level`: log level string
  - `session_id`: unique request correlation ID (generated per connection)
  - `msg`: human-readable event description
- Request lifecycle events:
  - `request_received`: method, path, content-length, client IP (if available)
  - `request_processed`: bytes_in, bytes_out, ssns_redacted, entities_masked, fuzzy_matches, pipeline_latency_us
  - `upstream_forwarded`: target host, response status code, upstream_latency_us
  - `response_sent`: total_latency_us
- Log to stderr by default (standard for 12-factor apps in containerized environments)
- `--log-file <path>` flag for file-based output (append mode, create if not exists)
- `--log-level <level>` flag to control verbosity (default: `INFO`)
- Thread-safe: logger must handle concurrent writes from multiple connection handler threads without interleaving
- Use `std.Thread.Mutex` to serialize log writes, or use per-thread log buffers flushed atomically
- Unit tests: log level filtering, JSON validity of output, session ID uniqueness, thread-safety stress test

**Acceptance**: Every proxied request produces at least 3 structured log entries (received, processed, sent). Output is valid JSON parseable by `jq`. `--log-level DEBUG` shows pipeline internals. `--log-level ERROR` is silent for successful requests.

---

#### 5.2 — Redaction audit events

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: 5.1

- When `--audit-log` flag is enabled, emit detailed redaction events for each pattern match
- Audit event fields:
  - `event`: `"redaction"`
  - `session_id`: correlates to the parent request
  - `stage`: `"ssn"` | `"entity_mask"` | `"fuzzy_match"`
  - `position`: byte offset in the original payload where the match started
  - `original_length`: length of the original PII (not the value itself — never log PII)
  - `replacement`: the replacement string (e.g., `"***-**-****"`, `"Entity_A"`)
  - `confidence`: for fuzzy matches, the similarity score (e.g., `0.87`)
- Audit logging is opt-in (off by default) because it adds overhead for high-throughput deployments
- When disabled, the pipeline skips audit event construction entirely (zero overhead)
- Audit events are written to the same log stream (stderr or `--log-file`) at `INFO` level
- Machine-parseable for downstream SIEM ingestion (Splunk, Elastic, CloudWatch)
- Unit tests: audit events emitted per redaction, no PII in audit output, disabled by default

**Acceptance**: With `--audit-log`, a request containing 2 SSNs and 3 entity names produces 5 audit events. `grep '"event":"redaction"' log.json | jq .original_length` shows lengths but never original values. Without `--audit-log`, zero audit events are emitted.

---

#### 5.3 — Health check endpoint

**Type**: Feature  
**Estimate**: 0.5 day  
**Depends on**: None

- Intercept `GET /healthz` in `src/proxy.zig` before forwarding to upstream — handle directly in the proxy
- Return HTTP 200 with JSON body:
  ```json
  {
    "status": "ok",
    "uptime_s": 3600,
    "connections_active": 12,
    "connections_total": 4521,
    "version": "0.1.0"
  }
  ```
- Track `connections_active` (current in-flight) and `connections_total` (lifetime counter) using atomic counters
- Track `uptime_s` from server start timestamp
- Embed version string at compile time via `build.zig` option or `@embedFile`
- Return HTTP 503 with `{"status": "draining"}` during graceful shutdown (if Epic 1.4 is implemented)
- Do not log health check requests at `INFO` level to avoid log noise — log at `DEBUG` only
- Usable as K8s liveness probe (`livenessProbe.httpGet.path: /healthz`) and readiness probe
- Unit test: mock request to `/healthz` returns 200 with valid JSON, correct content-type header

**Acceptance**: `curl http://localhost:8081/healthz` returns `200 OK` with `Content-Type: application/json` and a valid JSON body. Uptime increases monotonically. Active connections reflects current load.

---

### Epic 6: Containerization & Hardened Deployment

**Goal**: Deliver NanoMask as a production-ready container image compatible with Iron Bank / DHI hardened image requirements. The business plan claims "Hardened by Default" — the container must back that claim.

**Context**: DoD Iron Bank requires non-root containers, minimal base images, no package managers in runtime, and CVE-free base layers. Distroless/scratch images satisfy these requirements.

#### 6.1 — Multi-stage Dockerfile

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: 3.1 (config externalization — binary must accept CLI flags / env vars)

- **Stage 1 (Builder)**: Use `ghcr.io/ziglang/zig:0.15.2` or equivalent as the build image
  - Compile with `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-musl` for a fully static binary
  - Run `zig build test` in the builder stage to catch regressions before packaging
- **Stage 2 (Runtime)**: Use `scratch` (zero-CVE, zero-package-manager) or `gcr.io/distroless/static:nonroot` as the runtime base
  - Copy only the compiled binary from Stage 1
  - Set `USER 65534:65534` (nobody) — non-root execution
  - Set `ENTRYPOINT ["/nanomask"]` with sane defaults via env vars
  - Read-only root filesystem (`--read-only` flag compatible)
  - Expose port 8081
- Add `HEALTHCHECK --interval=30s --timeout=3s CMD ["/nanomask", "--healthcheck"]` or use `wget`-less HTTP check
- Add `.dockerignore` to exclude `.git`, `zig-cache`, `zig-out`, `*.md`, and test artifacts
- Document image size target: < 10 MB (static Zig binary is typically 2–5 MB)
- Test: `docker build -t nanomask .`, `docker run --rm -p 8081:8081 nanomask`, verify proxy responds

**Acceptance**: `docker build -t nanomask .` produces a working image under 10 MB. `docker run --read-only --user 65534 nanomask` starts the proxy. `docker scan nanomask` (or `trivy image nanomask`) reports zero CVEs.

---

#### 6.2 — Helm chart + K8s manifests

**Type**: Feature  
**Estimate**: 1–2 days  
**Depends on**: 6.1, 5.3 (health check endpoint for probes)

- Create `charts/nanomask/` Helm chart with standard structure:
  - `Chart.yaml`: name, version, appVersion, description
  - `values.yaml`: configurable settings (image tag, listen port, target host/port, TLS cert/key, entity list, resource limits, replica count)
  - `templates/deployment.yaml`: Deployment with liveness/readiness probes pointing to `/healthz`, resource requests/limits, security context (non-root, read-only FS, drop all capabilities)
  - `templates/service.yaml`: ClusterIP Service exposing the proxy port
  - `templates/configmap.yaml`: Entity name list mounted as a volume
  - `templates/secret.yaml`: TLS cert/key (optional, only created when TLS values provided)
  - `templates/networkpolicy.yaml`: Restrict egress to only the configured upstream host/port and DNS
- Create `examples/sidecar-pod.yaml`: example Pod manifest with an application container + NanoMask as a sidecar
  - Application container sends requests to `localhost:8081` instead of the external API
  - NanoMask container forwards to the real upstream
  - Shared network namespace (default in Kubernetes pods)
- Create `examples/standalone-deployment.yaml`: NanoMask as a centralized gateway Deployment with an Ingress
- Security context in all manifests:
  ```yaml
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
  ```
- Add `NOTES.txt` template with post-install instructions

**Acceptance**: `helm install nanomask ./charts/nanomask --set target.host=httpbin.org` deploys a working proxy. `kubectl get pods` shows `Running` with passing health checks. `kubectl apply -f examples/sidecar-pod.yaml` creates a pod where the app container's traffic flows through NanoMask.

---

## Phase 5 — Competitive Moat

> Features that differentiate NanoMask from Presidio, Comprehend, and Google DLP.

### Epic 7: Expanded PII Pattern Library

**Goal**: Cover all PII types listed in the business plan. Currently only SSNs (formatted) and entity names are supported — every missing pattern type is a sales objection for enterprise buyers.

**Context**: Microsoft Presidio supports 50+ entity types. AWS Comprehend supports 30+. NanoMask's advantage is performing the same detection at 200x lower latency, but it must first support the patterns customers need.

#### 7.1 — Email address redaction

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: None

- Add `src/patterns/email.zig` (or extend `src/redact.zig` with a modular pattern registry)
- Use SIMD-accelerated `@` scanning (load 16 bytes, compare against `@`, build bitmask — same technique as SSN dash scanning)
- For each `@` candidate, scan left for the local part (alphanumeric, `.`, `+`, `-`, `_`) and right for the domain (alphanumeric, `.`, `-`, valid TLD)
- Validate minimum structure: `a@b.cc` (at least 1 char local, 1 char domain, 2 char TLD)
- Replace entire email with `[EMAIL_REDACTED]` (fixed-length replacement avoids offset tracking complexity)
- Handle edge cases: consecutive dots in domain (invalid), IP-literal domains `user@[192.168.1.1]`, internationalized domains (IDN — defer to future work)
- In-place mutation where possible; when replacement is shorter/longer than original, use the same owned-slice approach as entity masking
- Benchmark: target > 1 GB/s on typical text payloads (most 16-byte windows contain no `@`, so SIMD skip rate should be very high)
- Unit tests: standard emails, `+` aliases (`user+tag@gmail.com`), subdomains (`a@b.c.d.com`), long TLDs (`.museum`), invalid formats (no TLD, consecutive dots, missing local part), emails adjacent to punctuation

**Acceptance**: All valid emails in a test payload are replaced with `[EMAIL_REDACTED]`. Zero false positives on non-email `@` usage (e.g., `@mentions`, `@@decorators`). Benchmark exceeds 1 GB/s.

---

#### 7.2 — Phone number redaction

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: None

- Add `src/patterns/phone.zig`
- Support US phone number formats:
  - `(555) 123-4567`
  - `555-123-4567`
  - `555.123.4567`
  - `5551234567` (10 contiguous digits)
  - `+1-555-123-4567` (international prefix)
  - `1-555-123-4567` (domestic prefix)
- Use SIMD digit-density heuristic: scan 16-byte windows for digit count ≥ 7; skip windows with fewer (most text windows have 0–2 digits)
- When a high-density window is found, extract the full candidate region and validate against known formats
- Reject obviously invalid sequences: area codes starting with 0 or 1, 555-0100 through 555-0199 (fictional), all-same digits
- Replace with `[PHONE_REDACTED]`
- Handle edge cases: phone numbers embedded in longer digit sequences (e.g., order numbers), phone numbers adjacent to other PII types
- Unit tests: all supported formats, international prefix variations, embedded in prose, adjacent to SSNs, false positive rejection (ZIP codes, order numbers)

**Acceptance**: All US phone numbers in standard formats are detected and replaced. Zero false positives on 10-digit non-phone sequences (ZIP+4, order IDs). Formats with and without country code are handled.

---

#### 7.3 — Credit card number redaction

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: None

- Add `src/patterns/credit_card.zig`
- Detect 13–19 digit sequences with optional separators (dashes or spaces): `4111-1111-1111-1111`, `4111 1111 1111 1111`, `4111111111111111`
- Implement Luhn checksum validation to dramatically reduce false positives — only redact sequences that pass the Luhn check
- Recognize major card prefixes for additional confidence: Visa (`4`), Mastercard (`51-55`, `2221-2720`), Amex (`34`, `37`), Discover (`6011`, `65`)
- Replace with `[CC_REDACTED]`
- SIMD approach: scan for contiguous digit regions of length ≥ 13; extract candidate and validate
- Handle edge cases: partial card numbers (last 4 digits should NOT be redacted — common in receipts), test card numbers, digit sequences embedded in UUIDs or order numbers
- Unit tests: valid card numbers for each major network, Luhn validation (valid vs. invalid checksums), formatted vs. unformatted, partial card numbers, false positive rejection

**Acceptance**: All valid credit card numbers (Visa, MC, Amex, Discover) are detected and redacted. Luhn checksum eliminates false positives on random 16-digit sequences. Partial card numbers (last 4 digits) are not redacted.

---

#### 7.4 — IP address redaction

**Type**: Feature  
**Estimate**: 0.5 day  
**Depends on**: None

- Add `src/patterns/ip_address.zig`
- **IPv4**: Detect `N.N.N.N` patterns where each octet is 0–255
  - SIMD scan for `.` density (3 dots in close proximity) to identify candidates quickly
  - Validate octet ranges — reject `999.999.999.999` or `256.1.2.3`
  - Skip common false positives: version numbers (`v1.2.3.4`), file paths, decimal numbers in prose
- **IPv6**: Detect standard (`2001:0db8:85a3::8a2e:0370:7334`), compressed (`::1`), and IPv4-mapped (`::ffff:192.168.1.1`) formats
  - Scan for `:` density heuristic (multiple colons in close proximity)
  - Validate hex digit groups (1–4 hex chars between colons)
- Replace with `[IPV4_REDACTED]` or `[IPV6_REDACTED]`
- Optionally preserve subnet information: `192.168.1.0/24` → `[IPV4_REDACTED]/24` (configurable)
- Unit tests: valid IPv4 (all octet ranges), valid IPv6 (full, compressed, mapped), version numbers rejected, CIDR notation handling, loopback addresses

**Acceptance**: All valid IPv4 and IPv6 addresses are detected and replaced. Version numbers (`v2.1.0.3`) and decimal-heavy prose are not falsely matched. CIDR notation is handled.

---

#### 7.5 — Healthcare identifiers (MRN, ICD-10, Insurance ID)

**Type**: Feature  
**Estimate**: 1.5 days  
**Depends on**: 7.6 (benefits from custom pattern support, but can be hardcoded initially)

- Add `src/patterns/healthcare.zig`
- **Medical Record Numbers (MRN)**:
  - MRN formats vary by institution — typically 6–10 digit sequences, sometimes with a letter prefix (e.g., `MRN: 1234567`, `MR#12345678`)
  - Detect common prefixes: `MRN`, `MR#`, `Medical Record`, `Patient ID` followed by digit sequences
  - Context-aware: only match digit sequences when preceded by a known label (pure digit sequences alone are too ambiguous)
  - Replace with `[MRN_REDACTED]`
- **ICD-10 Codes**:
  - Format: `[A-Z][0-9]{2}` optionally followed by `.` and 1–4 alphanumeric chars (e.g., `E11.65`, `M54.5`, `Z87.891`)
  - Context-aware: look for surrounding medical terminology or structured fields to reduce false positives (e.g., standalone `A12` in prose should not match)
  - Replace with `[ICD10_REDACTED]`
- **Health Insurance IDs**:
  - Format varies by payer — typically alphanumeric, 8–15 characters
  - Detect common labels: `Insurance ID`, `Member ID`, `Policy #`, `Group #` followed by the identifier
  - Replace with `[INSURANCE_REDACTED]`
- All healthcare patterns should be opt-in via a `--healthcare` flag or config setting (they are PHI-specific and may cause false positives in non-healthcare contexts)
- Unit tests: valid MRNs with various prefixes, ICD-10 codes (all categories), insurance IDs with labels, false positive rejection in non-medical text

**Acceptance**: In a sample clinical document, all MRNs, ICD-10 codes, and insurance IDs preceded by labels are detected and replaced. Zero false positives in a general-purpose text payload. Healthcare patterns are disabled by default.

---

#### 7.6 — Custom pattern support

**Type**: Feature  
**Estimate**: 2 days  
**Depends on**: 3.3 (config file loading infrastructure)

- Extend the config system to support a pattern definition file (TOML or simple DSL):
  ```toml
  [[patterns]]
  name = "va_claim_number"
  label = "[VA_CLAIM_REDACTED]"
  format = "\\d{2}-\\d{5,8}"           # VA claim case numbers
  context = ["claim", "case number"]    # optional context keywords that must appear nearby

  [[patterns]]
  name = "badge_id"
  label = "[BADGE_REDACTED]"
  format = "[A-Z]{2}\\d{6}"            # agency badge numbers
  ```
- Implement a simple pattern DSL that compiles to a state machine at startup — **not a full regex engine**
  - Supported elements: `\d` (digit), `\a` (alpha), `\w` (word char), literal chars, `{n}` and `{n,m}` quantifiers, character classes `[A-Z]`, `[-]` (literal dash)
  - Deliberately omit: backreferences, lookahead/lookbehind, greedy/lazy quantifiers, alternation — keeps the matcher deterministic and fast
- Pre-compile all custom patterns at startup into a shared multi-pattern automaton (extend the Aho-Corasick trie, or build a separate DFA)
- Where possible, use Zig `comptime` to generate optimized matchers for patterns known at compile time
- Context keywords (optional): if specified, the pattern only matches when one of the context words appears within N bytes (configurable, default 50)
- Each custom pattern produces its configured replacement label
- Unit tests: pattern DSL parsing, quantifier expansion, context keyword proximity matching, multiple custom patterns in one file, invalid DSL syntax errors

**Acceptance**: A custom pattern file with 3 patterns is loaded at startup. Each pattern is detected and replaced with its configured label. Invalid pattern syntax produces a clear startup error. Benchmark shows custom patterns add < 5% overhead to the pipeline.

---

### Epic 8: JSON Schema-Aware Redaction

**Goal**: Use Zig `comptime` to generate optimized, zero-allocation redaction functions from user-defined JSON schemas. This is the single most differentiating feature versus Go/Python competitors — the business plan explicitly calls out "comptime schema optimization" as a key edge.

**Context**: Current NanoMask scans the entire request body through all 3 pipeline stages. For structured JSON payloads (which most LLM API calls are), this is wasteful — if we know that `patient_name` is always PII and `visit_date` is always safe, we can skip scanning 80%+ of the payload.

#### 8.1 — Schema definition format

**Type**: Design / Feature  
**Estimate**: 1 day  
**Depends on**: None

- Define a TOML schema format loaded via `--schema-file <path>`:
  ```toml
  [schema]
  name = "va_claim_form"
  version = "1.0"

  [fields]
  patient_name = "REDACT"      # replace entire value without scanning
  date_of_birth = "REDACT"
  visit_date = "KEEP"          # pass through untouched
  diagnosis_notes = "SCAN"     # run value through 3-stage pipeline
  internal_id = "HASH"         # deterministic pseudonymization
  claim_number = "REDACT"

  [fields.nested]              # support nested key paths
  "address.street" = "REDACT"
  "address.city" = "REDACT"
  "address.state" = "KEEP"
  "address.zip" = "REDACT"
  ```
- Parse schema at startup (or at `comptime` if schema is embedded at compile time)
- Validate schema against a sample payload: warn if the schema references keys not present in the sample (likely misconfiguration)
- Define behavior for keys not listed in the schema: configurable default (`SCAN` or `KEEP`)
- Support JSON key paths for nested objects: `"address.street"` matches `{"address": {"street": "123 Main St"}}`
- Unit tests: schema parsing, nested key resolution, unknown-key default behavior, invalid schema rejection

**Acceptance**: Schema file is loaded and parsed without errors. Schema validation against a sample payload identifies mismatches. Nested key paths resolve correctly.

---

#### 8.2 — Comptime schema codegen

**Type**: Feature  
**Estimate**: 3–4 days  
**Depends on**: 8.1

- Implement a streaming JSON key-matcher that identifies target keys during a single pass over the payload
  - Use a stack-based key path tracker: push key names on `{`, pop on `}`, build the full dotted path for comparison
  - When a key path matches a `REDACT` entry, skip scanning and replace the entire value string
  - When a key path matches `SCAN`, extract the value and run it through the 3-stage pipeline
  - When a key path matches `KEEP`, copy the value verbatim to the output
- For schemas known at compile time (embedded via `@embedFile`), use `comptime` to generate a perfect-hash key matcher
  - The hash function maps key names to their action (`REDACT`/`SCAN`/`KEEP`/`HASH`) in O(1)
  - No runtime string comparison for known keys — just a hash lookup
  - Fall back to runtime string matching for schemas loaded from config files
- Handle JSON edge cases:
  - String escaping (`\"`, `\\`, `\uXXXX`) — the key matcher must handle escaped quotes inside string values
  - Nested objects and arrays: maintain depth counter to avoid confusing nested `{` with top-level structure
  - Null values, boolean values, numeric values — `REDACT` on non-string values should replace with `null` or a configurable placeholder
- The output is a new JSON string with redacted/kept/scanned values — maintain valid JSON structure
- Benchmark against full-body scanning: target 2–5x throughput improvement on structured payloads (because `KEEP` fields are zero-copy and `REDACT` fields skip the pipeline entirely)
- Unit tests: comptime vs runtime codegen produces identical output, nested objects, arrays of objects, escaped strings, null/boolean/numeric values, unknown keys default handling

**Acceptance**: Schema-aware mode produces correctly redacted JSON for a sample VA claim form payload. Comptime codegen is verifiably faster than runtime matching in benchmarks. `KEEP` fields pass through untouched. `REDACT` fields are replaced without pipeline scanning. `SCAN` fields are processed through all 3 stages.

---

#### 8.3 — HASH mode (deterministic pseudonymization)

**Type**: Feature  
**Estimate**: 1–2 days  
**Depends on**: 8.2

- For fields marked `HASH` in the schema, generate a deterministic, reversible pseudonym
- Use HMAC-SHA256 with a session key: `HMAC(session_key, original_value)` → truncate to 16 hex chars → prefix with `PSEUDO_`
  - Example: `"John Doe"` → `"PSEUDO_a1b2c3d4e5f6g7h8"`
  - Same input + same session key always produces the same output (enables data linkage in analytics)
- Session key management:
  - `--hash-key <hex>` CLI flag for explicit key
  - Auto-generate a random key per session if not provided — log the key at startup for later reversal
  - `--hash-key-file <path>` for key stored in a file (K8s Secret-friendly)
- Implement reversal: given the session key and the HASH map, `unhash()` restores original values on the response path
  - Maintain an in-memory `HashMap(pseudo → original)` per session  
  - Look up each `PSEUDO_*` token in the response and replace with the original
- Use `std.crypto.auth.hmac.sha2.HmacSha256` from the Zig standard library (zero external deps)
- Handle collision resistance: 16 hex chars = 64 bits → collision probability is negligible for typical entity counts (< 10K per session)
- Unit tests: deterministic output (same input→same output), different inputs→different outputs, round-trip (hash then unhash), session key from CLI vs. auto-generated, collision resistance for 1000 unique values

**Acceptance**: A `HASH`-tagged field produces a deterministic `PSEUDO_*` token that is stable across requests with the same session key. `unhash()` on the response path restores the original value. A round-trip test (request→hash→upstream→response→unhash) produces the original payload.

---

### Epic 9: E2E Integration Testing

**Goal**: Validate the full round-trip proxy pipeline with a mock upstream server, proving zero PII leakage end-to-end. Unit tests validate individual stages; E2E tests validate the complete system including HTTP parsing, pipeline orchestration, and response unmasking.

**Context**: Current test suite (49 tests) covers individual redaction stages thoroughly, but no test exercises the actual proxy path: client → NanoMask → upstream → NanoMask → client. Without E2E tests, integration bugs (header handling, body buffering, entity map lifecycle) can slip through.

#### 9.1 — Mock upstream server

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: None

- Create `test/mock_upstream.zig` — a minimal HTTP server that:
  - Accepts POST requests on a configurable port
  - Records the received request body verbatim into a buffer (for later assertion)
  - Responds with a configurable response body (or echoes the request body)
  - Supports configurable response headers (Content-Type, custom headers)
  - Supports configurable response delay (for latency testing)
  - Runs in a separate thread so the test can drive both the mock and the proxy
- Create `test/e2e_harness.zig` — a test harness that:
  - Starts the mock upstream on a random available port
  - Starts NanoMask configured to forward to the mock upstream
  - Sends requests to NanoMask via `std.http.Client`
  - Asserts on: what the mock upstream received (should be PII-free), what the test client received (should have PII restored)
  - Tears down both servers after each test
- Handle port conflicts: use port 0 binding to let the OS assign available ports
- Unit tests for the mock server itself: request recording, echo mode, delay mode

**Acceptance**: `zig build test` runs E2E tests alongside existing unit tests. The mock upstream starts and stops cleanly. Request bodies are recorded and assertable.

---

#### 9.2 — Compliance test suite

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: 9.1, 7.1–7.5 (pattern library — test all supported PII types)

- Create `test/compliance_suite.zig` with test payloads containing every supported PII type:
  - SSNs in `NNN-NN-NNNN` format
  - Entity names (exact and fuzzy/OCR variants)
  - Email addresses
  - Phone numbers (all supported formats)
  - Credit card numbers (all major networks)
  - IPv4 and IPv6 addresses
  - Healthcare identifiers (MRN, ICD-10, insurance ID) when `--healthcare` enabled
- For each test case:
  - **Upstream assertion**: the body received by the mock upstream contains ZERO instances of any original PII
  - **Client assertion**: the response received by the test client has all aliases/tokens correctly restored to original values
  - **Idempotency assertion**: running the same payload through the proxy twice produces identical results
  - **Mixed payload assertion**: a single payload containing ALL PII types simultaneously is fully redacted
- Create a "worst case" payload: a 100 KB document with PII interspersed at random positions, including boundary-spanning patterns and adjacent PII types (SSN immediately followed by a name)
- Negative tests: payloads with no PII pass through unchanged, payloads with PII-like-but-invalid patterns (failed Luhn, invalid SSN `000-00-0000`) are not redacted
- Run as part of `zig build test` — all compliance tests must pass for CI to go green

**Acceptance**: Full compliance suite passes with zero PII leakage across all supported pattern types. Mixed-payload test proves all stages cooperate correctly. False positive rate is documented (target: < 0.1% on general text). CI enforces compliance tests on every PR.

---

## Dependency Graph

```
Phase 3 (Scalability):
  Epic 1 (Event Loop):
    1.1 Spike ──┐
    1.2 Extract ─┼──► 1.3 Event Loop ──► 1.4 Graceful Shutdown
                 │
  Epic 2 (Streaming):         (2.1 Chunked SSN ✅ done)
    2.2 Chunked AC ──────────┐
    2.3 Chunked Fuzzy ────────┼──► 2.4 Streaming Pipeline
         (depends on 2.2)

Phase 4 (Production Readiness):
  Epic 3 (Config):    3.1 CLI ──► 3.2 Env Vars
                             └──► 3.3 Entity File
  Epic 4 (TLS):       4.1 Listener TLS ──► 4.2 Upstream TLS
  Epic 5 (Logging):   5.1 Structured Logs ──► 5.2 Audit Events
                       5.3 Health Check (independent)
  Epic 6 (Container): 6.1 Dockerfile ──► 6.2 Helm Chart
                       (depends on 3.x, 5.3)

Phase 5 (Competitive Moat):
  Epic 7 (Patterns):  7.1–7.5 (independent, parallelizable)
                       7.6 Custom Patterns (depends on 3.3)
  Epic 8 (Schema):    8.1 Format ──► 8.2 Codegen ──► 8.3 HASH
  Epic 9 (E2E):       9.1 Mock Server ──► 9.2 Compliance Suite
                       (9.2 depends on 7.x for full coverage)
```

## Recommended Order

| Priority | Phase | Tickets | Rationale |
|---|---|---|---|
| **P0** | Phase 4 | 3.1 → 3.2 → 3.3 | Can't deploy without external config |
| **P0** | Phase 4 | 5.1 → 5.2, 5.3 | Compliance/audit logging is table stakes |
| **P0** | Phase 4 | 6.1 → 6.2 | Container image unlocks K8s deployment |
| **P1** | Phase 3 | 1.1 → 1.2 → 1.3 | Concurrency ceiling 128 → 10K+ |
| **P1** | Phase 4 | 4.1 → 4.2 | TLS required for regulated environments |
| **P2** | Phase 3 | 2.2 → 2.3 → 2.4 | Memory reduction for large docs (2.1 ✅) |
| **P2** | Phase 5 | 7.1 → 7.6 | Expand PII coverage to match competitors |
| **P3** | Phase 3 | 1.4 | Graceful shutdown polish |
| **P3** | Phase 5 | 8.1 → 8.2 → 8.3 | Comptime schema — key differentiator |
| **P3** | Phase 5 | 9.1 → 9.2 | E2E compliance testing |

> **Strategy**: Tackle Phase 4 (Production Readiness) first — it converts the engine into a deployable product. Then Phase 3 Epic 1 (event loop) and Phase 5 Epic 7 (patterns) in parallel to build both scalability and coverage.
