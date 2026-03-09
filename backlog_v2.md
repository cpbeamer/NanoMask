# NanoMask Backlog V2

This file does not replace `backlog.md`. It is a customer-blocker-first backlog focused on turning NanoMask from a strong engine into a product that can win paid pilots and survive real buyer evaluation.

## Product Thesis

NanoMask should win as the fastest self-hosted privacy sidecar and gateway for regulated LLM and API traffic.

That means the backlog must prioritize:

- Proxy correctness before more pattern matching.
- Safe deployment before more benchmarks.
- Auditability and proof before bigger claims.
- Healthcare and government usability before generic feature sprawl.

## Priority Legend

- `P0`: Must ship before calling NanoMask a production-ready proxy.
- `P1`: Must ship before serious paid pilots and enterprise evaluations.
- `P2`: Important differentiation, scale, or expansion work after the core product is credible.

## Release Gates

### Gate 1: Pilot Ready

NanoMask can safely proxy real vendor traffic, preserve auth and streaming behavior, and deploy cleanly as a sidecar or gateway without obvious gotchas.

### Gate 2: Buyer Ready

NanoMask produces audit evidence, exposes metrics, has a documented compatibility matrix, and includes proof of accuracy on healthcare and PII workloads.

### Gate 3: Scale Ready

NanoMask can operate as a centralized gateway at materially higher concurrency with graceful shutdown, predictable memory use, and clear operational controls.

---

## Phase 1: Fix the Product Truth

### NMV2-001 - Add Payload Policy and Encoding Safety ✅ COMPLETED

**Priority:** P0  
**Estimate:** 3 days  
**Depends on:** None

**Goal**

Prevent NanoMask from corrupting binary or compressed payloads while making supported text and JSON payload handling explicit and predictable.

**Technical Scope**

- Parse `Content-Type` and `Content-Encoding` on both request and response paths.
- Introduce a body policy enum with at least `redact`, `bypass`, and `reject`.
- Default supported redactable types:
- `application/json`
- `application/*+json`
- `application/x-ndjson`
- `text/plain`
- `text/*`
- Default bypass types:
- `multipart/form-data`
- `application/octet-stream`
- `application/pdf`
- `image/*`
- `audio/*`
- `video/*`
- For upstream responses that must be unmasked or unhashed, force `Accept-Encoding: identity` unless explicit decompress and recompress support is added.
- Add structured logging fields for `body_policy`, `content_type`, and `content_encoding`.
- Add config flags for unsupported body behavior so operators can choose `bypass` or `reject`.

**Acceptance Criteria**

- A binary payload sent with `application/pdf` reaches the upstream byte-for-byte unchanged when policy is `bypass`.
- An unsupported body returns a clear `415 Unsupported Media Type` or equivalent when policy is `reject`.
- JSON and text payloads still run through the privacy pipeline.
- Gzip or Brotli response bodies are not silently mangled.
- README and examples clearly document which content types are supported for inline redaction.

**Plain English Value**

This stops NanoMask from being dangerous. A privacy product that can corrupt files or silently skip meaningful traffic will lose trust immediately.

### NMV2-002 - Preserve Request Header Fidelity and End-to-End Proxy Semantics

**Priority:** P0  
**Estimate:** 3 days  
**Depends on:** NMV2-001

**Goal**

Make NanoMask behave like a real reverse proxy instead of a partial body forwarder.

**Technical Scope**

- Forward all end-to-end request headers by default.
- Strip only hop-by-hop headers such as `Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authenticate`, and `Proxy-Authorization`.
- Preserve `Authorization`, `Accept`, `User-Agent`, `Cookie`, `Accept-Language`, idempotency keys, vendor headers, and tracing headers.
- Preserve path and query string exactly.
- Set `Host` behavior explicitly and document whether it is rewritten to the upstream host.
- Add tests for OpenAI-style, Anthropic-style, Azure-style, and generic API headers.

**Acceptance Criteria**

- A request containing `Authorization: Bearer ...`, `Accept: text/event-stream`, `OpenAI-Beta`, `anthropic-version`, and `x-request-id` reaches the upstream unchanged except for hop-by-hop headers.
- Existing request body redaction still occurs before egress.
- Proxy behavior is covered by automated tests that fail on dropped auth or vendor headers.
- Logs do not leak secret values while still allowing header-presence debugging.

**Plain English Value**

Without this, NanoMask is not a drop-in product. Dropped auth or vendor headers will make customers conclude the proxy is unreliable before they ever care about speed.

### NMV2-003 - Preserve Response Headers and Streaming Semantics

**Priority:** P0  
**Estimate:** 4 days  
**Depends on:** NMV2-001, NMV2-002

**Goal**

Make downstream clients receive upstream responses correctly, including streaming LLM output.

**Technical Scope**

- Forward all end-to-end response headers by default.
- Strip only hop-by-hop response headers.
- Preserve `Set-Cookie`, `Cache-Control`, rate-limit headers, request IDs, content type, and vendor metadata.
- Keep chunked or streaming behavior intact for responses that do not require full buffering.
- Ensure `text/event-stream` is flushed incrementally and not buffered until completion.
- Document behavior when HASH mode or other transforms force response buffering.
- Add local integration tests for chunked JSON lines and SSE event streams.

**Acceptance Criteria**

- A local SSE client receives events incrementally rather than all at once at the end of the response.
- Response headers such as `Set-Cookie`, `x-request-id`, and vendor rate-limit headers survive the proxy.
- When a response is buffered for a feature reason, NanoMask logs that mode explicitly.
- First-token latency overhead is measured and documented against a local mock upstream.

**Plain English Value**

Streaming is the product for many LLM use cases. If users lose token streaming or response headers, they will choose a slower competitor that behaves correctly.

### NMV2-004 - Add Listen Host Configuration and Make Deployment Modes Honest

**Priority:** P0  
**Estimate:** 2 days  
**Depends on:** None

**Goal**

Fix the mismatch between how NanoMask actually binds and how the deployment manifests claim it works.

**Technical Scope**

- Add `--listen-host` and `NANOMASK_LISTEN_HOST`.
- Keep sidecar-safe localhost binding available.
- Support `0.0.0.0` for container and centralized gateway mode.
- Update Helm chart values, deployment templates, and examples to use the right bind address for each mode.
- Log the effective bind address and port at startup.
- Add tests or smoke checks for both sidecar and gateway configurations.

**Acceptance Criteria**

- Sidecar example works with `127.0.0.1`.
- Gateway example works with `0.0.0.0` and is reachable through the Kubernetes Service.
- Helm chart exposes bind address cleanly.
- Startup logs show the exact listener address in a way operators can verify.

**Plain English Value**

This removes a credibility-killer. Right now the manifests imply a network-reachable gateway mode that the binary does not actually support.

### NMV2-005 - Build a Compatibility Integration Test Matrix

**Priority:** P0  
**Estimate:** 4 days  
**Depends on:** NMV2-001, NMV2-002, NMV2-003, NMV2-004

**Goal**

Turn compatibility from a claim into a repeatable engineering asset.

**Technical Scope**

- Add local mock upstreams for:
- OpenAI-compatible JSON request and response flows
- Anthropic-style SSE streaming
- Azure OpenAI path and query conventions
- Generic JSON REST APIs
- LiteLLM-style proxy headers
- Test request header fidelity, body mutation, response header fidelity, and streaming.
- Fail CI when a regression breaks compatibility.
- Generate a machine-readable compatibility matrix artifact from the test suite.

**Acceptance Criteria**

- CI runs the compatibility suite on every pull request.
- The repository includes a generated compatibility matrix with pass and fail status by flow type.
- A regression in auth header forwarding, SSE behavior, or vendor header handling breaks CI.

**Plain English Value**

This is how NanoMask stops losing on fear. Buyers trust products that can show exactly what traffic patterns they support.

---

## Phase 2: Make It Buyer Ready

### NMV2-006 - Wire Real Audit Event Emission Across All Redaction Paths

**Priority:** P1  
**Estimate:** 3 days  
**Depends on:** NMV2-005

**Goal**

Make the audit log feature real, not just configurable.

**Technical Scope**

- Emit audit events from:
- SSN redaction
- Entity masking
- Fuzzy matching
- Pattern-library matches
- Schema `REDACT`, `HASH`, and `SCAN` actions
- Include structured fields for stage, match type, offset or field path, original length, replacement type, and confidence where applicable.
- Ensure audit events do not leak the original sensitive value.
- Add sampling or rate controls if audit volume becomes too large.
- Document event schema and operator guidance.

**Acceptance Criteria**

- Enabling `--audit-log` produces actual redaction events during end-to-end requests.
- At least one integration test validates audit events for SSN, fuzzy name match, and schema-based redaction.
- Audit logs contain enough context to prove what happened without exposing the original secret.

**Plain English Value**

Auditors and security teams do not buy "trust us." They buy evidence. This ticket turns logging into evidence.

### NMV2-007 - Add Prometheus Metrics and Separate Liveness from Readiness ✅ COMPLETED

**Priority:** P1  
**Estimate:** 4 days  
**Depends on:** NMV2-005

**Goal**

Give operators the minimum observability they need to run NanoMask in production.

**Technical Scope**

- Add `/metrics` in Prometheus format.
- Add at minimum:
- request count
- request latency histogram
- upstream latency histogram
- response status counts
- bytes processed
- matches by redaction stage
- active connections
- entity reload success and failure counts
- dropped log line count
- Add `/readyz` separate from `/healthz`.
- Readiness should fail when critical startup dependencies or dynamic reload state are broken.
- Update Helm chart with optional metrics annotations or ServiceMonitor-compatible labels.

**Acceptance Criteria**

- Prometheus can scrape `/metrics` without custom parsing.
- `/healthz` answers basic process health and `/readyz` reflects service readiness.
- At least one chart example exposes metrics cleanly.
- Dropped log lines and reload failures are visible operationally.

**Plain English Value**

Ops teams will not deploy what they cannot observe. Metrics and correct health checks are mandatory table stakes.

### NMV2-008 - Add Graceful Shutdown, Draining, and Upstream Timeout Controls ✅ COMPLETED

**Priority:** P1  
**Estimate:** 4 days  
**Depends on:** NMV2-005

**Goal**

Make restarts safe and prevent hung upstreams from pinning worker capacity indefinitely.

**Technical Scope**

- Stop accepting new connections on shutdown signals.
- Drain in-flight requests before exit.
- Add configurable upstream connect, read, and overall request timeouts.
- Add clear timeout error responses and logs.
- Expose timeout settings via CLI, env, and Helm.
- Add tests for shutdown during active requests and for a deliberately hung upstream.

**Acceptance Criteria**

- A shutdown signal causes NanoMask to stop accepting new work and finish active work within a configurable window.
- Hung upstream requests do not block forever.
- Timeout settings are documented and configurable in all supported deployment paths.
- Logs show whether a request ended normally, timed out, or was drained during shutdown.

**Plain English Value**

Customers remember the day a proxy wedged a rollout or hung forever on an upstream call. This ticket prevents that story.

### NMV2-009 - Expose the Full Feature Surface in Config, Helm, and Docs

**Priority:** P1  
**Estimate:** 3 days  
**Depends on:** NMV2-005

**Goal**

Make the product you built actually usable by operators without reading the source.

**Technical Scope**

- Expose existing feature flags in Helm and examples:
- email
- phone
- credit card
- IP address
- healthcare patterns
- schema file
- schema default
- hash key and hash key file
- Fix `--help` to print the full help text instead of a single-line usage stub.
- Update README with supported features, supported payload types, streaming behavior, and known limitations.
- Remove or clarify claims that are broader than current support, especially around OCR documents or generic file handling.

**Acceptance Criteria**

- Every major runtime feature already present in config is represented in Helm values and at least one example deployment.
- `NanoMask.exe --help` or equivalent prints a complete help screen.
- README reflects the actual product behavior rather than a smaller or larger fictional version.

**Plain English Value**

This reduces time-to-first-value. If buyers cannot discover or configure the product cleanly, the code quality will not matter.

### NMV2-010 - Build an Accuracy and Benchmark Proof Harness

**Priority:** P1  
**Estimate:** 5 days  
**Depends on:** NMV2-005, NMV2-006, NMV2-007

**Goal**

Create repeatable proof that NanoMask is both fast and accurate.

**Technical Scope**

- Add curated test corpora for:
- SSNs
- names and fuzzy OCR variants
- email
- phone
- credit card
- IP
- healthcare identifiers
- schema-driven redaction payloads
- Measure precision, recall, and false-positive rate where feasible.
- Add end-to-end latency benchmarks for representative payload sizes and streaming flows.
- Emit a CI artifact in Markdown or JSON summarizing benchmark and accuracy results.
- Keep corpora anonymized and safe for source control.

**Acceptance Criteria**

- CI produces a benchmark and quality report on demand.
- The repo includes at least one healthcare-oriented representative corpus.
- A regression in detection quality or benchmark targets is visible in CI artifacts.

**Plain English Value**

This is how NanoMask beats competitors in a sales process. You need numbers for both speed and accuracy, not just claims.

### NMV2-011 - Harden the Admin API and Change-Control Plane

**Priority:** P1  
**Estimate:** 3 days  
**Depends on:** NMV2-006, NMV2-007

**Goal**

Make sure the control plane is not the easiest way to compromise the product.

**Technical Scope**

- Add audit events for entity add, remove, replace, and reload operations.
- Add optional admin bind address separate from the public proxy listener.
- Add optional IP allowlist for admin routes.
- Add read-only mode for environments that want visibility but no runtime mutation.
- Add rate limiting or simple abuse controls for entity mutation endpoints.
- Align docs and Helm comments with the actual requirement that admin auth is mandatory when enabled.

**Acceptance Criteria**

- Admin mutations generate structured audit events.
- Operators can bind admin endpoints to a safer listener or network scope.
- Unauthorized or abusive admin requests are rejected clearly.
- Documentation no longer implies anonymous admin mode is supported when it is not.

**Plain English Value**

Security buyers will inspect the admin plane immediately. If it looks weak, the entire product loses credibility.

---

## Phase 3: Differentiate for Regulated Workloads

### NMV2-012 - Add Streaming Schema-Aware Redaction for Large JSON Bodies ✅ COMPLETED

**Priority:** P2  
**Estimate:** 5 days  
**Depends on:** NMV2-001, NMV2-010

**Goal**

Keep schema mode usable for large healthcare and claims payloads without buffering the full body.

**Technical Scope**

- Replace full-body schema buffering with a bounded-memory streaming parser or a segmented pipeline that preserves schema action semantics.
- Preserve `KEEP`, `REDACT`, `SCAN`, and `HASH` behavior.
- Document any deliberate limitations around deeply nested streaming cases.
- Add benchmarks and memory measurements for large JSON payloads.

**Acceptance Criteria**

- A large JSON body can be processed in schema mode with bounded memory use.
- Existing schema behavior remains correct on nested payloads.
- The repo includes benchmark evidence for memory and latency in schema mode.

**Plain English Value**

Healthcare and claims payloads are often large. If the advanced mode only works by buffering everything, it becomes much less deployable.

### NMV2-013 - Ship a Healthcare Starter Pack

**Priority:** P2  
**Estimate:** 4 days  
**Depends on:** NMV2-009, NMV2-010, NMV2-012

**Goal**

Reduce time-to-value for the exact market NanoMask is targeting.

**Technical Scope**

- Add sample schemas for common regulated payloads such as patient demographics, encounter notes, and claims-like JSON.
- Add example entity files and policy presets.
- Add sample deployments for healthcare-focused traffic patterns.
- Add validation tests using representative sample payloads.
- Package the starter assets so they can be referenced cleanly from docs and examples.

**Acceptance Criteria**

- A new user can run NanoMask against a healthcare sample payload with minimal setup.
- Sample schemas are tested and versioned in the repo.
- Docs explain what each starter asset is for and when to modify it.

**Plain English Value**

Customers buy working examples close to their world. A healthcare starter pack turns NanoMask from a toolkit into a solution.

### NMV2-014 - Publish Integration Kits for the Ecosystems Buyers Already Use

**Priority:** P2  
**Estimate:** 4 days  
**Depends on:** NMV2-005, NMV2-009

**Goal**

Make NanoMask easier to adopt in the stacks buyers already have instead of asking them to invent the integration themselves.

**Technical Scope**

- Add working examples for:
- sidecar app container
- centralized Kubernetes gateway
- LiteLLM in front of vendor APIs
- generic OpenAI-compatible client configuration
- Add Docker Compose or local demo environments where practical.
- Add operator notes for auth, TLS, streaming, and health checks in each integration.

**Acceptance Criteria**

- Each integration example is runnable and tested at least at smoke-test level.
- README links directly to supported integration recipes.
- At least one example demonstrates streaming behavior end to end.

**Plain English Value**

This lowers the adoption cost. Buyers will choose the product that fits into their stack with the least friction.

### NMV2-015 - Refactor the Runtime for Higher-Concurrency Gateway Mode

**Priority:** P2  
**Estimate:** 6 days  
**Depends on:** NMV2-008

**Goal**

Make centralized gateway mode credible for higher concurrency workloads.

**Technical Scope**

- Extract a `ConnectionHandler` abstraction so the request pipeline is independent of the connection model.
- Replace or supplement thread-per-connection with a worker pool or `std.Io` event-driven model.
- Benchmark concurrency, memory usage, and latency against the current thread-per-connection approach.
- Preserve existing request correctness and redaction behavior.

**Acceptance Criteria**

- NanoMask handles materially higher concurrent connection counts than the current default model without thread exhaustion.
- Benchmarks compare old and new runtime behavior.
- The code clearly separates protocol handling from the connection scheduling model.

**Plain English Value**

This is what upgrades NanoMask from "great sidecar" to "serious shared gateway." It matters after correctness and trust are already solved.

---

## Suggested Execution Order

1. Ship NMV2-001 through NMV2-005 before making bigger product claims.
2. Ship NMV2-006 through NMV2-011 before serious pilot outreach.
3. Use NMV2-012 through NMV2-015 to sharpen differentiation after the product is operationally credible.

## Anti-Goals for Now

- Do not add more detection types before proxy correctness is fixed.
- Do not market PDF, image, or OCR ingestion unless the product actually handles those inputs end to end.
- Do not optimize for 10,000-connection gateway benchmarks before sidecar and low-scale gateway mode behave correctly.
