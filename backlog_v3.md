# NanoMask Backlog V3

This file does not replace `backlog.md` or `backlog_v2.md`. It builds on the product work already shipped and reorients the roadmap around becoming a competitive, buyer-ready product for regulated AI traffic. It merges insights from internal engineering analysis and external competitive gap assessment.

## Product Thesis

NanoMask should win as the fastest self-hosted privacy firewall for regulated AI and API traffic, especially in healthcare, claims, and government-adjacent environments.

That means the next backlog should prioritize:

- Proxy correctness and header fidelity before more performance claims.
- Buyer trust and security evidence before more low-level redaction features.
- Operator UX and evaluation tooling before enterprise control-plane sprawl.
- Enterprise controls and identity before wider market expansion.
- Document workflow coverage before generic platform sprawl.
- A narrow wedge for paid pilots before broad DLP ambitions.

## Current Strengths To Build On

- High-performance HTTP reverse proxy redaction for text and JSON payloads (16 GB/s SSN, 260 MB/s entity mask, 193 MB/s fuzzy match).
- Exact, fuzzy, schema-aware, and pattern-library redaction paths.
- Zero runtime, zero external dependencies, <10 MB binary.
- SIMD-accelerated + comptime schema optimization — unreplicable by Go/Python/Java competitors.
- Healthcare starter packs and deployment examples.
- Sidecar, gateway, LiteLLM, and OpenAI-compatible integration kits.
- Structured logs, audit events, health endpoints, and Prometheus metrics.
- Compatibility and proof harnesses already wired into the repo.
- TLS 1.3 end-to-end (listener + upstream, custom CA support).

## Current Product Constraints

- Request/response header forwarding and SSE streaming have known edge-case gaps (NMV2-002, NMV2-003 open).
- Product UX is still primarily CLI, environment variables, entity files, and schema files.
- Inline transformation focuses on text and JSON payloads, not full document pipelines.
- Listener-side TLS currently relies on a custom implementation.
- HASH restore is still an in-memory request/response convenience, not a true token vault.
- Entity alias generation caps at a fixed roster size (702).
- No web UI, management console, or dashboard exists.
- PII pattern coverage is US-centric (no international formats).
- No published Docker image, no landing page, no demo video.
- No compliance certifications or reusable security packet.

## Non-Goals For V3

- Do not try to become a full endpoint, browser, and SaaS DLP suite in this cycle.
- Do not chase every modality natively before the document ingestion story is coherent.
- Do not add more benchmark marketing unless buyer trust and operator UX improve in parallel.
- Do not broaden into a generic developer proxy brand before the regulated-AI wedge is proven.
- Do not add more detection types before proxy correctness is fixed.

## Priority Legend

- `P0`: Must ship before serious enterprise evaluations and security reviews.
- `P1`: Must ship before reliable paid pilots and repeatable procurement motion.
- `P2`: Important differentiation and expansion after the core offer is credible.

## Release Gates

### Gate 1: Product Truth

NanoMask behaves as a correct, drop-in reverse proxy and the compatibility matrix is enforced in CI.

### Gate 2: Trust Ready

NanoMask has a defensible TLS posture, a documented threat model, security testing automation, signed release artifacts, and a customer-ready security packet.

### Gate 3: Operator Ready

An operator can validate, tune, and deploy NanoMask without hand-editing raw config files for every workflow and without guessing why a policy changed behavior.

### Gate 4: Buyer Ready

NanoMask supports enterprise identity and control-plane expectations, exposes auditable evidence cleanly, has a published image and evaluation kit, and can survive a real pilot in a regulated environment.

### Gate 5: Expansion Ready

NanoMask handles document-centric workflows, larger identity sets, international PII, adjacent AI security controls, and cost-optimization features without losing its deployment simplicity or latency advantage.

---

## Phase 1: Fix Product Truth And Security

### NMV3-001 - Complete Request/Response Header Fidelity And SSE Streaming

**Priority:** P0
**Estimate:** 1 week
**Depends on:** None
**Carries forward:** NMV2-002, NMV2-003

**Goal**

Make NanoMask a correct, drop-in reverse proxy that preserves all headers and streaming semantics.

**Technical Scope**

- Forward all end-to-end request headers by default; strip only hop-by-hop headers.
- Preserve `Authorization`, `Accept`, `User-Agent`, `Cookie`, vendor headers (`OpenAI-Beta`, `anthropic-version`, `x-request-id`), idempotency keys, and tracing headers.
- Forward all end-to-end response headers by default; strip only hop-by-hop response headers.
- Preserve `Set-Cookie`, `Cache-Control`, rate-limit headers, request IDs, and vendor metadata.
- Fix Anthropic-style SSE incremental chunk fidelity so each event is flushed individually to the client.
- Ensure `text/event-stream` and chunked responses are not buffered until completion.
- Document behavior when HASH mode or other transforms force response buffering.
- Add automated tests for OpenAI, Anthropic SSE, Azure OpenAI, and generic API header patterns.
- Measure and document first-token latency overhead against a local mock upstream.

**Acceptance Criteria**

- A request containing `Authorization: Bearer ...`, vendor headers, and tracing headers reaches the upstream unchanged except for hop-by-hop headers.
- Response headers such as `Set-Cookie`, `x-request-id`, and rate-limit headers survive the proxy.
- A local SSE client receives Anthropic-style events incrementally, not collapsed.
- First-token latency overhead is measured and documented.

**Plain English Value**

Without this, NanoMask is not a drop-in product. Dropped auth or vendor headers will make customers conclude the proxy is unreliable before they ever care about speed.

### NMV3-002 - Enforce Compatibility Matrix In CI

**Priority:** P0
**Estimate:** 3 days
**Depends on:** NMV3-001
**Carries forward:** NMV2-005

**Goal**

Turn compatibility from a local artifact into a CI-enforced gate.

**Technical Scope**

- Run the compatibility suite (OpenAI JSON, Anthropic SSE, Azure OpenAI, Generic REST, LiteLLM headers) on every pull request.
- Fail CI when a regression breaks compatibility.
- Generate the machine-readable compatibility matrix artifact from the test suite.
- Add a CI badge or status check that buyers can see in the repo.

**Acceptance Criteria**

- CI runs the compatibility suite on every PR.
- A regression in auth header forwarding, SSE behavior, or vendor header handling breaks CI.
- The compatibility matrix artifact is generated automatically.

**Plain English Value**

Buyers trust CI badges over local JSON files. This is how NanoMask stops losing on fear.

### NMV3-003 - Choose And Implement A Production TLS Strategy

**Priority:** P0
**Estimate:** 1 week
**Depends on:** None

**Goal**

Remove "custom TLS" as an automatic buyer objection.

**Technical Scope**

- Make an explicit product decision:
  - Option A: terminate listener TLS with a battle-tested front proxy such as Envoy or NGINX and keep NanoMask behind it.
  - Option B: retain the in-repo TLS implementation but fund an external review and interoperability test plan.
- Document the supported deployment topologies for sidecar and gateway mode.
- Add reference manifests for the chosen TLS architecture.
- Update README and chart guidance so the recommended production path is unambiguous.

**Acceptance Criteria**

- NanoMask has one clearly documented recommended production TLS architecture.
- The recommended path is covered by automated smoke tests or deployment examples.
- A buyer can tell whether NanoMask itself terminates TLS in production or sits behind a hardened ingress tier.

**Plain English Value**

Custom TLS may be technically impressive, but it increases buyer anxiety and review time. This is the fastest way to reduce security skepticism.

### NMV3-004 - Add Threat Modeling, Security CI, And Supply-Chain Hardening

**Priority:** P0
**Estimate:** 1 week
**Depends on:** NMV3-003

**Goal**

Move NanoMask from "tested" to "security-engineered."

**Technical Scope**

- Write a STRIDE-based threat model covering ingress, egress, admin API, schema actions, token restore, logging, and deployment boundaries.
- Add dedicated fuzzing targets (AFL/libfuzzer) for payload parsing, schema parsing, alias restore, and admin API request handling.
- Add security-oriented CI checks for static analysis, linting, image scanning, and release validation.
- Generate an SBOM for release artifacts and container images (Executive Order 14028 requirement).
- Add release signing for binaries and OCI images.
- Create a security review checklist for every release.
- Test for request smuggling, header injection, and oversized header attacks.

**Acceptance Criteria**

- The repo contains a maintained threat model document.
- CI includes at least one dedicated security job beyond normal build and unit test execution.
- Release artifacts ship with SBOM metadata and a documented signing workflow.
- Fuzzing or adversarial parsing jobs exist for the highest-risk parsing surfaces.

**Plain English Value**

Enterprise buyers increasingly inspect the software supply chain as much as the app itself. This work gives NanoMask a credible answer.

### NMV3-005 - Produce An Independent Security Validation Pack

**Priority:** P0
**Estimate:** 2 weeks
**Depends on:** NMV3-003, NMV3-004

**Goal**

Create the evidence package needed to survive security review and procurement.

**Technical Scope**

- Run an external penetration test against the gateway and admin surfaces.
- Run TLS interoperability testing against the supported deployment path.
- Document remediation findings and closure status.
- Create a customer-facing security packet:
  - architecture summary
  - hardening guidance
  - network boundary explanation
  - logging and audit behavior
  - secrets and key handling summary
  - known limitations and compensating controls
- Draft a HIPAA BAA template for healthcare buyers.
- Document FedRAMP readiness status for federal buyers.

**Acceptance Criteria**

- A real external assessment exists and is tracked to closure.
- NanoMask has a reusable customer security packet instead of ad hoc answers.
- Known risks are documented with either fixes or explicit compensating controls.
- Draft HIPAA BAA and FedRAMP readiness docs exist.

**Plain English Value**

This turns security from a conversation into collateral. Without it, every pilot starts with weeks of distrust.

### NMV3-006 - Publish Docker Image And Demo Assets

**Priority:** P0
**Estimate:** 3 days
**Depends on:** NMV3-004

**Goal**

Let buyers try NanoMask in 30 seconds instead of building from source.

**Technical Scope**

- Publish the Docker image to GHCR with CI-automated builds on each release.
- Create a 60-second terminal recording (asciinema or GIF) showing PII → redacted → restored round-trip.
- Add a guided "try it now" section to the README with a copy-paste Docker command and sample PII payload.
- Group `--help` output by category (Network, Security, Redaction, Admin) for clarity.
- Add `--validate-config` mode that checks all configuration without starting the server.

**Acceptance Criteria**

- `docker pull ghcr.io/cpbeamer/nanomask:latest` works.
- README includes an embedded demo recording.
- A new evaluator can see NanoMask working within 30 seconds of reading the README.

**Plain English Value**

Buyers evaluate products they can try immediately. Building from source is a barrier that kills adoption.

---

## Phase 2: Operator UX And Productization

### NMV3-007 - Add Report-Only Mode And Evaluation Leak Reports

**Priority:** P0
**Estimate:** 1 week
**Depends on:** NMV3-004

**Goal**

Let teams evaluate NanoMask safely before they trust it to mutate live traffic.

**Technical Scope**

- Add a `--report-only` or `--shadow` mode where NanoMask detects and logs matches without changing the payload.
- Emit evaluation summaries with counts by stage, field, confidence band, and payload type.
- Add a machine-readable report artifact for pilot evaluations.
- Make this mode easy to enable in Helm and examples.

**Acceptance Criteria**

- Operators can run NanoMask in a non-mutating mode against representative traffic.
- The output clearly shows what would have been redacted and where.
- Pilot teams can compare redaction coverage before enabling active mutation.

**Plain English Value**

Security teams love products they can observe before they trust. This is a huge UX and adoption unlock.

### NMV3-008 - Build A Policy Playground With Before/After Diff

**Priority:** P1
**Estimate:** 2 weeks
**Depends on:** NMV3-007

**Goal**

Replace file-editing and curl-based experimentation with a product experience.

**Technical Scope**

- Build a minimal web console or local UI for testing policies.
- Support sample payload paste or upload for text and JSON.
- Show original payload, transformed payload, audit reasons, and stage-by-stage diff.
- Show when a result required buffering, bypass, reject, or stream-preserving behavior.
- Allow export of the resulting entity file, schema, and runtime config.
- Include a read-only dashboard tab showing:
  - Live request throughput and redaction counts
  - Audit event timeline
  - Entity list with search
  - Health/readiness status

**Acceptance Criteria**

- A new operator can validate a policy without editing raw files manually.
- The UI explains why a field was redacted, hashed, bypassed, or left unchanged.
- The resulting config can be exported into a deployable NanoMask setup.
- Non-technical stakeholders (CISOs, compliance officers) can see what NanoMask does.

**Plain English Value**

This is the most important UX work in V3. It converts NanoMask from a strong engine into something buyers can actually evaluate and demonstrate to their compliance teams.

### NMV3-009 - Add Schema And Entity Onboarding Wizard

**Priority:** P1
**Estimate:** 1 week
**Depends on:** NMV3-008

**Goal**

Make onboarding fast for real healthcare and claims payloads.

**Technical Scope**

- Support upload or paste of a representative JSON payload.
- Suggest initial schema actions based on field names, value types, and built-in healthcare heuristics.
- Generate starter entity lists from supplied rosters or representative names.
- Offer deployment presets for sidecar, gateway, and LiteLLM-style topologies.
- Emit a validation checklist for the generated config.

**Acceptance Criteria**

- A user can start from sample payload data and get a usable first policy in minutes.
- Generated artifacts map cleanly to NanoMask's existing runtime model.
- The onboarding flow works for at least one healthcare intake payload and one claims-like payload.

**Plain English Value**

Most buyers do not want to learn a config language before they see the product work. This shrinks time-to-value.

### NMV3-010 - Add Policy Versioning, Rollback, And Change Approval

**Priority:** P1
**Estimate:** 1 week
**Depends on:** NMV3-008

**Goal**

Make NanoMask safer to operate in teams.

**Technical Scope**

- Add versioned policy objects for schemas, entity sets, and runtime detection toggles.
- Record who changed what and when.
- Add rollback support to the last known-good policy.
- Add optional approval gating for production policy changes.
- Surface control-plane changes in audit and operator views.

**Acceptance Criteria**

- Operators can inspect, compare, and roll back policy revisions.
- Production changes no longer depend on editing raw files with no history.
- Audit records link policy changes to observed traffic behavior changes.

**Plain English Value**

This is how NanoMask becomes safe for real teams instead of just power users.

---

## Phase 3: Enterprise Control Plane And Observability

### NMV3-011 - Add SSO, RBAC, And Tenant-Scoped Policy Access

**Priority:** P1
**Estimate:** 2 weeks
**Depends on:** NMV3-010

**Goal**

Meet baseline enterprise control-plane expectations.

**Technical Scope**

- Add SSO support through a standard enterprise identity provider flow.
- Add role-based access controls for viewers, operators, and administrators.
- Scope policies, audit visibility, and config export by tenant, environment, or namespace.
- Enforce least-privilege defaults for admin operations.
- Add per-tenant entity sets, quota/rate limits, and audit streams for gateway mode.
- Add API key provisioning via admin API for multi-tenant deployments.

**Acceptance Criteria**

- A customer can integrate NanoMask with enterprise identity rather than local shared secrets alone.
- Roles cleanly separate read-only, tune, and mutate permissions.
- Tenant or environment boundaries are enforced consistently in the control plane.

**Plain English Value**

Enterprise buyers expect identity and access controls. Without them, the admin story feels unfinished no matter how good the proxy is.

### NMV3-012 - Add Audit Explorer And OTel/SIEM Export

**Priority:** P1
**Estimate:** 1 week
**Depends on:** NMV3-010

**Goal**

Make NanoMask's existing evidence usable by operations and compliance teams.

**Technical Scope**

- Add a searchable audit explorer view for redaction and admin events.
- Add export support for common observability and security pipelines.
- Add OpenTelemetry-compatible traces or logs (OTLP export).
- Add correlation IDs that link NanoMask audit events to upstream request tracing spans.
- Add stable field naming for SIEM ingestion.
- Add syslog forwarding support for legacy SIEM systems.
- Publish sample Fluentd/Fluent Bit sidecar examples in K8s manifests.
- Publish sample dashboards and alert queries.

**Acceptance Criteria**

- Operators can inspect audit data without tailing raw logs manually.
- NanoMask can feed common observability and SIEM tooling with minimal glue code.
- Customer-facing examples exist for at least one tracing path and one SIEM/log pipeline.

**Plain English Value**

The raw evidence already exists. This ticket makes that evidence operationally useful.

### NMV3-013 - Add Enterprise Key Management And Mutual Trust Options

**Priority:** P1
**Estimate:** 2 weeks
**Depends on:** NMV3-003, NMV3-011

**Goal**

Close major enterprise security gaps around secrets and trust boundaries.

**Technical Scope**

- Support external key sourcing through KMS, HSM, or a secret manager integration path.
- Add explicit key rotation handling for HASH and related features.
- Add mutual TLS (mTLS) support for zero-trust service-to-service deployments.
- Document trust-anchor and certificate lifecycle operations.

**Acceptance Criteria**

- NanoMask no longer depends only on inline secrets or local files for serious deployments.
- Operators can rotate keys with a documented procedure.
- Mutual-authenticated transport is available for environments that require it.

**Plain English Value**

This is the kind of checkbox that determines whether security architects approve or reject the product.

---

## Phase 4: Coverage, Scale, And Product Limits

### NMV3-014 - Finish Streaming Parity And Vendor Edge Cases

**Priority:** P1
**Estimate:** 1 week
**Depends on:** NMV3-007

**Goal**

Make streaming behavior boring and trustworthy across vendor styles.

**Technical Scope**

- Fix known chunk-fidelity issues for Anthropic-style SSE.
- Expand streaming compatibility tests to include long-lived sessions and partial flush behavior.
- Add more explicit operator logging for buffered versus streamed response paths.
- Re-test compressed, buffered, and transformed response edge cases.

**Acceptance Criteria**

- Streaming regressions break automated tests.
- Anthropic-style flows preserve incremental chunk behavior as expected by clients.
- Operators can tell exactly why a given response was buffered or streamed.

**Plain English Value**

For LLM products, streaming is not a bonus feature. It is a baseline product expectation.

### NMV3-015 - Remove Entity And Tokenization Scaling Ceilings

**Priority:** P1
**Estimate:** 2 weeks
**Depends on:** NMV3-013

**Goal**

Eliminate the most obvious scale-related product constraints.

**Technical Scope**

- Replace fixed alias naming limits (702 cap) with a larger or unbounded alias strategy.
- Rework HASH restore so it does not rely on a coarse global in-memory reverse map alone.
- Add request-scoped or persistent restore tracking where needed.
- Measure memory and throughput impact of larger identity sets and higher-cardinality token usage.
- Add operator visibility for eviction, lookup misses, and restore failures.

**Acceptance Criteria**

- NanoMask supports materially larger entity sets than the current fixed ceiling.
- HASH-mode behavior remains correct under larger, noisier workloads.
- Operators can detect when token restore or scale-related limits are affecting behavior.

**Plain English Value**

This removes hidden "it works in demo but not at scale" risks.

### NMV3-016 - Define And Ship A Document Workflow Strategy

**Priority:** P1
**Estimate:** 2 weeks
**Depends on:** NMV3-008

**Goal**

Bridge the gap between "JSON/text proxy" and the document-centric workflows buyers actually have.

**Technical Scope**

- Make a product decision between:
  - first-party document extraction and OCR support
  - a first-class partner integration path
  - a packaged upstream extraction service that feeds NanoMask clean text/JSON
- Ship one opinionated workflow for PDFs and scanned healthcare documents.
- Include examples, deployment templates, and validation guidance.
- Document where NanoMask begins and ends in the document pipeline.

**Acceptance Criteria**

- Buyers have a clear answer for PDF and scanned-document workflows.
- The recommended path is demonstrated end-to-end with starter assets.
- NanoMask's boundary with OCR and extraction tooling is explicit and productized.

**Plain English Value**

Many buyers think in terms of documents, not JSON. This ticket makes NanoMask feel like a solution instead of a component.

### NMV3-017 - Refactor Runtime For Higher-Concurrency Gateway Mode

**Priority:** P1
**Estimate:** 2 weeks
**Depends on:** NMV3-001
**Carries forward:** NMV2-015

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

## Phase 5: AI Security, Market Expansion, And Go-To-Market

### NMV3-018 - Add Guardrail Hooks For Prompt, Secret, And RAG Risks

**Priority:** P2
**Estimate:** 2 weeks
**Depends on:** NMV3-012

**Goal**

Expand NanoMask from privacy firewall to broader AI traffic control without losing focus.

**Technical Scope**

- Add a pluggable guardrail interface for prompt injection, secret detection (`BEGIN RSA PRIVATE KEY`, API keys), jailbreak indicators, code detection, and retrieval safety checks.
- Support alert-only and block modes.
- Keep guardrails optional so the core privacy path stays fast and predictable.
- Provide at least one reference integration with an external guardrail provider or an internal baseline rule set.

**Acceptance Criteria**

- NanoMask can evaluate AI-risk controls in the same request path without forcing every deployment to use them.
- Guardrail outcomes are auditable and operator-visible.
- The core privacy use case remains the default product story.

**Plain English Value**

This keeps NanoMask relevant as the market shifts from pure privacy tooling toward full AI gateways and control planes.

### NMV3-019 - Add International PII Pattern Coverage

**Priority:** P2
**Estimate:** 2 weeks
**Depends on:** NMV3-001

**Goal**

Expand pattern coverage beyond US-centric formats for broader enterprise adoption.

**Technical Scope**

- Add UK National Insurance Numbers, EU IBANs, passport number formats.
- Add non-US phone number formats (UK, EU common patterns).
- Add Unicode normalization for non-Latin entity names in Aho-Corasick.
- Add GDPR-specific patterns where they differ from US PII categories.
- Make new patterns opt-in via config flags to avoid false positives in US-only deployments.

**Acceptance Criteria**

- At least UK and EU PII patterns are supported with opt-in flags.
- Non-Latin entity names match correctly through the existing pipeline.
- Existing US-centric accuracy is unaffected.

**Plain English Value**

If NanoMask targets only US healthcare forever, the TAM is capped. This is how it becomes relevant to multinational buyers and GDPR-regulated environments.

### NMV3-020 - Add SDK Wrappers And Developer Experience Polish

**Priority:** P2
**Estimate:** 1 week
**Depends on:** NMV3-006

**Goal**

Meet developers where they already are.

**Technical Scope**

- Create lightweight Python and Node.js packages that auto-configure `base_url` pointing to NanoMask.
- Add `X-ZPG-Entities` header injection helpers.
- Add a `nanomask.verify()` test utility for CI integration.
- Add error message suggestions for common typos (e.g., "Did you mean `--target-tls`?").
- Improve startup banner with a formatted summary block: version, listener, upstream, enabled features, entity count.

**Acceptance Criteria**

- Python/Node packages are published and installable.
- A developer can switch from direct OpenAI SDK usage to NanoMask-proxied in <5 lines of code.
- Common configuration mistakes produce actionable error messages.

**Plain English Value**

Competitors like Private AI offer `from private_ai import PrivateAI`. NanoMask's "point your base_url at us" story is technically clean but feels manual. SDKs close that gap.

### NMV3-021 - Ship A Buyer Evaluation Kit And Pilot Package

**Priority:** P1
**Estimate:** 1 week
**Depends on:** NMV3-005, NMV3-008, NMV3-016

**Goal**

Turn the product into something sales and founders can actually take to market.

**Technical Scope**

- Build a reproducible evaluation kit for healthcare and claims buyers.
- Include:
  - reference deployment templates
  - sample data packs
  - report-only evaluation workflow
  - benchmark card
  - compatibility summary
  - security packet
- Create a single-page landing site with benchmarks, architecture diagram, competitor comparison ("NanoMask vs Presidio", "vs Private AI"), and quick-start instructions.
- Create a professional logo and branding package.
- Define pilot success criteria such as coverage, latency, false-positive rate, and deployment time.
- Write a standard pilot runbook for customer onboarding.

**Acceptance Criteria**

- A new prospect can run a structured evaluation without custom founder heroics.
- Pilot success criteria are documented before the pilot begins.
- NanoMask has a repeatable package for healthcare and regulated-AI evaluations.
- A landing page exists that positions the product against competitors.

**Plain English Value**

This is how the roadmap turns into revenue instead of remaining internal engineering progress.

### NMV3-022 - Package Commercial Offers Around The Wedge

**Priority:** P2
**Estimate:** 3 days
**Depends on:** NMV3-021

**Goal**

Create a simple commercial story that matches the product's strengths.

**Technical Scope**

- Define at least three motions:
  - pilot package
  - sidecar/team deployment
  - enterprise gateway deployment
- Tie packaging to support, security evidence, deployment mode, and control-plane capabilities.
- Define clear upgrade triggers between offers.
- Document the success metrics that justify expansion.

**Acceptance Criteria**

- NanoMask has a pricing and packaging draft aligned to the product roadmap.
- Expansion from pilot to paid deployment has a clear operational and commercial trigger.
- The commercial story reinforces the healthcare and regulated-AI wedge instead of diluting it.

**Plain English Value**

A strong product still loses if buyers cannot tell what they are buying and what success looks like.

### NMV3-023 - Add Semantic Caching For LLM Cost Reduction

**Priority:** P2
**Estimate:** 2 weeks
**Depends on:** NMV3-017

**Goal**

Turn NanoMask's inline position into a cost-saving story, not just a privacy story.

**Technical Scope**

- Cache de-identified prompt→response pairs to skip redundant upstream API calls.
- Add configurable TTL, max cache size, and per-tenant cache isolation.
- Add cache hit/miss metrics to Prometheus.
- Document cost reduction potential for common LLM workloads.

**Acceptance Criteria**

- Duplicate prompts hit cache and do not incur upstream API cost.
- Cache behavior is configurable and tenant-aware.
- Operators can see cache hit rates in metrics.

**Plain English Value**

LLM APIs are expensive. If NanoMask can demonstrably reduce API costs alongside providing privacy, it gets procurement attention from finance teams, not just security teams.

---

## Recommended Execution Order

If NanoMask needs a practical next-step sequence rather than parallel sprawl:

1. `NMV3-001` Request/response header fidelity and SSE streaming
2. `NMV3-002` Compatibility matrix in CI
3. `NMV3-003` TLS strategy decision
4. `NMV3-004` Security CI, threat model, SBOM
5. `NMV3-006` Published Docker image and demo assets
6. `NMV3-007` Report-only mode
7. `NMV3-005` External security validation pack
8. `NMV3-008` Policy playground and dashboard
9. `NMV3-010` Policy versioning and rollback
10. `NMV3-011` SSO and RBAC
11. `NMV3-012` Audit explorer and OTel/SIEM
12. `NMV3-014` Streaming parity
13. `NMV3-016` Document workflow strategy
14. `NMV3-015` Scale-limit removal
15. `NMV3-017` Gateway concurrency refactor
16. `NMV3-021` Buyer evaluation kit
17. `NMV3-018` AI guardrails
18. `NMV3-019` International PII patterns
19. `NMV3-020` SDK wrappers
20. `NMV3-022` Commercial packaging
21. `NMV3-023` Semantic caching

## Anti-Goals For This Cycle

- Do not add more detection types before proxy correctness is fixed.
- Do not market PDF, image, or OCR ingestion unless the product actually handles those inputs end to end.
- Do not optimize for 10,000-connection gateway benchmarks before sidecar and low-scale gateway mode behave correctly.
- Do not build a full SaaS management platform before the single-binary proxy story is airtight.

## Summary

Backlog V3 assumes the core engine is already compelling. The next product battle is proxy correctness, trust, usability, enterprise control, and buyer readiness.

If V2 made NanoMask a credible engine, V3 should make it a credible company product.
