# The Zig Privacy Guard (ZPG) - Architecture

## Overview
The Zig Privacy Guard (ZPG) is a high-throughput, low-latency de-identification HTTP proxy engineered in pure Zig (0.15.2). It serves as a privacy firewall designed to intercept requests, scan for sensitive Personally Identifiable Information (PII) or Protected Health Information (PHI)—such as Social Security Numbers and personal names—and redact or pseudonymize them in-flight before they reach upstream LLM endpoints. Responses are de-pseudonymized on the return path.

## 1. Network Component Stack

Rather than relying on third-party frameworks like `zap`, the proxy is built entirely upon the Zig Standard Library's `std.http` module to ensure a zero-dependency footprint and native cross-platform compilation (specifically to support Windows development seamlessly).

### Core Components
*   **Listener (`std.net.Server`)**: Binds to a configurable listener address with `reuse_address` enabled to handle incoming TCP connections. The default is `127.0.0.1:8081` for sidecar-safe localhost binding, while gateway deployments can use `0.0.0.0:8081`.
*   **Ingress Server (`std.http.Server`)**: Wraps the incoming connection stream. Utilizes specific `reader.interface()` and `&writer.interface` generic IO wrappers to coerce buffered connection streams into HTTP Server objects.
*   **Egress Client (`std.http.Client`)**: Manages the outbound connection to the downstream API. Supports both bodiless (`sendBodilessUnflushed`) and body-forwarding (`sendBodyComplete`) modes depending on the request method.
*   **Thread-Per-Connection Model**: Each accepted connection is dispatched to a dedicated, short-lived thread via `std.Thread.spawn` (not a fixed-size pool). An atomic counter enforces a configurable connection cap. Per-thread HTTP clients are created to avoid shared mutable state; the session-level entity map is passed as read-only context.

## 2. Data Flow & Payload Buffering

The proxy intercepts the HTTP transaction in a bidirectional pipeline:

### Request Path (Client → LLM)
1.  **Header Parsing**: The incoming HTTP request head is parsed. The `X-ZPG-Entities` header is extracted (if present) to build a per-request entity map.
2.  **Body Reading**: The request body is read via `request.readerExpectContinue()` into a dynamic `ArrayListUnmanaged(u8)` buffer.
3.  **Privacy Pipeline**: Entity masking (names→aliases) followed by SSN redaction (digits→`*`) is applied to the body.
4.  **Forwarding**: The sanitized body is sent upstream via `sendBodyComplete()` with auto-set content-length.

### Response Path (LLM → Client)
1.  **Body Reading**: The upstream response is streamed into a dynamic buffer via `appendRemainingUnlimited()`.
2.  **De-pseudonymization**: Entity unmasking (aliases→names) restores original identifiers.
3.  **Relay**: The restored response is sent back to the client.

## 3. Redaction Rule Engine (`src/redaction/redact.zig`)

The core privacy mechanism lives in an isolated engine module.

### In-Place SIMD Scanning
To maintain maximum performance and avoid expensive heap-allocations or garbage collection pauses, the SSN redaction engine uses **in-place mutation**.
*   It loads 16 bytes at a time via `@Vector(16, u8)` and builds a bitmask of all `-` (dash) positions using a SIMD compare.
*   Windows with no dashes are skipped entirely (one compare + mask check). For each dash candidate, the surrounding bytes are validated against the full `\d{3}-\d{2}-\d{4}` pattern.
*   When a pattern match occurs, the digit positions are directly mutated to `*` within the same memory slice.
*   A 3-byte scalar rewind after the SIMD loop ensures no SSN is missed at window boundaries (SSN first dash is at offset +3 from start, so the rewind covers the maximum gap between a SIMD window edge and a valid SSN start).
*   Throughput: ~16,000 MB/s at ReleaseFast (1 MB payload, 100 iterations, single-threaded).

### Streaming Chunked SSN Redaction
For streaming proxy scenarios where the full body is not available at once, `redactSsnChunked` processes data in arbitrarily-sized chunks:
*   A `SsnChunkState` struct holds a 10-byte pending buffer (SSN is 11 bytes, so at most 10 bytes can span a boundary).
*   Each call returns a `SsnChunkResult` with two slices: `finalized` (boundary-scanned old pending bytes, safe to emit) and `emitted` (the chunk body minus the new pending tail).
*   Small chunks (< 10 bytes) accumulate in pending without emitting, ensuring SSNs are never split across uncommitted buffers.
*   A `flush()` method emits the final pending bytes at end-of-stream.
*   Correctness is verified by a 1 MB fuzz-equivalence test (chunked output == single-pass output for 64-byte chunks).

## 4. Entity Masking Engine (`src/redaction/entity_mask.zig`)

The entity masking engine provides dictionary-based name pseudonymization for PII/PHI de-identification — critical for healthcare and government use cases where names (not just SSNs) must be removed before payloads reach LLM APIs.

### Aho-Corasick Multi-Pattern Automaton
*   **Algorithm**: A trie-based state machine with BFS-computed failure links, converted into a fully deterministic goto-function after construction. This allows single-pass O(n) scanning regardless of how many name patterns are loaded.
*   **Case-Insensitive**: All trie transitions are case-folded via `std.ascii.toLower`, enabling matching of "JOHN DOE", "john doe", and "John Doe" from a single pattern entry.
*   **Word-Boundary Enforcement**: Matches are only accepted when surrounded by non-alphanumeric characters (or buffer edges), preventing partial matches like "John" inside "Johnson".
*   **Memory Profile**: Each trie node uses a 256-entry child array (1 KB). This is efficient for typical entity sets (dozens of names). For very large dictionaries (thousands of entries), a sparse child map would reduce memory — noted as future optimization.

### Bidirectional EntityMap
*   **`EntityMap`**: Session-level context holding a bidirectional name↔alias mapping with two pre-built automatons.
*   **`mask()`**: Replaces real names with deterministic aliases (`Entity_A`, `Entity_B`, ...). Used on the request path before payloads reach the LLM.
*   **`unmask()`**: Reverses aliases back to real names. Used on the response path to restore original names in LLM output.
*   **Overlap Resolution**: When multiple patterns match at overlapping positions, the engine uses leftmost-longest greedy selection.
*   **Entity Limit**: Up to 702 entities per session (A–Z = 26, AA–ZZ = 676). Exceeding this returns `error.TooManyEntities`.

### Dynamic Entity Loading
The `X-ZPG-Entities` header allows per-request entity specification:
```
X-ZPG-Entities: John Doe, Dr. Smith, Jane Williams
```
If present, a per-request `EntityMap` is built from the header values. Otherwise, the session-level default is used.

## 5. Fuzzy Name Matching Engine (`src/redaction/fuzzy_match.zig`)

Stage 3 of the redaction pipeline provides OCR-resilient name matching, catching corrupted or variant name forms that slip past the deterministic Aho-Corasick engine (e.g. "J0hn Doe", "Mr. Doe", "John E. Doe").

### Myers' Bit-Vector Levenshtein Algorithm
*   **Algorithm**: Computes edit distance between two strings in O(n) time using bitwise operations on a single `u64` register. For patterns ≤ 64 characters (covers all realistic names), this runs in a handful of CPU instructions per character.
*   **Threshold-Based**: Matches are accepted when normalized similarity ≥ configurable threshold (default 0.80 / 80%). Similarity is computed as `1 - (edit_distance / max_length)`.

### Text Normalization
Before comparison, both the pattern and input window are normalized: lowercased, punctuation stripped, and whitespace collapsed. This means `"John E. Doe"` and `"john  e doe"` are treated identically.

### Name Variant Generation
For each entity, the matcher auto-generates variants:
*   **Full name**: `"john doe"`
*   **First name only**: `"john"` (≥ 3 chars to avoid false positives)
*   **Last name only**: `"doe"` (≥ 3 chars to avoid false positives)

### Sliding Window Scanning
Words are extracted from the input and grouped into windows matching each variant's word count (and +1 to catch middle-initial insertions). Each window is normalized and compared using Myers' distance.

### Gap-Aware Processing
The fuzzy matcher receives a list of regions already masked by Stage 2 (Aho-Corasick) and only scans the gaps between them, avoiding double-redaction and wasted work.

### Privacy Pipeline Order
The proxy applies redaction rules in sequence on the request path:
1.  **Entity Masking** (names → aliases) — Aho-Corasick scan
2.  **SSN Redaction** (digits → `*`) — SIMD scan
3.  **Fuzzy Name Matching** (OCR variants → aliases) — Myers' bit-vector scan

On the response path:
1.  **Entity Unmasking** (aliases → names) — Aho-Corasick reverse scan

## 6. State Management

Connections are handled concurrently via `std.Thread.spawn` — each connection runs in its own thread with dedicated read/write buffers and HTTP server instance. A single `std.http.Client` is shared across all handler threads; its built-in `ConnectionPool` is thread-safe (uses `std.Thread.Mutex`) and reuses TCP connections with keep-alive (default 32 pooled connections). This eliminates per-request TCP handshake overhead. An atomic connection counter enforces a configurable cap (default 128) to prevent thread exhaustion under load. The session-level EntityMap and FuzzyMatcher are passed as read-only thread context; both are optional, enabling SSN-only proxy mode without entity masking.

**Phase 3 Scalability**: The current thread-per-connection model is a deliberate simplicity trade-off. An `io_uring`/IOCP-based event loop via `std.Io` would be the natural evolution for 10K+ concurrent connection workloads.

