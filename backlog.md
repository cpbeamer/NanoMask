# NanoMask — Phase 3 Backlog

> **Status**: Epic 3 (Connection Pooling) is ✅ complete. Epics 1 and 2 below are the remaining work.

---

## Epic 1: IOCP / io_uring Event Loop

**Goal**: Replace `std.Thread.spawn` per connection with a `std.Io`-based event loop, scaling from 128 to 10,000+ concurrent connections.

**Context**: Zig 0.15.2 `std.Io` is the new cross-platform async I/O interface wrapping IOCP (Windows), io_uring (Linux), and kqueue (macOS). This is the idiomatic path forward.

### 1.1 — Spike: `std.Io` event loop with accept + echo

**Type**: Research / Spike  
**Estimate**: 1 day

- Build a minimal TCP echo server using `std.Io` (non-blocking accept, read, write)
- Verify it compiles and runs on Windows (IOCP backend)
- Measure max concurrent connections vs. the current 128-thread model
- Document API surface, gotchas, and buffer ownership semantics

**Acceptance**: A standalone `spike_io.zig` that accepts 1,000+ concurrent connections and echoes data back.

---

### 1.2 — Extract `ConnectionHandler` interface

**Type**: Refactor  
**Estimate**: 0.5 day  
**Depends on**: None (can start immediately)

- Extract `handleConnection` from `src/main.zig` into a `ConnectionHandler` struct with a well-defined interface
- Decouple `ThreadContext` from thread-specific assumptions (stack buffers)
- Pass read/write interfaces instead of raw `std.net.Server.Connection`

**Acceptance**: The existing thread-per-connection model works identically but the handler is decoupled from the threading model.

---

### 1.3 — Implement `std.Io`-based accept loop

**Type**: Feature  
**Estimate**: 2 days  
**Depends on**: 1.1, 1.2

- Replace the `while (true) accept()` loop in `src/main.zig` with `std.Io`-based non-blocking accept
- Remove `std.Thread.spawn` and `active_connections` atomic counter
- Handle connection lifecycle (read head → process → write response → close) as I/O completion callbacks
- Configurable max connections (default 10,000)

**Acceptance**: `zig build run` starts the proxy in event-loop mode. Benchmark tool shows 1,000+ concurrent connections handled without thread exhaustion.

---

### 1.4 — Graceful shutdown and connection draining

**Type**: Feature  
**Estimate**: 0.5 day  
**Depends on**: 1.3

- Handle `SIGINT` / `CTRL+C` to stop accepting new connections
- Drain in-flight connections before exiting
- Clean up GPA (currently unreachable due to infinite loop)

**Acceptance**: `Ctrl+C` triggers clean shutdown with "draining N connections" log message. No memory leaks.

---

## Epic 2: Streaming Chunked Redaction

**Goal**: Process request bodies in fixed-size chunks instead of buffering the entire payload. Critical for multi-MB clinical documents.

**⚠️ Risk**: Streaming complicates cross-chunk pattern matching. SSN patterns (11 chars) and name patterns can span chunk boundaries. The implementation must handle boundary overlaps correctly.

### 2.1 — Chunk-aware SSN redaction

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: None

- Modify `redactSsn` in `src/redact.zig` to accept a chunk + overlap buffer
- Maintain an 11-byte overlap window between chunks to catch SSNs spanning boundaries
- Unit tests: SSN split at every possible byte boundary across two chunks

**Acceptance**: `redactSsnChunked()` produces identical output to `redactSsn()` on the same input, verified by a comparison test on a 1 MB payload.

---

### 2.2 — Chunk-aware Aho-Corasick masking

**Type**: Feature  
**Estimate**: 1.5 days  
**Depends on**: None

- Add `EntityMap.maskChunked()` in `src/entity_mask.zig` that accepts a chunk + automaton state carry-over
- The Aho-Corasick automaton state (`current_node`) must persist between chunks
- Overlap buffer sized to `max_pattern_length` to handle matches spanning boundaries
- Alias replacement may change chunk length — output must be an owned slice per chunk

**Acceptance**: Round-trip test: `maskChunked` across N chunks → concatenate → equals `mask` on full buffer.

---

### 2.3 — Chunk-aware fuzzy matching

**Type**: Feature  
**Estimate**: 1 day  
**Depends on**: 2.1, 2.2

- `FuzzyMatcher.fuzzyRedactChunked()` in `src/fuzzy_match.zig` processes one chunk at a time
- Word-boundary overlap: carry the last 3 words from the previous chunk to handle multi-word windows spanning boundaries
- Masked regions from prior stages must be translated to chunk-local coordinates

**Acceptance**: Same round-trip test pattern as 2.2.

---

### 2.4 — Streaming proxy pipeline

**Type**: Feature  
**Estimate**: 1.5 days  
**Depends on**: 2.1, 2.2, 2.3

- Replace full-body buffering in `src/proxy.zig` with a `while (read_chunk)` loop
- Each chunk flows through all three pipeline stages, then is written to the upstream immediately
- Use `Transfer-Encoding: chunked` for upstream when original content-length is unknown
- Track peak memory usage per connection (target: < 64 KB per connection vs. current full-body)

**Acceptance**: Proxy successfully handles a 10 MB request body with constant memory usage.

---

## Dependency Graph

```
Epic 1 (Event Loop):
  1.1 Spike ──┐
  1.2 Extract ─┼──► 1.3 Event Loop ──► 1.4 Graceful Shutdown
               │
Epic 2 (Streaming):
  2.1 Chunked SSN ────────┐
  2.2 Chunked AC ──────────┼──► 2.4 Streaming Pipeline
  2.3 Chunked Fuzzy ──────┘
       (depends on 2.1, 2.2)
```

## Recommended Order

| Priority | Tickets | Rationale |
|---|---|---|
| **P1** | 1.1 → 1.2 → 1.3 | Concurrency ceiling 128 → 10K+ |
| **P2** | 2.1 → 2.2 → 2.3 → 2.4 | Memory reduction for large docs |
| **P3** | 1.4 | Production polish |

> **Tip**: Start with Epic 1 (event loop). It delivers the connection scalability needed for production. Epic 2 (streaming) has higher correctness risk due to cross-chunk boundary handling and should be tackled after the event loop is stable.
