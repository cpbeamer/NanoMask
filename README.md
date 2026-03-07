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

# Run benchmarks (ReleaseFast, clean output on Windows)
zig build bench-all 2>$null

# Run all tests (49 tests)
zig build test
```

### Configure

Edit `src/main.zig` to set your environment:

```zig
const listen_port: u16 = 8081;
const target_host = "your-llm-api.internal";
const target_port: u16 = 443;

// Entity names to mask (production: load from headers or config)
const demo_names = [_][]const u8{ "John Doe", "Jane Smith", "Dr. Johnson" };
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
Stage 2 | Aho-Corasick Mask   |    260 MB/s |  50 iter × 1 MB
Stage 3 | Myers' Fuzzy Match  |    201 MB/s |  10 iter × 256 KB
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
├── main.zig          # Entry point, server setup, thread management
├── proxy.zig         # HTTP proxy handler, pipeline orchestration
├── redact.zig        # Stage 1: SIMD SSN redaction
├── entity_mask.zig   # Stage 2: Aho-Corasick entity masking/unmasking
├── fuzzy_match.zig   # Stage 3: Fuzzy name matching (Myers' + trigram filter)
├── bench.zig         # Standalone benchmark runner
├── root.zig          # Module root for test discovery
└── test_reader.zig   # Test utilities
```

## Testing

```bash
# Run all 49 tests
zig build test

# Run benchmarks (ReleaseFast, clean output on Windows)
zig build bench-all 2>$null

# Run only fuzzy match tests
zig test src/fuzzy_match.zig

# Run a specific test by name
zig test src/fuzzy_match.zig --test-filter "OCR corrupted"
```

## Configuration

| Setting | Location | Default | Description |
|---|---|---|---|
| Listen port | `src/main.zig` | `8081` | Port the proxy listens on |
| Target host | `src/main.zig` | `httpbin.org` | Upstream server hostname |
| Target port | `src/main.zig` | `80` | Upstream server port |
| Entity names | `src/main.zig` or `X-ZPG-Entities` header | Demo set | Names to mask |
| Fuzzy threshold | `src/main.zig` | `0.80` (80%) | Minimum similarity for fuzzy match |
| Max connections | `src/main.zig` | `128` | Concurrent connection limit |
| Connection pool | `std.http.Client` default | `32` | Max pooled upstream connections |

## License

See [LICENSE](LICENSE) for details.
