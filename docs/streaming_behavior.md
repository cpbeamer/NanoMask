# NanoMask Streaming Behavior

NanoMask aims to be a minimal-overhead, drop-in reverse proxy. Understanding when it
streams versus buffers responses helps operators predict latency characteristics and
diagnose unexpected delays.

## Response Forwarding Modes

The proxy selects one of four `response_mode` values, logged in every `response_sent`
event:

| Mode | When Used | Body Behavior |
|---|---|---|
| `stream_passthrough` | Bypass policy, no response transform needed | Chunks forwarded 1:1 as received from upstream |
| `stream_unmask` | Entity unmasking required, identity-encoded body | Chunks individually unmasked then forwarded |
| `buffered` | HASH-mode JSON unhashing needed | Full body buffered, parsed, unhashed, then sent |
| `no_body` | HEAD request or 204/304 status | No body forwarded |

## Per-Chunk Flushing

For streaming modes, the proxy flushes each forwarded chunk immediately when the
response meets any of these conditions:

- **Content-Type** is `text/event-stream` (SSE) or `application/x-ndjson`
- **Transfer-Encoding** includes `chunked`
- The body is being streamed without content-length

This ensures that SSE events, NDJSON lines, and chunked responses arrive at the
client incrementally. The proxy logs `flush_per_chunk=true` when this behavior is
active.

## HASH-Mode Buffering

When the proxy detects that a response requires JSON unhashing (because the request
used schema `HASH` pseudonymisation), it cannot stream the response. Instead:

1. The full response body is read into memory.
2. The JSON is parsed and `PSEUDO_*` tokens are replaced with original values.
3. The restored body is sent to the client with a correct `Content-Length`.

The proxy logs `response_mode="buffered"` and `buffer_reason="json_unhash"` when this
happens, so operators can tell from structured logs why streaming was disabled for a
particular response.

**Impact**: The client does not receive any response body bytes until the upstream
completes. This is unavoidable because unhashing requires the full JSON parse tree.

## First-Token Latency

In streaming mode, first-token latency measures the time from the proxy starting to
receive the upstream response until the first body bytes are forwarded to the client.
The main contributors are:

- **Network read** — time for the first upstream chunk to arrive
- **Redaction overhead** — unmasking cost for the first chunk (typically < 1 ms)
- **Proxy buffering** — internal write buffer flush latency

The compatibility matrix measures `first_token_latency_ms` for each SSE and streaming
flow. In loopback tests, first-token latency is typically under 10 ms.

## Operator Log Fields

| Field | Values | Meaning |
|---|---|---|
| `response_mode` | `stream_passthrough`, `stream_unmask`, `buffered`, `no_body` | Which forwarding path was used |
| `buffer_reason` | `json_unhash`, `-` | Why buffering was forced |
| `flush_per_chunk` | `true`, `false` | Whether per-chunk flushing was active |
| `stream_event_count` | integer (only present when > 0) | Number of SSE events (`\n\n` delimiters) forwarded |
| `response_body_bytes` | integer | Total bytes forwarded to the client |

## Edge Cases (NMV3-014)

### Compressed Response Bypass

When the upstream returns a response with `Content-Encoding: gzip` (or any non-identity
encoding), the proxy **bypasses** the body untouched. The compressed bytes are forwarded
to the client as-is, and the `Content-Encoding` header is preserved. The proxy logs
`body_policy=bypass` for these responses.

### HASH-Mode Buffering Under SSE

If the request used schema `HASH` pseudonymisation AND the upstream returns
`text/event-stream`, the proxy must still buffer the full response for JSON unhashing.
Streaming is disabled and `response_mode=buffered` is logged. Operators who need both
SSE and HASH should be aware of the latency impact.

### Long-Lived SSE Sessions

For Anthropic-style multi-event streams (10+ events with mixed types like
`message_start`, `content_block_delta`, `content_block_stop`, `message_stop`), the
proxy flushes per raw chunk when `flush_per_chunk=true`. Each SSE event delimiter
(`\n\n`) is counted and logged as `stream_event_count`.

### Diagnosing Collapsed Events

If the client observes fewer chunks than expected, check:

1. **`flush_per_chunk`** — should be `true` for SSE/NDJSON
2. **`stream_event_count`** — should match the expected event count
3. **`response_mode`** — should be `stream_passthrough` or `stream_unmask` (not `buffered`)
4. **Transfer Protocol** — upstream should use `Transfer-Encoding: chunked` (HTTP/1.1) or the response should have
   `text/event-stream` Content-Type (HTTP/1.1, HTTP/2, HTTP/3)

