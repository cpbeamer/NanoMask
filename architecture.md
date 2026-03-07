# The Zig Privacy Guard (ZPG) - Phase 1 Architecture

## Overview
The Zig Privacy Guard (ZPG) is a high-throughput, low-latency de-identification HTTP proxy engineered in pure Zig (0.15.2). It serves as a privacy firewall designed to intercept requests, scan for sensitive Personally Identifiable Information (PII) or Protected Health Information (PHI)—such as Social Security Numbers—and redact them in-flight before they reach upstream or downstream endpoints.

## 1. Network Component Stack

Rather than relying on third-party frameworks like `zap`, the MVP is built entirely upon the Zig Standard Library's `std.http` module to ensure a zero-dependency footprint and native cross-platform compilation (specifically to support Windows development seamlessly).

### Core Components
*   **Listener (`std.net.Server`)**: Binds to `127.0.0.1:8081` with `reuse_address` enabled to handle incoming TCP connections.
*   **Ingress Server (`std.http.Server`)**: Wraps the incoming connection stream. Due to API changes in Zig 0.15, proxying utilizes specific `reader.interface()` and `&writer.interface` generic IO wrappers to coerce buffered connection streams into HTTP Server objects.
*   **Egress Client (`std.http.Client`)**: Manages the outbound connection to the downstream API (e.g., `httpbin.org`). Connections are established via `Client.request`, transmitting the method, URI, and explicitly flushing headers and bodiless requests (in the Phase 1 MVP).

## 2. Data Flow & Payload Buffering

The proxy intercepts the HTTP transaction in three phases:

1.  **Header Forwarding**: The incoming HTTP Request Head is parsed, and an exact replica (method + target URI) is minted onto the `std.http.Client` request.
2.  **Streaming Read**: The downstream response header is obtained via `client_req.receiveHead()`. Following this, the raw payload body is streamed sequentially. 
3.  **Dynamic Buffering**: To support the current "full-payload" analysis, the body stream is dynamically captured into a `std.ArrayListUnmanaged(u8)`. This unmanaged list interacts closely with `downstream_reader.appendRemainingUnlimited(allocator, &body_alloc)` to safely allocate only the memory required for the response size.

## 3. Redaction Rule Engine (`src/redact.zig`)

The core privacy mechanism lives in an isolated engine module.

### In-Place Scanning
To maintain maximum performance and avoid expensive heap-allocations or garbage collection pauses, the SSN redaction engine uses **in-place mutation**. 
*   It utilizes a highly optimized state-machine/sliding-window loop to scan byte slices iteratively.
*   When a pattern match occurs (e.g., exactly matching `\d{3}-\d{2}-\d{4}` via sequential `std.ascii.isDigit` checks), the sequence is directly mutated within the same memory slice to `***-**-****`.

Since this logic operates purely on `[]u8` slices, it is highly parallelizable and ready for future SIMD (Single Instruction, Multiple Data) optimizations.

## 4. State Management (MVP)

Currently, the proxy processes connections sequentially within an infinite accept loop (`while (true) { connection = net_server.accept() ... }`). 
This guarantees absolute stability for initial compliance verification but will be evolved into an asynchronous/multi-threaded event loop strategy in Phase 2 to handle high-throughput parallel traffic.
