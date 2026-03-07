# Phase 1 Backlog: Basic Zig Proxy & SSN Redaction MVP

**Goal:** Build a basic Zig proxy that intercepts HTTP traffic and redacts SSNs using a simple SIMD scanner.

## Epic: Phase 1 - Basic Zig Proxy & SSN Redaction MVP

### 1. Project Foundation & CI/CD
- [ ] **Story:** Initialize the Zig project structure with standard build files (`build.zig`).
- [ ] **Story:** Set up a basic CI/CD pipeline (e.g., GitHub Actions) to automatically build the project and run `zig fmt` and basic tests on pull requests.

### 2. Network Layer: HTTP Proxy Server
- [ ] **Story (Spike):** Evaluate and select the initial HTTP networking approach (raw `std.net` vs. a fast wrapper like `zap`).
- [ ] **Story:** Implement a basic HTTP server that listens on a configured local port and accepts incoming connections.
- [ ] **Story:** Implement a reverse proxy mechanism that forwards incoming HTTP requests (headers, body, method) to a target destination (e.g., a mock OpenAI API).
- [ ] **Story:** Ensure the HTTP proxy can receive the response from the downstream target and relay it back to the original client cleanly.

### 3. Data Layer: JSON Parsing & Manipulation
- [ ] **Story:** Implement or integrate a lightweight, low-allocation JSON parser in Zig.
- [ ] **Story:** Build middleware into the proxy that intercepts the incoming request body and successfully parses it into a Zig struct or DOM representation.
- [ ] **Story:** Implement the ability to re-serialize the parsed JSON back into a string/byte array to forward it to the target destination.

### 4. Scanning Engine: SSN Detection
- [ ] **Story:** Write a basic string scanning function to identify standard US Social Security Number patterns (`XXX-XX-XXXX` and `XXXXXXXXX`).
- [ ] **Story (Optimization):** Refactor the SSN scanning loop to utilize basic SIMD instructions in Zig for faster substring/pattern evaluation over the JSON payload.
- [ ] **Story:** Write unit tests covering various valid and invalid SSN edge cases to ensure the scanner is accurate and doesn't produce false positives on similar numeric strings.

### 5. Redaction & Tokenization Pipeline (Ingress)
- [ ] **Story:** Implement an in-memory, fast map/dictionary to serve as the Tokenization Vault.
- [ ] **Story:** Connect the SSN scanner to the JSON payload parser. When an SSN is found in a payload string, generate a secure token (e.g., `ZPG_USER_123`).
- [ ] **Story:** Store the mapping of `ZPG_USER_123 -> [Actual SSN]` in the in-memory Vault.
- [ ] **Story:** Mutate the outgoing JSON payload by replacing the real SSN with the generated token before forwarding it to the target destination.

### 6. Re-identification Pipeline (Egress)
- [ ] **Story:** Intercept the HTTP response body coming back from the target destination (the LLM).
- [ ] **Story:** Parse the response body and scan it for known tokens (e.g., searching for strings matching the `ZPG_USER_*` format).
- [ ] **Story:** For any token found, look up the original SSN in the in-memory Vault.
- [ ] **Story:** Mutate the response payload by swapping the token back to the original SSN before relaying the final HTTP response back to the client.

### 7. MVP Validation & Benchmarking
- [ ] **Story:** Create an end-to-end integration test containing a mock client, the ZPG MVP, and a mock LLM server to verify the full round-trip tokenization and re-identification flow.
- [ ] **Story:** Set up a basic benchmarking script (e.g., using `wrk` or `hey`) to measure the baseline latency overhead added by the proxy parsing and scanning against a direct connection.
