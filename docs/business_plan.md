# The Zig Privacy Guard (ZPG) - Business Plan

## I. Executive Summary

### What the business is?
A high-throughput, low-latency PII/PHI De-identification Proxy. It acts as a "Privacy Firewall" that sits between your secure internal environment and external AI services (like OpenAI, Claude, or Gemini). It programmatically redacts or tokenizes sensitive data in real-time before it ever leaves your VPC.

### What problem are we solving?
*   **The "Compliance Wall"**: Organizations in Gov/Health are currently blocked from using the best LLMs because they cannot risk PII/PHI leaking into external training sets or logs.
*   **The "Infrastructure Tax"**: Hosting inferior open-source models on-site (like SageMaker or GCCH) is 10x more expensive in compute and maintenance than using external APIs.
*   **The "Latency Gap"**: Current software-based scrubbers (Python/Java) add 100ms+ of latency, making real-time applications sluggish.

### How does this differ from existing companies? (Our Edge)
*   **Engineered in Zig**: Unlike competitors written in Go or Python, ZPG has no runtime and no garbage collector. This means zero "stop-the-world" pauses and a tiny memory footprint.
*   **Deterministic Latency**: By using SIMD-accelerated pattern matching, we process gigabits of data at wire-speed.
*   **Hardened by Default**: Designed for non-root, hardened container images (Iron Bank/DHI compatible), making the ATO (Authority to Operate) process significantly faster for Gov contractors.
*   **Comptime Schema Optimization**: We don't just use generic regex; we use Zig's comptime to generate optimized machine code specific to the user's JSON schema (e.g., VA Claim Forms).

### Potential Revenue Opportunities
*   **The Sidecar License**: Monthly subscription per instance for DevOps teams to drop into their K8s pods.
*   **Enterprise Gateway**: A site-wide license for large agencies/hospitals to route all outbound AI traffic through a centralized, audited cluster.
*   **Compliance-as-a-Service**: High-margin consulting for custom schema mapping and "Zero-Trust" AI integration.

### What information can we redact?
*   **Identifiers**: Names, SSNs, Driver's License numbers, Passport numbers.
*   **Contact Info**: Emails, Phone numbers, IP addresses, Physical addresses.
*   **Health Data (PHI)**: Medical Record Numbers (MRN), ICD-10 codes, health insurance IDs.
*   **Financials**: Credit card numbers, Bank account details.
*   **Custom Regex/Patterns**: Specific agency-defined identifiers (e.g., VA Claim Case Numbers).

## II. Technical Implementation

### The Stack
*   **Core Engine**: Zig (for performance and memory safety).
*   **Network Layer**: `zap` (Zig's ultra-fast wrapper around facil.io) or raw `std.net` for L7 proxying.
*   **Pattern Matching**: Hyperscan (Intel's SIMD regex engine) or a custom Zig SIMD matcher.
*   **Deployment**: Hardened Distroless OCI Images (Docker/Podman).
*   **Configuration**: YAML/TOML for defining redaction rules.

### Technical Architecture
The ZPG operates as a Transparent Reverse Proxy:
1.  **Ingress**: The application sends a JSON request to ZPG instead of the OpenAI endpoint.
2.  **Streaming Parse**: ZPG parses the JSON stream using a "Single-Pass" approach.
3.  **The Matcher**:
    *   **Direct Keys**: If a key is known to be sensitive ("patient_name"), its value is immediately tokenized.
    *   **Value Scanning**: Unstructured text ("summary") is scanned using SIMD bitmasking for PII patterns.
4.  **Tokenization**: Sensitive values are hashed and stored in an ultra-fast, in-memory LRU cache (John Doe -> USER_A).
5.  **Egress**: The "Clean" JSON is forwarded to the external LLM.
6.  **Re-identification**: When the LLM responds, ZPG performs the reverse mapping (USER_A -> John Doe) so the internal app sees the original names.

### Implementation Plan

| Phase | Timeline | Key Milestone |
| :--- | :--- | :--- |
| **Phase 1: MVP** | Weeks 1-4 | Build a basic Zig proxy that intercepts HTTP traffic and redacts SSNs using a simple SIMD scanner. |
| **Phase 2: Schema Aware** | Weeks 5-8 | Implement comptime JSON parsing to allow users to define "Safe" and "Unsafe" keys for faster processing. |
| **Phase 3: Hardening** | Weeks 9-12 | Package as a non-root, hardened container. Integrate Prometheus metrics for auditing and throughput monitoring. |
| **Phase 4: Pilot** | Month 4+ | Deploy as a sidecar in a dev environment for a Gov project to validate "Zero-Leak" compliance. |

---