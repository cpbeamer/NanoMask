# Compatibility Summary

Current checked-in compatibility artifact: `compatibility/compatibility-matrix.json`

## Summary

- total reference flows: 5
- passed: 5
- failed: 0

## Covered flows

- OpenAI-compatible JSON: header fidelity, body mutation, response headers, path/query fidelity
- Anthropic-style SSE: streaming fidelity plus request and response header checks
- Azure OpenAI-style routes: path and query preservation
- Generic REST JSON: ordinary API compatibility outside AI-specific routes
- LiteLLM-style headers: proxy and vendor header preservation

## Buyer takeaway

NanoMask is positioned as a drop-in reverse proxy, not a custom integration project. This artifact is the proof packet for that claim.
