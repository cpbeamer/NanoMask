# Benchmark Card

This card is the short proof artifact to hand to buyers during technical evaluation.

## Core performance claims

| Surface | Current proof point | How to reproduce |
|---|---|---|
| SSN redaction | 16+ GB/s single-core scan in ReleaseFast | `zig build bench-all` |
| Exact entity masking | 260 MB/s | `zig build proof-report` |
| OCR-tolerant fuzzy matching | 193 MB/s | `zig build proof-report` |
| Compatibility coverage | 5/5 reference flows passing | `zig build compat-matrix -- compatibility/compatibility-matrix.json` |

## Operational proof points

- single static Zig binary with no runtime dependency chain
- request and response header fidelity covered by the compatibility matrix
- optional report-only mode for low-risk first deployment
- Prometheus metrics for redaction, guardrail, and semantic-cache behavior

## Evaluation note

Use this card together with:

- `compatibility/compatibility-matrix.json`
- `docs/security_packet.md`
- `evaluation/pilot-success-criteria.md`
