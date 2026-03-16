# Pilot Runbook

## Before kickoff

- confirm target workflow, owner, and upstream API surface
- choose deployment shape: sidecar or centralized gateway
- choose evaluation corpus from `starters/healthcare/` or buyer-supplied sanitized payloads
- agree on pilot success criteria and review cadence

## Day 0 setup

1. Validate the config with `--validate-config`.
2. Start in report-only mode.
3. Run the compatibility suite against the buyer's preferred API shape.
4. Hand over the security packet and threat model.

## Day 1 validation

1. Replay seeded traffic and compare detections to the expected corpus.
2. Review false positives and tighten schema or entity inputs.
3. Enable active masking for one bounded route or integration.

## Day 2+ operationalization

1. Turn on audit logging and metrics scraping.
2. Measure latency overhead and operational fit.
3. If applicable, enable guardrails or semantic cache after privacy controls are accepted.

## Closeout packet

- benchmark card
- compatibility summary
- pilot scorecard against success criteria
- security packet
- recommended next commercial motion
