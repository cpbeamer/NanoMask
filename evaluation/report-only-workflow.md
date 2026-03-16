# Report-Only Workflow

Use report-only mode to prove coverage and operational safety before payload mutation is enabled.

## Objectives

- measure what NanoMask would redact without changing traffic
- baseline false positives on real prompts, notes, and claims payloads
- show auditors that rollout starts with observation, not blind enforcement

## Commands

Start NanoMask with the healthcare starter pack:

```bash
zig build run -- \
  --listen-host 127.0.0.1 \
  --target-host httpbin.org \
  --target-port 80 \
  --entity-file starters/healthcare/entities/encounter-notes.txt \
  --schema-file starters/healthcare/schemas/encounter-notes.nmschema \
  --schema-default KEEP \
  --hash-key-file starters/healthcare/hash-key.example.txt \
  --enable-email \
  --enable-phone \
  --enable-healthcare \
  --report-only \
  --audit-log
```

Send representative traffic:

```bash
curl -X POST http://127.0.0.1:8081/post \
  -H "Content-Type: application/json" \
  --data-binary @starters/healthcare/payloads/encounter-note.json
```

## Evidence to capture

- structured logs showing detected classes and request IDs
- audit events for each detected pattern or entity match
- `/metrics` snapshots before and after the sample run
- operator notes on any expected-but-undetected values or false positives

## Exit criteria

- all sample payloads produce detections on the expected fields
- no critical false positives block adjacent non-PII fields
- operators understand what will change when enforcement is turned on
