# NanoMask Evaluation Kit

This folder is the repeatable buyer package for healthcare, claims, and regulated-AI evaluations.

## What is included

- Reference deployments:
  `examples/integrations/sidecar/README.md`,
  `examples/integrations/gateway/README.md`,
  `starters/healthcare/deployments/`
- Sample data packs:
  `starters/healthcare/payloads/`,
  `starters/healthcare/entities/`,
  `starters/healthcare/schemas/`
- Report-only evaluation workflow:
  [report-only-workflow.md](report-only-workflow.md)
- Benchmark card:
  [benchmark-card.md](benchmark-card.md)
- Compatibility summary:
  [compatibility-summary.md](compatibility-summary.md)
- Pilot scorecard and runbook:
  [pilot-success-criteria.md](pilot-success-criteria.md),
  [pilot-runbook.md](pilot-runbook.md)
- Security packet:
  `docs/security_packet.md`

## Recommended evaluation flow

1. Start in report-only mode with the healthcare starter assets.
2. Run the compatibility suite and attach `compatibility/compatibility-matrix.json` to the evaluation packet.
3. Switch one bounded workflow from report-only to active masking.
4. Review the security packet and threat model with the buyer's security team.
5. Lock pilot success criteria before production-shaped traffic is enabled.

## Reproducible starter command

```bash
zig build run -- \
  --listen-host 127.0.0.1 \
  --target-host httpbin.org \
  --target-port 80 \
  --entity-file starters/healthcare/entities/patient-demographics.txt \
  --schema-file starters/healthcare/schemas/patient-demographics.nmschema \
  --schema-default KEEP \
  --hash-key-file starters/healthcare/hash-key.example.txt \
  --enable-email \
  --enable-phone \
  --enable-healthcare \
  --report-only
```

Then send the included sample payload:

```bash
curl -X POST http://127.0.0.1:8081/post \
  -H "Content-Type: application/json" \
  --data-binary @starters/healthcare/payloads/patient-demographics.json
```
