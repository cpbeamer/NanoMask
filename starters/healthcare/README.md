# Healthcare Starter Pack

This directory is the checked-in healthcare starter pack for NanoMask. The files here are versioned, referenced by docs and examples, and validated by automated tests so new users can start with something close to real intake, encounter-note, and claims traffic.

## What's Included

- `schemas/`
  - `patient-demographics.nmschema`: intake and registration JSON with structured identifiers plus a small free-text notes field.
  - `encounter-notes.nmschema`: clinician or triage note payloads where structured metadata stays useful but `note.summary` is scanned for PHI.
  - `claims-processing.nmschema`: claims-like gateway traffic that hashes routing IDs while scanning supporting text.
- `entities/`
  - Seed entity files for each workflow. Replace these names with your own patient roster, provider list, or care-team names.
- `payloads/`
  - Representative JSON payloads that match the starter schemas and are used by the starter-pack tests.
- `presets/`
  - Environment-variable presets for local sidecar and gateway smoke tests. Replace the upstream target and rotate the sample hash key before production use.
- `deployments/`
  - Kubernetes examples for an encounter-note sidecar pattern and a claims-gateway pattern. They expect ConfigMaps and Secrets created from the starter assets in this directory.
- `hash-key.example.txt`
  - A sample 64-character hash key for local testing only.

## Local Smoke Test

Run the patient-demographics starter against `httpbin.org`:

```bash
zig build run -- \
  --listen-host 127.0.0.1 \
  --target-host httpbin.org \
  --target-port 80 \
  --entity-file starters/healthcare/entities/patient-demographics.txt \
  --schema-file starters/healthcare/schemas/patient-demographics.nmschema \
  --schema-default KEEP \
  --hash-key-file starters/healthcare/hash-key.example.txt \
  --profile hipaa-safe-harbor

curl -X POST http://localhost:8081/post \
  -H "Content-Type: application/json" \
  --data-binary @starters/healthcare/payloads/patient-demographics.json
```

## When To Modify Each Schema

- `patient-demographics.nmschema`
  - Start here for registration, eligibility, scheduling, and intake payloads.
  - Modify it when your demographics live under different nested keys or when a field like DOB or ZIP must stay visible for downstream routing.
- `encounter-notes.nmschema`
  - Start here for SOAP notes, triage summaries, nurse handoff payloads, or other note-centric JSON.
  - Modify it when the free-text note field is named differently or when care-team names are supplied per request instead of from a file.
- `claims-processing.nmschema`
  - Start here for clearinghouse, prior-authorization, and payer-integrator traffic.
  - Modify it when claim IDs or policy numbers should remain visible, or when additional nested fields need `HASH` instead of `REDACT`.

## Kubernetes Setup

Create the assets for the encounter-note sidecar example:

```bash
kubectl create configmap nanomask-healthcare-encounter \
  --from-file=starters/healthcare/schemas/encounter-notes.nmschema \
  --from-file=starters/healthcare/entities/encounter-notes.txt \
  --from-file=starters/healthcare/payloads/encounter-note.json

kubectl create secret generic nanomask-healthcare-hash \
  --from-file=hash-key.txt=starters/healthcare/hash-key.example.txt

kubectl apply -f starters/healthcare/deployments/encounter-sidecar-pod.yaml
```

Create the assets for the claims gateway example:

```bash
kubectl create configmap nanomask-healthcare-claims \
  --from-file=starters/healthcare/schemas/claims-processing.nmschema \
  --from-file=starters/healthcare/entities/claims-processing.txt

kubectl create secret generic nanomask-healthcare-hash \
  --from-file=hash-key.txt=starters/healthcare/hash-key.example.txt \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f starters/healthcare/deployments/claims-gateway.yaml
```

## Notes

- NanoMask schema files use the line-based `field.path = ACTION` format, not a JSON object.
- Keep `schema.name` and `schema.version` in your derived schemas so change-control reviews can track which starter revision you began from.
- The sample hash key is only for local testing. Generate a new key for every real environment.
- The `--profile hipaa-safe-harbor` flag expands to enable all default 18 identifiers required for safe-harbor de-identification. You can review presets via `zig build run -- --list-profiles`
