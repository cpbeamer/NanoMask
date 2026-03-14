# Document Pipeline Reference

This example demonstrates a complete healthcare document intake workflow:
**PDF → Text Extraction (Tika) → PII Redaction (NanoMask) → LLM**.

## Prerequisites

- Docker and Docker Compose installed
- A valid NanoMask entity file and schema (see `starters/healthcare/`)

## Quick Start

```bash
# From the NanoMask repo root
cd examples/document_pipeline

# Start the pipeline
docker compose up -d

# Submit a PDF for processing (Tika extracts text, NanoMask redacts PII)
# Step 1: Extract text from PDF via Tika
curl -T /path/to/patient-record.pdf \
  -H "Accept: text/plain" \
  http://localhost:9998/tika \
  -o extracted.txt

# Step 2: Send extracted text through NanoMask to the LLM
# jq safely escapes the file content as a JSON string value
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "$(jq -n --rawfile content extracted.txt \
       '{"model":"gpt-4o","messages":[{"role":"user","content":$content}]}')"
```

## Architecture

```
┌──────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐
│   PDF    │────▶│  Tika   │────▶│ NanoMask │────▶│  LLM    │
│  Source  │     │ :9998   │     │  :8080   │     │ Upstream│
└──────────┘     └─────────┘     └──────────┘     └─────────┘
```

## Components

| Service | Port | Role |
|---|---|---|
| `tika` | 9998 | Apache Tika server — extracts text from PDF, DOCX, images |
| `nanomask` | 8080 | PII redaction proxy |

## Notes

- NanoMask does **not** process PDFs directly. Always extract text first.
- For production, replace the upstream target with your actual LLM endpoint.
- Use NanoMask's `--entity-file` and `--schema-file` flags to configure redaction.
