# `nanomask-openai`

Thin Python helpers for routing official OpenAI SDK traffic through NanoMask.

## Install

```bash
pip install ./sdk/python
```

## Usage

```python
from nanomask import OpenAI, verify, with_entities

client = OpenAI(
    api_key="replace-me",
    entities=["Jane Doe", "ACME Health"],
)

assert verify().ok
response = client.responses.create(
    model="gpt-4o-mini",
    input="Summarize Jane Doe's chart.",
    **with_entities(entities=["Jane Doe"]),
)
```

## What it does

- defaults `base_url` to `http://127.0.0.1:8081/v1`
- injects `X-NanoMask-Entities` when `entities=` is provided
- accepts `header_name="X-ZPG-Entities"` for legacy deployments
- exposes `with_entities()` for per-request entity headers
- exposes `verify()` for CI and readiness checks

The wrapper is intentionally thin. It delegates to the official `openai` package and only preconfigures NanoMask-specific transport settings.
