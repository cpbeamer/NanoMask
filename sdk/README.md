# NanoMask SDK Wrappers

Phase 5 adds lightweight wrappers for the official OpenAI SDKs so teams can point existing clients at NanoMask with minimal changes.

## Packages

- `sdk/python`: `nanomask-openai` package, imported as `nanomask`
- `sdk/node`: `@nanomask/openai` package

## Goals

- Default the client `base_url` to NanoMask's local `/v1` endpoint
- Provide `X-ZPG-Entities` header helpers
- Expose `verify()` health probes for CI and deployment checks

## Local install

```bash
pip install ./sdk/python
npm install ./sdk/node
```

Each package has its own README with usage examples.
