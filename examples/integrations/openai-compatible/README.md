# OpenAI-Compatible Clients

This kit shows how to point generic OpenAI-compatible clients at NanoMask instead of talking to the vendor endpoint directly.

## Files

- [client.env.example](client.env.example)
- [curl-chat.sh](curl-chat.sh)
- [python_client.py](python_client.py)
- [node_client.mjs](node_client.mjs)

## Configure

Set the client base URL to NanoMask's `/v1` endpoint:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8081/v1
export OPENAI_API_KEY=replace-me
export OPENAI_MODEL=gpt-4o-mini
```

## Curl

```bash
sh examples/integrations/openai-compatible/curl-chat.sh
```

## Python

```bash
pip install ./sdk/python
python examples/integrations/openai-compatible/python_client.py
```

## Node

```bash
npm install openai ./sdk/node
node examples/integrations/openai-compatible/node_client.mjs
```

## SDK Wrappers

If you want the client boilerplate packaged instead of handwritten:

- Python: `from nanomask import OpenAI, verify`
- Node: `import { createClient, verify } from "@nanomask/openai"`

The wrappers default the client base URL to NanoMask and inject `X-ZPG-Entities` headers when you pass an entity list.

## Auth

Use the same bearer token you would normally send to the upstream API unless your gateway terminates client auth before NanoMask. NanoMask preserves the auth header on the vendor hop.

## TLS

If NanoMask is exposed with listener TLS, switch `OPENAI_BASE_URL` from `http://` to `https://` and trust the serving certificate the same way you would for any other internal API.

## Streaming

The curl, Python, and Node examples all request streaming responses. Keep `curl -N` and `stream=True` or `stream: true` enabled so you can see tokens arrive incrementally through NanoMask.

## Health Checks

Before repointing application traffic, verify `http://127.0.0.1:8081/healthz` and `http://127.0.0.1:8081/readyz`. Use `/readyz` for deployment gates so clients do not switch over while NanoMask is draining or reloading.
