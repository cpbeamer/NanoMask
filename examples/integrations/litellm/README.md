# LiteLLM in Front of Vendor APIs

This kit runs `LiteLLM -> NanoMask -> vendor API` so teams can keep LiteLLM's client surface while inserting NanoMask before traffic leaves the network.

## Files

- [docker-compose.yaml](docker-compose.yaml)
- [config.yaml](config.yaml)

## Run Locally

1. Build the NanoMask image:

```bash
docker build -t nanomask:0.1.0 .
```

2. Export the upstream provider key and optional LiteLLM gateway key:

```bash
export OPENAI_API_KEY=replace-me
export LITELLM_MASTER_KEY=sk-local-litellm
```

3. Start LiteLLM and NanoMask:

```bash
docker compose -f examples/integrations/litellm/docker-compose.yaml up
```

4. Smoke-test a streaming chat completion through LiteLLM:

```bash
curl -N http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer sk-local-litellm" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"Patient Jane Smith SSN 123-45-6789 needs follow up"}]}'
```

## Auth

Clients authenticate to LiteLLM with the LiteLLM gateway key, while LiteLLM authenticates upstream with `OPENAI_API_KEY`. NanoMask stays in the middle and forwards the OpenAI-compatible auth headers LiteLLM emits.

## TLS

NanoMask terminates plaintext only on the internal Docker network and uses `NANOMASK_TARGET_TLS=true` for the vendor hop. If you expose NanoMask directly to other clients, add listener TLS or put it behind a TLS-terminating reverse proxy.

## Streaming

Keep `"stream": true` in the LiteLLM request body and use `curl -N` for the smoke test so you can verify incremental downstream tokens instead of a buffered full response.

## Health Checks

Treat NanoMask `/healthz` and `/readyz` as the readiness gate for the privacy hop. If you already run a separate LiteLLM probe, keep it in addition to, not instead of, the NanoMask checks.
