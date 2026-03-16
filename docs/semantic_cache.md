# Semantic Cache

Semantic caching lets NanoMask skip duplicate upstream LLM calls after de-identification.

## What is cached

- request key inputs: HTTP method, URI, tenant identifier, transformed request body
- cached value: eligible upstream response body
- isolation: per-tenant using `--semantic-cache-tenant-header`

## Enable it

```bash
zig build run -- \
  --target-host api.openai.com \
  --target-port 443 \
  --target-tls \
  --enable-semantic-cache \
  --semantic-cache-ttl-ms 300000 \
  --semantic-cache-max-entries 256 \
  --semantic-cache-tenant-header X-NanoMask-Tenant
```

## Current behavior

- duplicate transformed prompts can short-circuit the upstream request path
- entries expire by TTL
- cache capacity is bounded and old entries are evicted
- response caching is limited to successful, identity-encoded, text or JSON responses

## Metrics

- `nanomask_semantic_cache_requests_total{result="hit"}`
- `nanomask_semantic_cache_requests_total{result="miss"}`
- `nanomask_semantic_cache_requests_total{result="eviction"}`
- `nanomask_semantic_cache_entries`

## Cost reduction framing

Use semantic cache when the same de-identified prompts recur across:

- repeated summarization templates
- common support or claims-routing prompts
- batch reprocessing jobs

Estimated savings model:

`monthly_savings = cache_hits * average_prompt_cost`

The buyer conversation is not just privacy. It becomes privacy plus reduced API spend.
