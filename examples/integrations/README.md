# Integration Kits

NanoMask ships with integration recipes for the deployment shapes buyers usually test first.

## Included Recipes

- [Sidecar App Container](sidecar/README.md): local Docker Compose sidecar demo plus the checked-in Kubernetes pod manifest at [../../sidecar-pod.yaml](../sidecar-pod.yaml).
- [Centralized Kubernetes Gateway](gateway/README.md): Helm values for the chart plus the checked-in raw manifest at [../../standalone-deployment.yaml](../standalone-deployment.yaml).
- [LiteLLM in Front of Vendor APIs](litellm/README.md): Docker Compose stack for `LiteLLM -> NanoMask -> OpenAI-compatible upstream`.
- [Generic OpenAI-Compatible Clients](openai-compatible/README.md): curl, Python, and Node examples that point `base_url` or `baseURL` at NanoMask.

## Smoke-Test Coverage

The repo test suite includes a file-backed smoke test that checks these recipes for:

- runnable entrypoints and config files
- sidecar versus gateway bind-address correctness
- direct README links from the top-level docs
- streaming-oriented example commands
- operator notes for auth, TLS, streaming, and health checks

Use these kits as starting points, then replace the demo upstreams, credentials, and schemas with your own environment-specific values.
