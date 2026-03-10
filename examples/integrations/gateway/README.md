# Centralized Kubernetes Gateway

This kit runs NanoMask as a shared in-cluster gateway instead of a per-pod sidecar.

## Files

- [values.yaml](values.yaml)
- [../../standalone-deployment.yaml](../../standalone-deployment.yaml)

## Deploy With Helm

1. Build or publish the image tag referenced by the example values:

```bash
docker build -t nanomask:0.1.0 .
```

2. Install the chart with the gateway recipe values:

```bash
helm upgrade --install nanomask ./charts/nanomask \
  -f examples/integrations/gateway/values.yaml
```

Or apply the raw manifest directly:

```bash
kubectl apply -f examples/standalone-deployment.yaml
```

3. Wait for the gateway rollout:

```bash
kubectl rollout status deploy/nanomask
```

4. Smoke-test liveness and readiness through the Service:

```bash
kubectl run nm-gateway-smoke --rm -i --tty --restart=Never \
  --image=curlimages/curl -- \
  curl -sS http://nanomask.default.svc.cluster.local:8081/healthz
```

```bash
kubectl run nm-gateway-ready --rm -i --tty --restart=Never \
  --image=curlimages/curl -- \
  curl -sS http://nanomask.default.svc.cluster.local:8081/readyz
```

5. Smoke-test response streaming through the shared gateway:

```bash
kubectl run nm-gateway-stream --rm -i --tty --restart=Never \
  --image=curlimages/curl -- \
  curl -N http://nanomask.default.svc.cluster.local:8081/stream/3
```

## Auth

Keep caller `Authorization`, vendor headers, and tracing headers on requests to the Service. NanoMask forwards them upstream by default, which lets clients treat the gateway as a drop-in proxy.

## TLS

This recipe enables `targetTls: true` for the upstream side. If clients should also speak HTTPS to NanoMask, either enable listener TLS in the chart values or terminate TLS at your Ingress and keep the Service internal.

## Streaming

Use `/stream/3` against the example `httpbin.org` upstream to prove chunked delivery survives the gateway hop. For LLM workloads, the same gateway mode preserves SSE and NDJSON responses when no buffering transform is required.

## Health Checks

Use `/healthz` for liveness, `/readyz` for readiness, and `/metrics` for Prometheus scrape traffic. Keep Kubernetes `terminationGracePeriodSeconds` longer than NanoMask's shutdown drain window so in-flight traffic can finish cleanly.
