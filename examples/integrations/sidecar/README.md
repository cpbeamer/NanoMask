# Sidecar App Container

This kit packages NanoMask as an app sidecar in the two places teams usually ask for it first:

- local Docker Compose with NanoMask sharing the app container's network namespace
- Kubernetes pod deployment via [../../sidecar-pod.yaml](../../sidecar-pod.yaml)

## Files

- [docker-compose.yaml](docker-compose.yaml)
- [../../sidecar-pod.yaml](../../sidecar-pod.yaml)

## Run Locally

1. Build the NanoMask container image:

```bash
docker build -t nanomask:0.1.0 .
```

2. Start the demo stack:

```bash
docker compose -f examples/integrations/sidecar/docker-compose.yaml up -d app nanomask httpbin
```

3. Send a JSON request from the app container to its localhost sidecar:

```bash
docker compose -f examples/integrations/sidecar/docker-compose.yaml exec app \
  curl -sS -X POST http://127.0.0.1:8081/anything \
    -H "Authorization: Bearer sidecar-demo" \
    -H "Content-Type: application/json" \
    -d '{"patient":"Jane Smith","notes":"SSN 123-45-6789","email":"jane.smith@example.com"}'
```

4. Smoke-test downstream streaming end to end:

```bash
docker compose -f examples/integrations/sidecar/docker-compose.yaml exec app \
  curl -N http://127.0.0.1:8081/stream/3
```

5. Tear the stack down when finished:

```bash
docker compose -f examples/integrations/sidecar/docker-compose.yaml down -v
```

## Kubernetes

Apply the checked-in pod manifest when you want the same sidecar shape in-cluster:

```bash
kubectl apply -f examples/sidecar-pod.yaml
```

## Auth

Pass vendor credentials from the app to `http://127.0.0.1:8081` exactly as the upstream expects them. NanoMask forwards end-to-end auth headers and strips only hop-by-hop headers.

## TLS

Loopback traffic between the app and NanoMask can stay plaintext inside the shared pod or network namespace. For external upstreams, set `NANOMASK_TARGET_TLS=true` and mount any custom CA bundle the upstream requires.

## Streaming

The `curl -N http://127.0.0.1:8081/stream/3` smoke test proves that a sidecar deployment can preserve chunked downstream delivery instead of buffering the whole response first.

## Health Checks

Use `/healthz` for liveness and `/readyz` for readiness. The Kubernetes manifest already wires both probes, and the Docker Compose service exposes the same paths on the sidecar's localhost listener.
