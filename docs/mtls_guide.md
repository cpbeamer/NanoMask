# Mutual TLS (mTLS) Configuration Guide

## Overview

NanoMask supports mutual TLS for zero-trust deployments where both the proxy
and its clients must present valid certificates. This ensures that only
authenticated services can send traffic through the proxy.

## Quick Start

```bash
nanomask \
  --listen 0.0.0.0:8443 \
  --target api.openai.com:443 --target-tls \
  --tls-cert /etc/nanomask/server.pem \
  --tls-key  /etc/nanomask/server-key.pem \
  --mtls-ca   /etc/nanomask/client-ca.pem \
  --mtls-cert /etc/nanomask/client.pem \
  --mtls-key  /etc/nanomask/client-key.pem
```

## Configuration Flags

| Flag | Description |
|---|---|
| `--mtls-ca <path>` | PEM file containing the CA certificate(s) that sign client certs |
| `--mtls-cert <path>` | PEM file for the client certificate presented by NanoMask to upstream |
| `--mtls-key <path>` | PEM private key corresponding to `--mtls-cert` |

All three flags must be provided together. Corresponding environment variables:
`NANOMASK_MTLS_CA`, `NANOMASK_MTLS_CERT`, `NANOMASK_MTLS_KEY`.

## Certificate Lifecycle

### Generating a Self-Signed CA (Development)

```bash
# Create CA key and cert
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca.pem \
  -days 365 -nodes -subj "/CN=NanoMask Dev CA"

# Create client key and CSR
openssl req -newkey rsa:2048 -keyout client-key.pem -out client.csr \
  -nodes -subj "/CN=nanomask-client"

# Sign with CA
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out client.pem -days 90
```

### Production Recommendations

1. **Use short-lived certificates** (30-90 days) and automate renewal
2. **Store private keys in a secrets manager** (Vault, AWS Secrets Manager, GCP
   Secret Manager) — use `--hash-key-exec` pattern for retrieval
3. **Separate CA hierarchies** for client and server certificates
4. **Monitor certificate expiry** with Prometheus alerts on `notAfter` dates
5. **CRL/OCSP**: NanoMask does not currently support certificate revocation
   lists; rotate the CA trust anchor to revoke all previously-signed certs

### Certificate Rotation

1. Issue new client certificate signed by the same CA
2. Deploy new cert/key to the client application
3. The CA trust anchor (`--mtls-ca`) does not change, so NanoMask requires no
   reconfiguration
4. To rotate the CA itself:
   a. Create new CA
   b. Concatenate old + new CA PEMs into `--mtls-ca` (trust both during transition)
   c. Re-sign all client certs with new CA
   d. Remove old CA from the bundle

## Kubernetes Deployment

```yaml
# Mount certificates from Kubernetes Secrets
volumes:
  - name: mtls-certs
    secret:
      secretName: nanomask-mtls
      items:
        - key: ca.pem
          path: ca.pem
        - key: client.pem
          path: client.pem
        - key: client-key.pem
          path: client-key.pem

containers:
  - name: nanomask
    args:
      - --mtls-ca
      - /etc/nanomask/mtls/ca.pem
      - --mtls-cert
      - /etc/nanomask/mtls/client.pem
      - --mtls-key
      - /etc/nanomask/mtls/client-key.pem
    volumeMounts:
      - name: mtls-certs
        mountPath: /etc/nanomask/mtls
        readOnly: true
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `error: cannot open mTLS CA file` | Path incorrect or not mounted | Verify file exists at runtime |
| `error: --mtls-ca, --mtls-cert, and --mtls-key must all be specified together` | Incomplete config | Provide all three flags |
| Client connections rejected | Client cert not signed by the CA in `--mtls-ca` | Re-sign with correct CA |
