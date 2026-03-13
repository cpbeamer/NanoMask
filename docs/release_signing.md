# Release Signing And SBOM Generation

This document describes the signing and software bill of materials (SBOM) workflow for NanoMask release artifacts. It satisfies Executive Order 14028 requirements for software supply-chain transparency.

## SBOM Generation

NanoMask has zero external Zig dependencies (`build.zig.zon` has an empty `.dependencies` block). The SBOM is primarily useful for documenting the container image layers and the Zig toolchain version.

### Container Image SBOM

Generate a CycloneDX SBOM from the Docker image:

```bash
# Using trivy
trivy image --format cyclonedx --output nanomask-sbom.cdx.json ghcr.io/cpbeamer/nanomask:latest

# Using syft (alternative)
syft ghcr.io/cpbeamer/nanomask:latest -o cyclonedx-json > nanomask-sbom.cdx.json
```

### Build Metadata

The Zig toolchain version is pinned in `build.zig.zon`:
- `minimum_zig_version`: `0.15.2`
- `fingerprint`: `0xa3717543b57a2b5b`
- `version`: See `build.zig.zon` for the current package version.

## Binary Signing With minisign

[minisign](https://jedisct1.github.io/minisign/) is a lightweight, auditable alternative to GPG for signing release binaries.

### One-Time Key Generation

```bash
minisign -G -s nanomask-release.key -p nanomask-release.pub
```

Store the secret key securely (e.g., GitHub Secrets as `MINISIGN_SECRET_KEY`). Publish the public key in the repository root.

### Signing A Release Binary

```bash
# Sign the binary
minisign -Sm zig-out/bin/NanoMask -s nanomask-release.key

# Produces: zig-out/bin/NanoMask.minisig
```

### Verifying A Release Binary

```bash
minisign -Vm NanoMask -p nanomask-release.pub
```

## OCI Image Signing With cosign

[cosign](https://github.com/sigstore/cosign) provides keyless signing for container images via GitHub Actions OIDC, following the Sigstore model.

### Keyless Signing In CI (Recommended)

```yaml
# In GitHub Actions release workflow:
- name: Sign Container Image
  uses: sigstore/cosign-installer@v3
- name: Sign
  env:
    COSIGN_EXPERIMENTAL: "1"
  run: |
    cosign sign ghcr.io/cpbeamer/nanomask@${{ steps.build.outputs.digest }}
```

This uses GitHub OIDC — no secret keys to manage. The signature is recorded in the Rekor transparency log.

### Verifying An Image

```bash
cosign verify ghcr.io/cpbeamer/nanomask:latest \
  --certificate-identity-regexp="https://github.com/cpbeamer/NanoMask" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

## CI Integration

The `security.yml` workflow generates the SBOM on every PR/push. Release-time signing is performed by the release workflow (see `security_review_checklist.md`).

## Revision History

| Date | Change |
|------|--------|
| 2026-03-13 | Initial release signing and SBOM guide |
