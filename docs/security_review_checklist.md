# Security Review Checklist

Use this checklist before every NanoMask release. Each item must be verified and signed off before publishing release artifacts.

## Pre-Release Checks

### Threat Model
- [ ] `docs/threat_model.md` has been reviewed and is current with any new features or attack surface changes.
- [ ] No new trust boundaries introduced without corresponding STRIDE analysis.
- [ ] Recommended controls (RC-*) are tracked in the backlog.

### Fuzz Testing
- [ ] All fuzz targets compile: `zig build test` (fuzz edge-case tests run as part of the standard test suite).
- [ ] No new findings from fuzz edge-case tests.
- [ ] Long-duration fuzzing has been run if parsing surfaces changed (admin JSON parser, schema parser, redaction engines).

### Container Security
- [ ] `docker build` succeeds with the current Dockerfile.
- [ ] Container image scan shows zero critical and zero high CVEs: `trivy image ghcr.io/cpbeamer/nanomask:latest`.
- [ ] Image runs as non-root (`USER 65534:65534` in Dockerfile).
- [ ] Base image is `scratch` (no OS packages, no shell).

### Supply Chain
- [ ] SBOM generated and attached to the release (see `docs/release_signing.md`).
- [ ] Binary signed with `minisign` and signature published alongside the binary.
- [ ] OCI image signed with `cosign` (keyless via GitHub OIDC).
- [ ] `build.zig.zon` dependencies unchanged, or any new dependencies reviewed for security.
- [ ] Zig toolchain version matches `minimum_zig_version` in `build.zig.zon`.

### Source Code
- [ ] No hardcoded secrets, API keys, or credentials in source: `grep -rn "BEGIN.*PRIVATE\|sk-\|AKIA\|password\s*=" src/`.
- [ ] Admin API auth (`--admin-token`) is enabled in all production examples and Helm defaults.
- [ ] TLS posture in deployment examples matches `docs/tls_strategy.md` recommendation.
- [ ] All `TODO` and `FIXME` comments reviewed for security relevance.

### Tests
- [ ] `zig build test` passes (includes security HTTP tests and fuzz edge cases).
- [ ] `zig build compat-matrix` produces a clean compatibility matrix.
- [ ] Security CI workflow (`security.yml`) passes on the release branch.

### Changelog
- [ ] Changelog reviewed for security-relevant changes.
- [ ] Security fixes explicitly called out with severity.
- [ ] Breaking changes documented with migration guidance.

## Sign-Off

| Reviewer | Date | Status |
|----------|------|--------|
| | | |

## Revision History

| Date | Change |
|------|--------|
| 2026-03-13 | Initial security review checklist |
