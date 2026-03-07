# ── Stage 1: Builder ─────────────────────────────────────────────────
# Pin the Zig version here. If ghcr.io/ziglang/zig:0.15.2 is available,
# replace this stage with:  FROM ghcr.io/ziglang/zig:0.15.2 AS builder
FROM alpine:3.21 AS builder

# Install Zig 0.15.2 from the official tarball.
ARG ZIG_VERSION=0.15.2
RUN apk add --no-cache curl xz && \
    mkdir -p /opt/zig && \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
    | tar -xJ -C /opt/zig --strip-components=1
ENV PATH="/opt/zig:${PATH}"

WORKDIR /app

# Copy only build inputs — .dockerignore excludes .git, caches, docs, etc.
COPY build.zig build.zig.zon ./
COPY src/ src/
# Test fixtures required by unit tests (file_watcher, entity loading).
COPY entities.txt ./

# Run tests natively (Alpine is x86_64-linux) — tests need to execute,
# not just cross-compile. Cross-compilation is only for the release binary.
RUN zig build test

# Produce a fully static, release-optimised binary.
RUN zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-musl

# ── Stage 2: Runtime (scratch — zero CVEs, zero package manager) ────
FROM scratch

# Copy the static binary from the builder stage.
COPY --from=builder /app/zig-out/bin/NanoMask /nanomask

# Non-root execution (nobody:nogroup).
USER 65534:65534

EXPOSE 8081

# The binary itself acts as the health check client (scratch has no curl).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/nanomask", "--healthcheck"]

ENTRYPOINT ["/nanomask"]
