# RustCrash - Cross-platform mihomo/sing-box management
# Multi-stage build for minimal image size

# Stage 1: Build
FROM rust:1.98-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl

# Copy workspace files
COPY Cargo.toml Cargo.lock* ./
COPY core/ core/
COPY engine/ engine/
COPY cmd/ cmd/
COPY tests/ tests/

# Build the single crash binary for musl (static)
RUN cargo build --release --target x86_64-unknown-linux-musl --bin crash

# Stage 2: Minimal runtime image
FROM alpine:3.19

# Install runtime dependencies
# gcompat: glibc compatibility — the mihomo/sing-box release binaries are
# glibc-linked and need it to execute on musl Alpine.
RUN apk add --no-cache \
    ca-certificates \
    iptables \
    nftables \
    bash \
    curl \
    gcompat

# The single management binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/crash /usr/local/bin/

RUN chmod +x /usr/local/bin/crash

# Default command
ENTRYPOINT ["/usr/local/bin/crash"]
