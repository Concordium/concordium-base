# Build binaries in builder image.
FROM rust:1.85.1-bookworm AS builder
RUN apt-get update && \
    apt-get -y install --no-install-recommends \
      pkg-config \
      libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . /build
WORKDIR /build/identity-provider-service
RUN cargo build --release --locked

# Collect build artifacts in fresh image.
FROM ubuntu:24.04
RUN apt-get update && \
    apt-get -y install \
      libssl-dev \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/identity-provider-service/target/release/identity-provider-service /identity-provider-service
COPY --from=builder /build/identity-provider-service/target/release/identity-verifier /identity-verifier
ENTRYPOINT ["/bin/sh", "-c", "case \"$MODE\" in identity-verifier|identity-provider-service) exec /\"$MODE\" ;; *) echo \"Unsupported mode '$MODE'\" >&2; exit 1 ;; esac"]
