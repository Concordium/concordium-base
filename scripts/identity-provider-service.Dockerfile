# Build binaries in builder image.
ARG base_image_tag
FROM concordium/base:${base_image_tag} as builder
COPY . /build
WORKDIR /build/identity-provider-service
RUN cargo build --release

# Collect build artifacts in fresh image.
FROM ubuntu:20.04
RUN apt-get update && \
    apt-get -y install \
      libssl-dev \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/identity-provider-service/target/release/identity-provider-service /identity-provider-service
COPY --from=builder /build/identity-provider-service/target/release/identity-verifier /identity-verifier
COPY --from=builder /build/scripts/start.sh /start.sh
ENTRYPOINT ["/start.sh"]
