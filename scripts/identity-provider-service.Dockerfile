# syntax=docker/dockerfile:experimental

# Build binaries in builder image.
FROM 192549843005.dkr.ecr.eu-west-1.amazonaws.com/concordium/development:0.17 as builder
COPY . /build
RUN (cd /build/identity-provider-service && cargo build --release)

# Fetch selected files from genesis data.
RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan gitlab.com >> ~/.ssh/known_hosts

# Clone specified ref of genesis-data (master by default).
# The only files that are needed are `global.json`, `anonymity_revokers.json`, and `ip_private_keys/identity_provider-1.json`.
# These change rarely and are always manually generated and curated.
# It is important that those files match the identity providers and global parameters of the network
# the identity provider will connect to. This needs to be ensured manually.
ARG GENESIS_REF=master
RUN --mount=type=ssh git clone --depth 1 --branch ${GENESIS_REF} git@gitlab.com:Concordium/genesis-data.git

# Collect build artifacts in fresh image.
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y libssl-dev ca-certificates
COPY --from=builder /build/identity-provider-service/target/release/identity-provider-service /identity-provider-service
COPY --from=builder /build/identity-provider-service/target/release/identity-verifier /identity-verifier
COPY --from=builder /build/identity-provider-service/data/identity_provider.pub.json /identity_provider.pub.json
COPY --from=builder /genesis-data/global.json /global.json
COPY --from=builder /genesis-data/anonymity_revokers.json /anonymity_revokers.json
COPY --from=builder /genesis-data/ip_private_keys/identity_provider-1.json /identity_provider.json
COPY --from=builder /build/scripts/start.sh /start.sh
RUN chmod a+x /start.sh

ENTRYPOINT ["/start.sh"]
