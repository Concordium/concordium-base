# syntax=docker/dockerfile:experimental

# This Dockerfile builds a relatively small docker image that contains all the tools
# needed to generate a genesis block. These tools are
# - genesis_tool to create accounts
# - client to create identity providers, anonymity revokers, and cryptographic parameters
# - generate-update-keys to create update keys
# - genesis to finally combine all the input files into a `genesis.dat` file.

# The builder is based on a base image that has stack, haskell, and rust installed.
# The only argument is the branch name of a concordium-base repository branch, given as BASE_REF.

FROM 192549843005.dkr.ecr.eu-west-1.amazonaws.com/concordium/base:0.18 AS builder

# Which branch of concordium-base to build the tools from.
ARG BASE_REF=master

RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan gitlab.com >> ~/.ssh/known_hosts

RUN --mount=type=ssh git clone --depth 1 --branch ${BASE_REF} git@gitlab.com:Concordium/concordium-base.git

WORKDIR /concordium-base

# Build haskell tools.
RUN stack build concordium-base:exe:generate-update-keys concordium-base:exe:genesis

# Build rust tools
# The vendored feature makes for statically built binaries, not depending
# on libssl.
RUN cargo build --manifest-path rust-bins/Cargo.toml --release --features openssl-sys/vendored

# Copy interesting binaries
RUN mkdir libs bins

RUN cp $(stack exec -- which generate-update-keys) $(stack exec -- which genesis) bins
RUN cp rust-bins/target/release/client rust-bins/target/release/genesis_tool bins

RUN cp rust-src/target/release/*.so libs

# Start a new stage with just the binaries.
# This base image should be the same as the one for the concordium-base image
# so that we have no problems with shared libraries.
FROM debian:buster

WORKDIR /

# Install the necessary dependencies for running binaries.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq-dev

# Copy shared libraries to a location in the library path.
COPY --from=builder /concordium-base/libs/ /usr/local/lib/

# And binaries into PATH.
COPY --from=builder /concordium-base/bins/ /usr/local/bin/

# Finally, update the shared library cache so that binaries can be run without setting LD_LIBRARY_PATH
RUN ldconfig
