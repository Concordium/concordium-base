# This Dockerfile builds a relatively small docker image that contains all the tools
# needed to generate a genesis block. These tools are
# - genesis_tool to create accounts
# - client to create identity providers, anonymity revokers, and cryptographic parameters
# - generate-update-keys to create update keys
# - genesis to finally combine all the input files into a `genesis.dat` file.

# The builder is based on a base image that has stack, haskell, and rust installed.
# The only argument is the branch name of a concordium-base repository branch, given as 'base_ref'.

ARG base_image_tag
FROM concordium/base:${base_image_tag} AS builder

COPY . /build
WORKDIR /build

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
COPY --from=builder /build/libs/ /usr/local/lib/

# And binaries into PATH.
COPY --from=builder /build/bins/ /usr/local/bin/

# Make a workspace for mapping and running commands.
RUN mkdir /home/workspace

# Finally, update the shared library cache so that binaries can be run without setting LD_LIBRARY_PATH
RUN ldconfig
