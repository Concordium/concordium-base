# syntax=docker/dockerfile:experimental
FROM 192549843005.dkr.ecr.eu-west-1.amazonaws.com/concordium/base:0.12 as build

WORKDIR /

RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan gitlab.com >> ~/.ssh/known_hosts

RUN --mount=type=ssh git clone git@gitlab.com:Concordium/crypto.git

RUN (cd crypto/rust-bins && cargo build --release && cp target/release/wallet_server /wallet_server && cp ../scripts/start.sh /start.sh)

RUN --mount=type=ssh git clone git@gitlab.com:Concordium/p2p-client.git
RUN --mount=type=ssh (cd p2p-client && git checkout develop && git submodule update --init --recursive && ./scripts/download-genesis-complementary-bundle.sh)

RUN cp -r p2p-client/genesis-complementary-bundle /genesis-complementary-bundle

FROM ubuntu:20.04

RUN useradd -l -m -s /bin/false -u 61000 docker

COPY --from=build /wallet_server /wallet-server
COPY --from=build /start.sh /start.sh
RUN chmod a+x /start.sh
RUN mkdir -p /wallet-server-data
COPY --from=build /genesis-complementary-bundle/identity-providers-with-metadata.json /wallet-server-data/identity-providers-with-metadata.json
COPY --from=build /genesis-complementary-bundle/global.json /wallet-server-data/global.json

USER docker

ENTRYPOINT ["/start.sh"]
