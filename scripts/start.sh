#!/usr/bin/env bash

if [ -n "$WALLET_SERVER_INFOS_FILE" ];
then
    ARGS="$ARGS --ip-infos $WALLET_SERVER_INFOS_FILE"
else
    ARGS="$ARGS --ip-infos /genesis-complementary-bundle/identity-providers-with-metadata.json"
fi
if [ -n "$WALLET_SERVER_GLOBAL_FILE" ];
then
    ARGS="$ARGS --global $WALLET_SERVER_GLOBAL_FILE"
else
    ARGS="$ARGS --global /genesis-complementary-bundle/global.json"
fi
if [ -n "$DB_SLEEP" ];
then
    echo "Sleeping for $DB_SLEEP"
    sleep $DB_SLEEP
fi

/wallet-server --address 0.0.0.0:8000 $ARGS
