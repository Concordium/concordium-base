#!/usr/bin/env bash

if [ -n "$WALLET_SERVER_INFOS_FILE" ];
then
    ARGS="$ARGS --ip-infos $WALLET_SERVER_INFOS_FILE"
else
    ARGS="$ARGS --ip-infos /wallet-server-data/identity-providers-with-metadata.json"
fi
if [ -n "$WALLET_SERVER_GLOBAL_FILE" ];
then
    ARGS="$ARGS --global $WALLET_SERVER_GLOBAL_FILE"
else
    ARGS="$ARGS --global /wallet-server-data/global.json"
fi
if [ -n "$DB_SLEEP" ];
then
    echo "Sleeping for $DB_SLEEP"
    sleep $DB_SLEEP
fi

/wallet-server --address 0.0.0.0:8000 $ARGS
