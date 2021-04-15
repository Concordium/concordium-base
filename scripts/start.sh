#!/usr/bin/env bash

case "$MODE" in
	identity-verifier)
		/identity-verifier
		;;
	identity-provider-service)
		/identity-provider-service
		;;
	*)
		>&2 echo "Unsupported mode '$MODE'"
		exit 1
esac
