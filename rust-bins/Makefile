all:
	mkdir -p database
	rm -rf database/*
	cargo run --bin client -- generate-global
	cargo run --bin client -- generate-ips
	cargo run --bin client -- create-chi --out database/chi.json
	cargo run --bin client -- start-ip --chi database/chi.json --private database/private.json --public database/public.json
	cargo run --bin client -- ip-sign-pio --ip-data database/identity_provider-0.json --pio database/public.json --out database/id.json
	cargo run --bin client -- deploy-credential --id-object database/id.json --ip-info database/identity_provider-1.pub.json --private database/private.json --bin-out database/credential.bin --out database/credential.json
	cargo run --bin client -- revoke-anonymity -a database/identity_provider-1_anonymity_revoker-0.json database/identity_provider-1_anonymity_revoker-1.json -c database/credential.json

