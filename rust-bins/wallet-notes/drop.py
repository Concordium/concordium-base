#!/usr/bin/env python3
import requests
import json
import binascii

# probably needs pip3 install pynacl
import nacl.signing
# probably needs pip3 install base58
import base58

import hashlib
import time

import argparse

PROXY_URL="https://wallet-proxy.eu.staging.concordium.com/"

import argparse

parser = argparse.ArgumentParser(description='Request GTU for a given account.')
parser.add_argument('source', metavar='FILE', type=str)
parser.add_argument('--target', type=str, dest='target', help='Address of the target account.')
parser.add_argument('--amount', type=int, dest='amount', help='Amount to transfer.')

args = parser.parse_args()

with open(args.source, "r") as f:
    input = json.load(f)
    keys = input["accountData"]["keys"]
    account = input["address"]
    account_raw = base58.b58decode_check(account.encode('ascii'))[1:]

nonce_response = requests.get(PROXY_URL + "accNonce/" + account)

nonce = json.loads(nonce_response.text)["nonce"]

print(f"Using nonce = {nonce}.")

payload_type = 3
address_kind = 0 

to_address = base58.b58decode_check(args.target.encode('ascii'))[1:]

amount = args.amount

energy = 165

payload = payload_type.to_bytes(1, 'big') + address_kind.to_bytes(1, 'big') + to_address + amount.to_bytes(8, 'big')

expiry = int(time.time()) + 3600

body = account_raw + nonce.to_bytes(8, 'big') + energy.to_bytes(8, 'big') + len(payload).to_bytes(4, 'big') + expiry.to_bytes(8, 'big') + payload

bodyHash = hashlib.sha256()
bodyHash.update(body)
bodyHash = bodyHash.digest()

signatures = dict()

for (key_index, key_obj) in keys.items():
    key = nacl.signing.SigningKey(key_obj["signKey"], encoder=nacl.encoding.HexEncoder)
    signatures[key_index] = binascii.hexlify(key.sign(bodyHash).signature).decode("utf-8")

submission = {"signatures" : signatures, "transaction": binascii.hexlify(body).decode("utf-8")}

r = requests.put(PROXY_URL + "submitTransfer/", data = json.dumps(submission))

print("Transfer submitted.")

print(json.dumps(json.loads(r.text)))
