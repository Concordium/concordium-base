#!/usr/bin/env python3
import requests
import json
import sys
import urllib

inputPio = json.loads(open(sys.argv[1], 'r').read())

input = json.dumps({'idObjectRequest': inputPio})

print(input)

payload = {'state': input,
           'redirect_uri': 'http://localhost:1234'
          }

r = requests.get('http://localhost:8100/api/identity', params=payload)

print(r)

print(r.text)

print(json.dumps(json.loads(r.text), indent=4, sort_keys=True))
