#!/usr/bin/env python3
import requests
import json

payload = {'id_request': open("id_request.json", 'r').read()}

r = requests.get('http://localhost:8000/request_id', params=payload)

print(json.dumps(json.loads(r.text), indent=4, sort_keys=True))
