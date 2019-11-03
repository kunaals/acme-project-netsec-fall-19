from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from pprint import pprint
import sys
import requests
import copy
import json
import base64
import binascii

# for str in sys.argv:
#     print(str)

def _b64(b):
    # encodes string as base64
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')

directory_headers = {"User-Agent": "myacmeclient"}
jws_headers = copy.deepcopy(directory_headers)
jws_headers["Content-Type"] = "application/jose+json"
pebble_cert = "project/pebble_https_ca.pem"

# GET acme server config from /dir
ACME_SERVER_URL = "https://localhost:14000/dir"
r = requests.get(url=ACME_SERVER_URL, headers=directory_headers, verify=pebble_cert)
directory_data = r.json()
# pprint(directory_data)

# Create new account
# Retrieve new replay-nonce
nonce = requests.head(url = directory_data['newNonce'], headers=directory_headers, verify=pebble_cert)

# Generate RSA key
rsa_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Write our key to disk for safe keeping
with open("project/rsa_key.pem", "wb") as f:
    f.write(rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))

protected = {
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "n": str(rsa_key.public_key().public_numbers()._n),
        "e": str(rsa_key.public_key().public_numbers()._e)
    },
    "nonce": nonce.headers["Replay-Nonce"],
    "url": directory_data["newAccount"]
}
protected64 = _b64(json.dumps(protected).encode("utf8"))

payload = {
    "termsOfServiceAgreed": True,
    "contact": ["mailto:admin@lol.ch"]
}
payload64 = _b64(json.dumps(payload).encode("utf8"))

message = "{0}.{1}".format(protected64, payload64).encode('utf-8')

chosen_hash = hashes.SHA256()
hasher = hashes.Hash(chosen_hash, default_backend())
hasher.update(protected64.encode('utf-8'))
hasher.update(('.'+payload64).encode('utf-8'))
digest = hasher.finalize()
sig = rsa_key.sign(
    digest,
    padding.PKCS1v15(),
    utils.Prehashed(chosen_hash)
)
# print(_b64(sig))

jose_payload = {
    "protected": protected64,
    "payload": payload64,
    "signature": _b64(sig)
}

# rsa_key.public_key().verify(
#     base64.urlsafe_b64decode(jose_payload['signature']),
#     message,
#     padding.PKCS1v15(),
#     hashes.SHA256()
# )

# jws_headers["Host"] = 'localhost:14000'
pprint("{0}.{1}.{2}".format(jose_payload['protected'], jose_payload['payload'], jose_payload['signature']))
pprint(jws_headers)
# pprint(jose_payload)
r = requests.post(
    url=directory_data['newAccount'], 
    json=jose_payload, 
    headers=jws_headers, 
    verify=pebble_cert
)

pprint(r.json())




