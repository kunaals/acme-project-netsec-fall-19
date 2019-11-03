from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from pprint import pprint
import sys, requests, copy, json, base64, binascii

ACME_SERVER_URL = "https://localhost:14000/dir"
directory_headers = {"User-Agent": "myacmeclient"}
jws_headers = copy.deepcopy(directory_headers)
jws_headers["Content-Type"] = "application/jose+json"
pebble_cert = "project/pebble_https_ca.pem"

# for str in sys.argv:
#     print(str)

def _b64(b):
    # encodes string as base64
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')

def _b64_rsa_public_numbers(input):
    # encodes an RSA public number into b64 url-safe string
    num = "{0:x}".format(input)
    num = "0{0}".format(num) if len(num) % 2 else num
    return _b64(binascii.unhexlify(num.encode("utf-8")))

def create_account():
    # GET acme server config from /dir
    r = requests.get(
        url=ACME_SERVER_URL, 
        headers=directory_headers, 
        verify=pebble_cert
    )
    directory_data = r.json()

    # Create new account
    # Retrieve new replay-nonce
    nonce = requests.head(
        url = directory_data['newNonce'], 
        headers=directory_headers, 
        verify=pebble_cert
    )

    # Generate RSA key
    rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write our private key to disk for safe keeping
    with open("project/rsa_private_key.pem", "wb") as f:
        f.write(rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    # Write our public key to disk for safe keeping
    with open("project/rsa_public_key.pem", "wb") as f:
        f.write(rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Generate protected header
    protected = {
        "alg": "RS256",
        "jwk": {
            "kty": "RSA",
            "n": _b64_rsa_public_numbers(rsa_key.public_key().public_numbers()._n),
            "e": _b64_rsa_public_numbers(rsa_key.public_key().public_numbers()._e)
        },
        "nonce": nonce.headers["Replay-Nonce"],
        "url": directory_data["newAccount"]
    }
    # Convert to URL-safe encoding
    protected64 = _b64(json.dumps(protected).encode("utf8"))

    # Generate payload for JWS
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:admin@lol.ch"]
    }
    # Conver to URL-safe encoding
    payload64 = _b64(json.dumps(payload).encode("utf8"))

    # Message is protected and payload dumps separated by a '.'
    message = "{0}.{1}".format(protected64, payload64).encode('utf-8')

    # Create RSA signature
    sig = rsa_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Generate JOSE payload for final request
    jose_payload = {
        "protected": protected64,
        "payload": payload64,
        "signature": _b64(sig)
    }

    # pprint("{0}.{1}.{2}".format(jose_payload['protected'], jose_payload['payload'], jose_payload['signature']))
    # pprint(jws_headers)

    account = requests.post(
        url=directory_data['newAccount'], 
        json=jose_payload, 
        headers=jws_headers, 
        verify=pebble_cert
    )
    return account

pprint(create_account().headers)