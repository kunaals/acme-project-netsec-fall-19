from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from pprint import pprint
import sys, requests, copy, json, base64, binascii

ACME_SERVER_URL = "https://localhost:14000/dir"
pebble_cert = "project/pebble_https_ca.pem"
directory_headers = {"User-Agent": "myacmeclient"}
# GET acme server config from /dir
directory_data = requests.get(
    url=ACME_SERVER_URL, 
    headers=directory_headers, 
    verify=pebble_cert
).json()
jws_headers = copy.deepcopy(directory_headers)
jws_headers["Content-Type"] = "application/jose+json"

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

def _send_signed_request(url, payload, nonce, rsa_key, kid=None, jwk=None):
    # Generate protected header
    protected = {
        "alg": "RS256",
        "nonce": nonce,
        "url": url
    }
    if jwk:
        protected["jwk"] = jwk
    elif kid:
        protected["kid"] = kid
    else:
        raise Exception('No JWK or kid supplied.')
    
    # Convert to URL-safe encoding
    protected64 = _b64(json.dumps(protected).encode("utf8"))

    # Convert payload to URL-safe encoding
    payload64 = _b64(json.dumps(payload).encode("utf8"))
    
    # If request is POST-as-GET we set payload to be empty string
    if payload == "":
        payload64 = ""
    
    # Message is protected and payload dumps separated by a '.'
    message = "{0}.{1}".format(protected64, payload64).encode('utf-8')

    # Create RSA signature
    sig = rsa_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Generate JOSE payload for request
    jose_payload = {
        "protected": protected64,
        "payload": payload64,
        "signature": _b64(sig)
    }

    r = requests.post(
        url=url, 
        json=jose_payload, 
        headers=jws_headers, 
        verify=pebble_cert
    )

    if r.status_code != 200 and r.status_code != 201:
        raise Exception("Failed request. " + json.dumps(r.json()))
    
    return r

def create_account():
    # Create new account
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
    jwk = {
        "kty": "RSA",
        "n": _b64_rsa_public_numbers(rsa_key.public_key().public_numbers()._n),
        "e": _b64_rsa_public_numbers(rsa_key.public_key().public_numbers()._e)
    }

    # Generate payload for JWS
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:admin@lol.ch"]
    }

    # Retrieve new replay-nonce
    nonce = requests.head(
        url = directory_data['newNonce'], 
        headers=directory_headers, 
        verify=pebble_cert
    )
    account = _send_signed_request(
        directory_data['newAccount'], 
        payload, 
        nonce=nonce.headers['Replay-Nonce'], 
        rsa_key=rsa_key, 
        jwk=jwk
    )
    return account, rsa_key

def submit_order(domains, challenge, nonce, rsa_key, kid):
    payload = { 'identifiers': [] }
    for d in domains:
        payload['identifiers'].append({"type": challenge, "value": d})
    
    order = _send_signed_request(
        directory_data['newOrder'], 
        payload,
        nonce=nonce,
        rsa_key=rsa_key,
        kid=kid
    )
    return order, order.headers['Replay-Nonce']

def authorization_request(authorizations, nonce, rsa_key, kid):
    challenges = []
    for a in authorizations:
        chall = _send_signed_request(
            a,
            "",
            nonce,
            rsa_key,
            kid=kid
        )
        nonce = chall.headers['Replay-Nonce']
        challenges.extend(chall.json()["challenges"])
    return challenges, nonce

# main
# Create account
account, rsa_key = create_account()
kid = account.headers['Location']
nonce = account.headers['Replay-Nonce']

# Submit order
order, nonce = submit_order(["example.com"], "dns", nonce, rsa_key, kid)
authorizations = order.json()["authorizations"] # list of authorizations

# Solicit challenges
challenges, nonce = authorization_request(authorizations, nonce, rsa_key, kid)
pprint(challenges)
