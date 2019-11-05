from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from pprint import pprint, pformat
import sys, requests, copy, json, base64, binascii, hashlib, os, time, datetime
import logging, subprocess
import dns_server
import multiprocessing

WRITE_KEYS = False
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

def _new_nonce():
    r = requests.head(
        url = directory_data['newNonce'], 
        headers=directory_headers, 
        verify=pebble_cert
    )
    return r.headers['Replay-Nonce']

def _poll_challenge(a_url, nonce, rsa_key, kid):
    # Helper method that returns True when challenge is validated
    # and returns False if the challenge is not validated within 10 tries
    chall = _send_signed_request(
        a_url,
        "",
        nonce,
        rsa_key,
        kid=kid
    )
    nonce = chall.headers['Replay-Nonce']
    i = 1
    while chall.json()['status'] != 'valid':
        if i > 10:
            return False, nonce
        time.sleep(2) # sleep for 2 seconds
        chall = _send_signed_request(
            a_url,
            "",
            nonce,
            rsa_key,
            kid=kid
        )
        nonce = chall.headers['Replay-Nonce']
        i = i + 1
    return True, nonce


def _send_signed_request(url, payload, nonce, rsa_key, kid=None, jwk=None, field_check=None):
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
        # First try a new nonce
        try:
            logging.debug('Trying new nonce.')
            print('new nonce')
            nonce = _new_nonce()
            r = _send_signed_request(url, payload, nonce, rsa_key, kid, jwk)
        except:
            raise Exception("Failed request. " + json.dumps(r.json()))
    i = 0
    while field_check != None and field_check not in r.json() and i < 10:
        logging.debug('FIELD CHECK: ' + pformat(r.json()))
        print('field check')
        time.sleep(1) # wait before next call
        nonce = _new_nonce()
        i = i + 1
        r = _send_signed_request(url, payload, nonce, rsa_key, kid, jwk)
    return r

def create_account():
    # Create new account
    # Generate RSA key
    rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    if WRITE_KEYS:
        # Write our private key to disk for safe keeping
        with open("project/rsa_private_key.pem", "wb+") as f:
            f.write(rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            ))

        # Write our public key to disk for safe keeping
        with open("project/rsa_public_key.pem", "wb+") as f:
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

    accountkey = json.dumps(jwk, sort_keys=True, separators=(',', ':'))

    # Generate payload for JWS
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:admin@lol.ch"]
    }

    # Retrieve new replay-nonce
    nonce = _new_nonce()

    account = _send_signed_request(
        directory_data['newAccount'], 
        payload, 
        nonce=nonce, 
        rsa_key=rsa_key, 
        jwk=jwk
    )
    return account, rsa_key, accountkey

def submit_order(domains, challenge, nonce, rsa_key, kid):
    payload = { 'identifiers': [] }
    for d in domains:
        payload['identifiers'].append({"type": challenge, "value": d})
    
    order = _send_signed_request(
        directory_data['newOrder'], 
        payload,
        nonce=nonce,
        rsa_key=rsa_key,
        kid=kid,
        field_check="authorizations"
    )
    return order, order.headers['Replay-Nonce']

def solve_challenge(authorizations, nonce, rsa_key, kid, challenge_type, thumbprint):
    if challenge_type != 'http-01' and challenge_type != 'dns-01':
        raise Exception('Invalid challenge type.')
    confirmations = [] # store confirmation responses of the challenges that we attempt
    for a_url in authorizations["authorizations"]:
        # Retrieve challenges from ACME server
        chall = _send_signed_request(
            a_url,
            "",
            nonce,
            rsa_key,
            kid=kid,
            field_check="challenges"
        )
        nonce = chall.headers['Replay-Nonce']
        # Isolate the types of challenges that we wish to attempt
        challenge = [c for c in chall.json()["challenges"] if c['type'] == challenge_type][0]
        domain = chall.json()['identifier']['value']
        token = challenge['token']
        thumbprint = hashlib.sha256(accountkey.encode("utf-8")).digest()
        key_auth = "{0}.{1}".format(token, _b64(thumbprint))
        key_auth_dns = _b64(hashlib.sha256(key_auth.encode("utf-8")).digest())
        if challenge_type == 'http-01':
            thumbprint = _b64(hashlib.sha256(accountkey.encode("utf-8")).digest())
            key_auth = "{0}.{1}".format(token, thumbprint)
            # start DNS server with just A record
            dns_thread = multiprocessing.Process(target=dns_server.run)
            dns_thread.start()
            # Create file on domain and write key_auth to challenge file
            # First we create the directory
            challenge_dir = os.path.join('.well-known','acme-challenge')
            if not os.path.exists(challenge_dir):
                os.makedirs(challenge_dir)
            # Then we write the file with name token
            challenge_path = os.path.join(challenge_dir, token)
            with open(challenge_path, "x") as file:
                file.write(key_auth)
            # POST to the challenge url indicating that we have created the challenge file
            confirmation = _send_signed_request(
                challenge['url'],
                {},
                nonce,
                rsa_key,
                kid
            )
            nonce = confirmation.headers['Replay-Nonce']
            confirmations.append(confirmation)
            valid = _poll_challenge(a_url, nonce, rsa_key, kid)
            if not valid:
                raise Exception('Challenge failed.')
            os.remove(challenge_path) # remove the challenge file after validation            
            dns_thread.terminate()
        elif challenge_type == 'dns-01':
            # start DNS server with A record and TXT record for challenge
            dns_thread = multiprocessing.Process(
                target=dns_server.run,
                args=([
                    '. 60 IN A 127.0.0.1', 
                    '_acme-challenge.{0} 60 IN TXT \"{1}\"'.format(domain, key_auth_dns)
                ],)
            )
            dns_thread.start()
            confirmation = _send_signed_request(
                challenge['url'],
                {},
                nonce,
                rsa_key,
                kid
            )
            nonce = confirmation.headers['Replay-Nonce']
            confirmations.append(confirmation)
            valid = _poll_challenge(a_url, nonce, rsa_key, kid)
            if not valid:
                raise Exception('Challenge failed.')
            dns_thread.terminate()
    return confirmations, nonce

# main
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(level=logging.DEBUG, filename="logs/{0}.txt".format(datetime.datetime.now()))
logging.info("starting")
# Create account
account, rsa_key, accountkey = create_account()
while 'Location' not in account.headers:
    print('Location not in account.headers')
    logging.debug(pformat(account))
    # wait before next call and retry
    time.sleep(1)
    account, rsa_key, thumbprint = create_account()
kid = account.headers['Location']
nonce = account.headers['Replay-Nonce']

# Submit order 
order, nonce = submit_order(["example.com", "example.org"], "dns", nonce, rsa_key, kid) # dns or http01
authorizations = order.json() # contains identifiers and list of authorizations

# Solicit and solve challenges
confirmations, nonce = solve_challenge(authorizations, nonce, rsa_key, kid, 'dns-01', accountkey)

