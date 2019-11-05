import argparse
import base64
import binascii
import copy
import datetime
import hashlib
import json
import logging
import multiprocessing
import os
import subprocess
import sys
import time
from pprint import pformat, pprint

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

import dns_server
import http_server
import http_shutdown_server
import https_server

DIR_URL = "https://localhost:14000/dir"
IPv4_RECORD = "127.0.0.1"
domains = ["example.com", "example.org"]
challenge_type = 'dns-01'

WRITE_KEYS = True
pebble_cert = "pebble_https_ca.pem"
directory_headers = {"User-Agent": "myacmeclient"}
# GET acme server config from /dir
directory_data = requests.get(
    url=DIR_URL, 
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


def _send_signed_request(url, payload, nonce, rsa_key, kid=None, jwk=None, field_check=None, retry=True):
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

    i = 0
    while field_check != None and field_check not in r.json() and i < 10:
        logging.debug('FIELD CHECK: ' + pformat(r.json()))
        print('field check')
        time.sleep(1) # wait before next call
        nonce = _new_nonce()
        i = i + 1
        r = _send_signed_request(url, payload, nonce, rsa_key, kid, jwk)

    if r.status_code != 200 and r.status_code != 201 and retry:
        # We try a new nonce
        for i in range(10):
            logging.debug('Trying new nonce.')
            print('new nonce')
            nonce = _new_nonce()
            try:
                r = _send_signed_request(url, payload, nonce, rsa_key, kid, jwk, retry=False)
                if r.status_code == 200 or r.status_code == 201: # extra check
                    return r
            except:
                print("failed request")
    elif r.status_code != 200 and r.status_code != 201 and not retry:
        logging.debug(pformat(r.json()))
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

    if WRITE_KEYS:
        # Write our private key to disk for safe keeping
        with open("rsa_private_key.pem", "wb+") as f:
            f.write(rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Write our public key to disk for safe keeping
        with open("rsa_public_key.pem", "wb+") as f:
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
            dns_thread = multiprocessing.Process(
                target=dns_server.run,
                args=([
                    '. 60 IN A ' + IPv4_RECORD, 
                ],)
            )
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
                    '. 60 IN A ' + IPv4_RECORD, 
                    '_acme-challenge.{0} 60 IN TXT \"{1}\"'.format(domain, key_auth_dns)
                ],)
            )
            dns_thread.start()
            time.sleep(1)
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

def send_csr(finalize_url, nonce, rsa_key, kid, domains):
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(domains[0])),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(str(d)) for d in domains
        ]),
        critical=False,
    # Sign the CSR with our private key.
    ).sign(rsa_key, hashes.SHA256(), default_backend())
    csr_payload = {
        "csr": _b64(csr.public_bytes(serialization.Encoding.DER)),
    }
    logging.debug("CSR: " + pformat(csr_payload))
    r = _send_signed_request(
        finalize_url,
        csr_payload,
        nonce,
        rsa_key,
        kid
    )
    logging.debug(pformat(r.json()))
    return r, r.headers['Replay-Nonce']

if __name__ == '__main__':
    q = argparse.ArgumentParser(description="A simple ACME client.")
    q.add_argument("challenge_type", choices=['http01', 'dns01'])
    q.add_argument("--dir",required=True,
                    metavar="<dir>",
                    help="(required) DIR URL is the directory URL of the ACME server that should be used.")
    q.add_argument("--record", required=True,
                    metavar="<record>",
                    help="(required) IPv4 ADDRESS is the IPv4 address which must be returned \
                    by your DNSserver for all A-record queries.")
    q.add_argument("--domain", required=True,
                    metavar="<domain>",
                    help="(required, multiple) DOMAIN is the domain for which to request the certificate. \
                        If multiple --domain flags are present, a single certificate for multiple domains should \
                        be requested. Wildcard domains have no special flag and are simply denoted by, \
                        e.g., *.example.net.")
    q.add_argument("--revoke",action='store_true',default=False,
                    help="(optional) If present, your application should immediately revoke the certificate \
                        after obtaining it. In both cases, your application should start its HTTPS server \
                        and set it up to use the newly obtained certificate.")

    params = q.parse_args()

    DIR_URL = params.dir
    print(DIR_URL)
    IPv4_RECORD = params.record
    print(IPv4_RECORD)
    domains = ["example.com", "example.org"]
    print(params.domain)
    if params.challenge_type == 'http01':
        challenge_type = 'http-01'
    else:
        challenge_type = 'dns-01'
    print(challenge_type)
    http_thread = multiprocessing.Process(
        target=http_server.run,
        args=[IPv4_RECORD]
    )
    http_thread.start()
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
    order, nonce = submit_order(domains, "dns", nonce, rsa_key, kid) # dns or http01
    order_json = order.json() # contains identifiers, list of authorizations, and finalize url
    order_url = order.headers['Location']

    # Solicit and solve challenges
    confirmations, nonce = solve_challenge(order_json, nonce, rsa_key, kid, challenge_type, accountkey)
    csr_response, nonce = send_csr(order_json['finalize'], nonce, rsa_key, kid, domains)
    # pprint(csr_response.json())
    cert_request = _send_signed_request(order_url, "", nonce, rsa_key, kid, field_check='certificate')
    # pprint(cert_request.json())
    cert = _send_signed_request(cert_request.json()['certificate'], "", nonce, rsa_key, kid)
    with open("web_cert.pem", "wb+") as f:
        f.write(cert.text.encode('utf-8'))
    http_thread.terminate()

    http_shutdown_thread = multiprocessing.Process(
        target=http_shutdown_server.run,
        args=[IPv4_RECORD])
    https_thread = multiprocessing.Process(
        target=https_server.run,
        args=[IPv4_RECORD])
    https_thread.start()
    http_shutdown_thread.start()

    while http_shutdown_thread.is_alive():
        pass
    http_shutdown_thread.terminate()
    https_thread.terminate()