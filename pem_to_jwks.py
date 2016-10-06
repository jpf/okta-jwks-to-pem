#! /usr/bin/env nix-shell
#! nix-shell -i python -p python27Packages.cryptography
# This is, essentially, the reverse of "jwks_to_pem.py".
# Given a PEM encoded public key, it will extract the modulus and exponent
# from the key and return JWKS formatted JSON

input_key = ""

import struct
import base64
import argparse
import fileinput
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


parser = argparse.ArgumentParser()
parser.add_argument('--kid',
                    default="example",
                    help='JWK Key ID to include in output.')
parser.add_argument('key',
                    metavar='FILE',
                    nargs='?',
                    help='PEM encoded public key. Use "-" for STDIN.')
args = parser.parse_args()

input_file = args.key

if input_file is None:
    parser.print_help()
    sys.exit(1)

for line in fileinput.input(files=input_file):
    input_key += line


def long2intarr(long_int):
    _bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n):
    bys = long2intarr(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")


pem_data = input_key
public_key = serialization.load_pem_public_key(
    input_key,
    backend=default_backend())

public_numbers = public_key.public_numbers()

jwk = {
    "alg": "RS256",
    "e": None,
    "n": None,
    "kid": args.kid,
    "kty": "RSA",
    "use": "sig"
}

jwk['n'] = long_to_base64(public_numbers.n)
jwk['e'] = long_to_base64(public_numbers.e)

import json

print json.dumps(jwk)
