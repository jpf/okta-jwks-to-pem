# Introduction

This is a Python script that fetches JWKS results, and for
each jwk, uses the **modulus** and **exponent** to generate a PEM encoded
public key, suitable for use in tools like [jwt.io](https://jwt.io)

Here is an example of using this tool to get the PEM encoded public
keys for the "example.okta.com" Okta org:

    ./jwks_to_pem.py --org example.okta.com

    Fetching JWKS from example.okta.com
    PEM for KID 're7eOFV6SiygSbCyYHGGdERFCJ_EoNpi9Duv0FIxllo'
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgVdVgO4RogxtWt4XN2vO
    9SG3Ekt6Qh+k6Io28dTNjEWuNxCYCtQI2dFtFs2y7OyLxQ2e3491XTDVRxtUx/Kl
    RhQCcGDtLM5vTRWtGo39heg9dLWv7mqlk+jVkJrK2vAO+0bfl0x2Ouov4VS4Ixwx
    lJfaec8v0cw+xjcJc29Y28WNFYhW/wpf1uEHYAf/pQ9q7S25rhK5yPv23101P7pA
    bCNDyFB6PYLuXxqkE7dq7rIZXfw5xgNQBRugBrSmUEjoCFs3XowAXCk2gWhM/1Lg
    mSqaaAh/Cu5vvzM0wYoaEi598LWYmtgurQ3C2Nenu8HVjI+zCSg8v7VrcTa1MHua
    owIDAQAB
    -----END PUBLIC KEY-----
    
    PEM for KID 'kTP2cLZY0qA2qfnedNEgx6rs6yqIEdf4DQYYV2m4KPQ'
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjKb91FLaoZe9/5NEMZrO
    1eDn4hdrhtjrvsy+qO1QIbbdhRXJIJoE+qpHmgmq1gK28OZCV51xUAwk8ugw5p7/
    m2wIarykHtXuBmhcFPkWez6N/yX30qvdOPPKUGqd05AoGcrzAW6fV07CRROU+5g1
    RnTdNasLEMYaq0xPlmCMDjb3usyiafGyyrwg4+tndOTry4uMtF7LeTVLZo9Tnn2x
    dJiytWWh+Rq5/KAn1mJ2GgwG8tp8o7SRf65c0LYQenN1d6vXX/Iimq/mg//B5CHP
    zIaUrZfoL+2sbRIyQ5AePlDyn8Neg6sIsV9nTkPAcYvvQsS+/8xnfNq6np0zKbua
    dQIDAQAB
    -----END PUBLIC KEY-----

# Installing

This Python script depends on the `cryptography` and `requests` Python
2.7 packages

The easiest way to install these dependencies is to use the [Nix
package manager](https://nixos.org/nix/), which will automatically install these dependencies
for you if you run the commands below.

> Note: While Nix is the easiest way to install the dependencies for
> this script, Nix will download several hundred [MiB](https://en.wikipedia.org/wiki/Mebibyte) of packages these
> dependencies. If you don't want to use the Nix package manager, you
> can install the dependencies manually using your preferred package
> manager and then change the interpreter on the first line of
> included script from "`/usr/bin/env nix-shell`" to "`/usr/env/python`"

Here is how to install this script on your system using the Nix
package manager on GNU/Linux or Macintosh OS X systems:

1.  Install the Nix package manager:
    
        curl https://nixos.org/nix/install | sh
2.  Download the `get_id_token.sh` shell script to your system
    
        git clone git@github.com:jpf/okta-jwks-to-pem.git
3.  Change to the directory containing the `get_id_token.sh` shell
    script
    
        cd okta-jwks-to-pem
4.  Run the script:
    
        ./jwks-to-pem.py --org example.okta.org

# How it works

The most important part of this code is the conversion of RSA public
key modulus and exponent integers into a PEM encoded public key.

Thanks to the excellent [Python cryptography](https://cryptography.io/en/latest/) library, the process of
converting an RSA public key modulus and exponent is three step
process:

1.  Convert the JWK modulus and exponent, which are Base64url
    encoded, into integers:
    
        exponent = base64_to_long(jwk['e'])
        modulus = base64_to_long(jwk['n'])
    
    Note: This conversion is actually pretty frustrating, the
    `base64_to_long` function abstracts this all away.
2.  Use the [RSAPublicNumbers](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers) class to store the modulus and exponent
    
        numbers = RSAPublicNumbers(exponent, modulus)
        public_key = numbers.public_key(backend=default_backend())
3.  [Serialize the RSAPublicNumbers object](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/) to PEM
    
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

We cover the rest of the script below.

First, we import the libraries that we'll need:

-   `argparse`: For handling the `--org=` command line argument and giving
    help when it isn't present.
-   `base64`, `six`, `struct`: Used to properly decode the Base64url encoded modulus
    and exponent.
-   `cryptography`: For conversion of the modulus and exponent to PEM
-   `requests`: To fetch the JWKS URI

Here is how we import the dependencies listed above:

    import argparse
    import base64
    import six
    import struct
    
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    import requests

Next, we set up `ArgumentParser` to handle the `--org` command line
argument. The `required=true` option will cause `ArgumentParser` to give
help text if the `--org=` argument isn't present.

    arg_parser = argparse.ArgumentParser(
        description='JWK to PEM conversion tool')
    arg_parser.add_argument('--org',
                            dest='org',
                            help='Domain for Okta org',
                            required=True)
    args = arg_parser.parse_args()

The code below handles the ugly job of decoding and properly padding
the base64url encoded strings that are used in a JWK. This code
comes from: 

<https://github.com/rohe/pyjwkest/blob/master/src/jwkest/__init__.py> 

    def intarr2long(arr):
        return int(''.join(["%02x" % byte for byte in arr]), 16)
    
    
    def base64_to_long(data):
        if isinstance(data, six.text_type):
            data = data.encode("ascii")
    
        # urlsafe_b64decode will happily convert b64encoded data
        _d = base64.urlsafe_b64decode(bytes(data) + b'==')
        return intarr2long(struct.unpack('%sB' % len(_d), _d))

Here we fetch and decode the JSON from an Okta `jwks_uri` endpoint:

    print("Fetching JWKS from {}".format(args.org))
    r = requests.get("https://{}/oauth2/v1/keys".format(args.org))
    jwks = r.json()

Finally, we process each key, and print out the PEM encoded key for
each JWK Key ID (`kid`) that we find:

    for jwk in jwks['keys']:
        exponent = base64_to_long(jwk['e'])
        modulus = base64_to_long(jwk['n'])
        numbers = RSAPublicNumbers(exponent, modulus)
        public_key = numbers.public_key(backend=default_backend())
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
        print "PEM for KID '{}'".format(jwk['kid'])
        print pem