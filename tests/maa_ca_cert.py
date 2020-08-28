# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import requests
import base64
import subprocess

host = "shareduks.uks.attest.azure.net"

openid_url = f"https://{host}/.well-known/openid-configuration"
jwks_url = requests.get(openid_url).json()["jwks_uri"]

jwks = requests.get(jwks_url).json()

# Find a self-signed cert in the JWKS.
# MAA uses self-signed certs for signing MAA tokens.
cert_b64 = None
for jwk in jwks["keys"]:
    chain = jwk["x5c"]
    if len(chain) == 1:
        cert_b64 = chain[0]
        break
assert cert_b64, "no self-signed cert found!"

cert = base64.b64decode(cert_b64)
path_der = "maa_ca_cert.der"
with open(path_der, "wb") as f:
    f.write(cert)
path_pem = "maa_ca_cert.pem"
subprocess.run(
    ["openssl", "x509", "-inform", "DER", "-in", path_der, "-out", path_pem],
    check=True,
)
os.remove(path_der)
