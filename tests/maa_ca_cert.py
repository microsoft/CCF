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

# First cert is used for signing tokens.
cert_b64 = jwks["keys"][0]["x5c"][0]

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
