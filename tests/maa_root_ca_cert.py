# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import requests
import base64
import subprocess

# https://shareduks.uks.attest.azure.net/.well-known/openid-configuration
url = "https://shareduks.uks.attest.azure.net/certs"

o = requests.get(url).json()

keys = []
for k in o["keys"]:
    for key in k["x5c"]:
        keys.append(key)

# The first key is the one we need.
key_b64 = keys[0]

cert = base64.b64decode(key_b64)
path_der = "maa_root_ca_cert.der"
with open(path_der, "wb") as f:
    f.write(cert)
path_pem = "maa_root_ca_cert.pem"
subprocess.run(
    ["openssl", "x509", "-inform", "DER", "-in", path_der, "-out", path_pem],
    check=True,
)
os.remove(path_der)
