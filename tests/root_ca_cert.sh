#!/bin/bash
set -ex

if [ -z "$OE_BUILD_DIR" ]; then
    echo "OE_BUILD_DIR must be set to the build folder of OE"
    exit 1
fi

openssl genrsa -out key.priv 2048
openssl rsa -in key.priv -outform PEM -pubout -out key.pub

"$OE_BUILD_DIR/tests/tools/oecert/host/oecert" \
    "$OE_BUILD_DIR/tests/tools/oecert/enc/oecert_enc" \
    --cert key.priv key.pub \
    --out root_ca_cert.der

openssl x509 -inform DER -in root_ca_cert.der -out root_ca_cert.pem

rm key.priv key.pub root_ca_cert.der
