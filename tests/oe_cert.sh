#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -e

if [ -z "$OE_BUILD_DIR" ]; then
    echo "OE_BUILD_DIR must be set to the build folder of OE"
    exit 1
fi

OECERT_TOOL="$OE_BUILD_DIR/tests/tools/oecert/host/oecert"
OECERT_ENCL="$OE_BUILD_DIR/tests/tools/oecert/enc/oecert_enc"

if [ ! -f "$OECERT_TOOL" ]; then
    echo "$OECERT_TOOL not found, did you build with -DBUILD_TESTS=ON?"
    exit 1
fi

set -x

openssl genrsa -out oe_cert_key.priv 2048
openssl rsa -in oe_cert_key.priv -outform PEM -pubout -out oe_cert_key.pub

"$OECERT_TOOL" "$OECERT_ENCL" \
    --cert oe_cert_key.priv oe_cert_key.pub \
    --out oe_cert.der

openssl x509 -inform DER -in oe_cert.der -out oe_cert.pem
openssl x509 -inform DER -in oe_cert.der -text
echo "New attested certificate written to oe_cert.pem"

rm oe_cert_key.priv oe_cert_key.pub oe_cert.der
