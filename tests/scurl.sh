#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

# TODO:
# - Support for inline string input

req=$1

# Args:
# - private key
# - headers to sign
# - host and port
# - Passthrough to curl: URI, --cacert, --key, --cert, -data-binary

# Get date
date=$(date "+%a, %d %b %Y %H:%M:%S %Z")
echo "$date"

# Compute digest
req_digest=$(echo -n $(cat $req) | openssl dgst -sha256 -binary | openssl base64)
echo $req_digest

# Construct string to sign
string_to_sign="date: $date
digest: SHA-256=$req_digest"
echo -n $string_to_sign > string_to_sign
echo "$string_to_sign"

echo ""
echo ""
echo ""
echo ""

# Create signature
signed_raw=$(echo -n "$string_to_sign" | openssl dgst -sha256 -sign member1_privk.pem | openssl base64 -A)
echo $signed_raw

curl \
-H "Date: $date" \
-H "Digest: SHA-256=$req_digest" \
-H "Authorization: Signature keyId=\"lala\",algorithm=\"ecdsa-sha256\",headers=\"date digest\",signature=\"$signed_raw\"" \
-H "Content-Type: application/json" \
-d @$req \
--key member1_privk.pem \
--cert member1_cert.pem \
--cacert networkcert.pem \
https://127.47.192.242:42503/members/vote