#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

# Loop through all arguments and find request data
next_is_data=false
for item in "$@" ; do
    if [ "$next_is_data" == true ]; then
        request=$item
        next_is_data=false
    fi
    if [ "$item" == "-d" ] || [ "$items" == "--data-binary" ]; then
        next_is_data=true
    fi
done

if [ -z "$request" ]; then
    echo "No request found in arguments"
    exit 1
fi

if [ $(echo "$request" | cut -c1) == "@" ]; then
    request="${request:1}"
    request=$(cat "$request")
fi

# Get date
date=$(date "+%a, %d %b %Y %H:%M:%S %Z")

req_digest=$(echo -n $request | openssl dgst -sha256 -binary | openssl base64)

# Construct string to sign
string_to_sign="date: $date
digest: SHA-256=$req_digest"

# Compute signature
signed_raw=$(echo -n "$string_to_sign" | openssl dgst -sha256 -sign member1_privk.pem | openssl base64 -A)

curl \
-H "Date: $date" \
-H "Digest: SHA-256=$req_digest" \
-H "Authorization: Signature keyId=\"tls\",algorithm=\"ecdsa-sha256\",headers=\"date digest\",signature=\"$signed_raw\"" \
"$@"

echo ""