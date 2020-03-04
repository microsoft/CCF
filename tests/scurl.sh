#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

# Loop through all arguments and find request data and private key
next_is_data=false
next_is_privk=false
for item in "$@" ; do
    if [ "$next_is_data" == true ]; then
        request=$item
        next_is_data=false
    fi
    if [ "$next_is_privk" == true ]; then
        privk=$item
        next_is_privk=false
    fi
    if [ "$item" == "-d" ] || [ "$item" == "--data" ] || [ "$item" == "--data-binary" ]; then
        next_is_data=true
    fi
    if [ "$item" == "--key" ]; then
        next_is_privk=true
    fi
done

if [ -z "$request" ]; then
    echo "No request found in arguments (-d or --data-binary)"
    exit 1
fi

if [ -z "$privk" ]; then
    echo "No private key found in arguments (--key)"
    exit 1
fi

# If the first letter of the request is @, consider it a filename
if [ "$(echo "$request" | cut -c1)" == "@" ]; then
    request="${request:1}"
    request=$(cat "$request")
fi

date=$(date "+%a, %d %b %Y %H:%M:%S %Z")

req_digest=$(echo -n "$request" | openssl dgst -sha256 -binary | openssl base64)

content_length=${#request}

# Construct string to sign
string_to_sign="date: $date
digest: SHA-256=$req_digest
content-length: $content_length"

# Compute signature
signed_raw=$(echo -n "$string_to_sign" | openssl dgst -sha256 -sign "$privk" | openssl base64 -A)

curl \
-H "Date: $date" \
-H "Digest: SHA-256=$req_digest" \
-H "Authorization: Signature keyId=\"tls\",algorithm=\"ecdsa-sha256\",headers=\"date digest content-length\",signature=\"$signed_raw\"" \
"$@"