#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

# Loop through all arguments and find url, request data, command and private key
# NB: For simplicity, assume url is the first argument or preceded by --url. curl is slightly more permissive
next_is_url=false
next_is_data=false
next_is_command=false
next_is_privk=false

url=$1
command="post"

for item in "$@" ; do
    if [ "$next_is_url" == true ]; then
        url=$item
        next_is_url=false
    fi
    if [ "$next_is_data" == true ]; then
        request=$item
        next_is_data=false
    fi
    if [ "$next_is_command" == true ]; then
        command=$item
        next_is_command=false
    fi
    if [ "$next_is_privk" == true ]; then
        privk=$item
        next_is_privk=false
    fi
    if [ "$item" == "--url" ]; then
        next_is_url=true
    fi
    if [ "$item" == "-d" ] || [ "$item" == "--data" ] || [ "$item" == "--data-binary" ]; then
        next_is_data=true
    fi
    if [ "$item" == "-X" ] || [ "$item" == "--request" ]; then
        next_is_command=true
    fi
    if [ "$item" == "--key" ]; then
        next_is_privk=true
    fi
done

if [ -z "$privk" ]; then
    echo "Error: No private key found in arguments (--key)"
    exit 1
fi

additional_curl_args=()

if [ -z "$request" ]; then
    # If no request is provided, use empty body (content-length and digest calculation proceed as normal)
    request=""
    additional_curl_args+=(-H "content-length: 0")
fi

# If the first letter of the request is @, consider it a filename
if [ "$(echo "$request" | cut -c1)" == "@" ]; then
    request_path="${request:1}"
    req_digest=$(openssl dgst -sha256 -binary "$request_path" | openssl base64)
    content_length=$(wc -c "$request_path" | awk '{print $1}' )
else
    req_digest=$(printf "%s" "$request" | openssl dgst -sha256 -binary | openssl base64)
    content_length=${#request}
fi

# Trim URL to just the ":path" pseudo-header
# https://tools.ietf.org/html/rfc7540#section-8.1.2.3
url=${url#*//} # Remove protocol
url=/${url#*/} # Remove domain name, restore leading slash
url=${url%\#*} # Remove fragment

# Construct string to sign
string_to_sign="(request-target): ${command,,} ${url}
digest: SHA-256=$req_digest
content-length: $content_length"

# Compute signature
signed_raw=$(echo -n "$string_to_sign" | openssl dgst -sha256 -sign "$privk" | openssl base64 -A)

curl \
-H "Digest: SHA-256=$req_digest" \
-H "Authorization: Signature keyId=\"tls\",algorithm=\"ecdsa-sha256\",headers=\"(request-target) digest content-length\",signature=\"$signed_raw\"" \
"${additional_curl_args[@]}" \
"$@"