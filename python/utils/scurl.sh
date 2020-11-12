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

algorithm="hs2019"

hash_to_sign=$(echo -n "$string_to_sign" | openssl dgst -binary -sha384 | openssl base64 -A)

signature_base64url=$(curl -s -X POST https://demo-vault-ccf.vault.azure.net/keys/key-sign-ccf-pub4/98fa9e4ddbf24b16a6cf3a75bad9b7c0/sign?api-version=7.1 --data "{\"alg\":\"ES384\", \"value\":\"$hash_to_sign\"}" -H "Authorization: Bearer ${AZ_TOKEN}" -H "Content-Type: application/json" | jq -r .value)

signature=$(echo "$signature_base64url" | sed 's/-/+/g; s/_/\//g')
echo $signature | openssl base64 -d > signature.in

set -x
ccf_compatible_signature=$(python3.8 ../python/utils/jws_to_der.py signature.in)



echo $ccf_compatible_signature

# signed_raw=$(echo -n "$string_to_sign" | openssl dgst -sha384 -sign "$privk" | openssl base64 -A)

# echo "Signature: ${signed_raw}"

curl \
-H "Digest: SHA-256=$req_digest" \
-H "Authorization: Signature keyId=\"tls\",algorithm=\"$algorithm\",headers=\"(request-target) digest content-length\",signature=\"$ccf_compatible_signature\"" \
"${additional_curl_args[@]}" \
"$@"