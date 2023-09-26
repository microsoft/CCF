#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

function usage()
{
    echo "Usage:"""
    echo "  $0 https://<node-address> --member-enc-privk /path/to/member_enc_privk.pem --api-version api_version --cert /path/to/member_cert.pem [CURL_OPTIONS]"
    echo "Retrieves the encrypted recovery share for a given member, decrypts the share and submits it for recovery."
    echo ""
    echo "A sufficient number of recovery shares must be submitted by members to initiate the end of recovery procedure."
}

if [[ "$1" =~ ^(-h|-\?|--help)$ ]]; then
    usage
    exit 0
fi

if [ -z "$1" ]; then
    echo "Error: First argument should be CCF node address, e.g.: https://127.0.0.1:8000"
    exit 1
fi
node_rpc_address=$1
shift

api_version="classic"
while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        --member-enc-privk)
            member_enc_privk="$2"
            ;;
        --api-version)
            api_version="$2"
            ;;
        *)
            break
    esac
    shift
    shift
done

# Loop through all arguments and find cert
next_is_cert=false

for item in "$@" ; do
    if [ "$next_is_cert" == true ]; then
        cert=$item
        next_is_cert=false
    fi
    if [ "$item" == "--cert" ]; then
        next_is_cert=true
    fi
done

if [ -z "${member_enc_privk}" ]; then
    echo "Error: No member encryption private key in arguments (--member-enc-privk)"
    exit 1
fi

if [ -z "${cert}" ]; then
    echo "Error: No user certificate in arguments (--cert)"
    exit 1
fi

# Compute member ID, as the SHA-256 fingerprint of the signing certificate
member_id=$(openssl x509 -in "$cert" -noout -fingerprint -sha256 | cut -d "=" -f 2 | sed 's/://g' | awk '{print tolower($0)}')

if [ "${api_version}" == "classic" ]; then
    get_share_path="gov/encrypted_recovery_share/${member_id}"
    share_field="encrypted_share"
    submit_share_path="gov/recovery_share"
else
    get_share_path="gov/recovery/encrypted-shares/${member_id}?api-version=${api_version}"
    share_field="encryptedShare"
    submit_share_path="gov/recovery/members/${member_id}:recover?api-version=${api_version}"
fi

# First, retrieve the encrypted recovery share
encrypted_share=$(curl -sS --fail -X GET "${node_rpc_address}/${get_share_path}" "${@}" | jq -r ".${share_field}")

# Then, decrypt encrypted share with member private key submit decrypted recovery share
# Note: all in one line so that the decrypted recovery share is not exposed
echo "${encrypted_share}" \
    | openssl base64 -d \
    | openssl pkeyutl -inkey "${member_enc_privk}" -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    | openssl base64 -A | jq -R '{share: (.)}' \
    | curl -i -sS --fail -H "Content-Type: application/json" -X POST "${node_rpc_address}/${submit_share_path}" "${@}" -d @-