#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

function usage()
{
    echo "Usage:"""
    echo "  $0 https://<node-address> "
    echo "    --member-enc-privk /path/to/member_enc_privk.pem"
    echo "    --cert /path/to/member_cert.pem"
    echo "    --key /path/to/member_key.pem"
    echo "    [CURL_OPTIONS]"
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

while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        --member-enc-privk)
            member_enc_privk="$2"
            ;;
        --cert)
            member_cert="$2"
            ;;
        --key)
            member_key="$2"
            ;;
        *)
            break
    esac
    shift
    shift
done

if [ -z "${member_enc_privk}" ]; then
    echo "Error: No member encryption private key in arguments (--member-enc-privk)"
    exit 1
fi

if [ -z "${member_cert}" ]; then
    echo "Error: No member cert in arguments (--cert)"
    exit 1
fi

if [ -z "${member_key}" ]; then
    echo "Error: No member key in arguments (--key)"
    exit 1
fi

member_id=$(openssl x509 -in "${member_cert}" -noout -fingerprint -sha256 | cut -d "=" -f 2 | sed 's/://g' | awk '{print tolower($0)}')

# First, retrieve the encrypted recovery share
encrypted_share=$(curl -sS --fail -X GET "${node_rpc_address}"/gov/recovery_share/"${member_id}" "${@}" | jq -r '.encrypted_share')

# Then, decrypt encrypted share with member private key submit decrypted recovery share
# Note: all in one line so that the decrypted recovery share is not exposed
echo "${encrypted_share}" \
    | openssl base64 -d \
    | openssl pkeyutl -inkey "${member_enc_privk}" -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    | openssl base64 -A \
    | jq -R '{share: (.)}' \
    | ccf_cose_sign1 --content - --signing-cert "${member_cert}" --signing-key "${member_key}" \
        --ccf-gov-msg-type recovery_share --ccf-gov-msg-created_at "$(date -Is)" \
    | curl -i -sS --fail -X POST "${node_rpc_address}"/gov/recovery_share/"${member_id}" -H 'Content-Type: application/cose' "$@" --data-binary @-
