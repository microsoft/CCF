#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

function usage()
{
    echo "Usage:"""
    echo "  $0 https://<node-address> --member-enc-privk /path/to/member_enc_privk.pem --api-version api_version --member-id-privk /path/to/member_id_privk.pem ----member-id-cert /path/to/member_cert.pem [CURL_OPTIONS]"
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

api_version="2024-07-01"
while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        --member-enc-privk)
            member_enc_privk="$2"
            ;;
        --member-id-privk)
            member_id_privk="$2"
            ;;
        --member-id-cert)
            member_id_cert="$2"
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

if [ -z "${member_enc_privk}" ]; then
    echo "Error: No member encryption private key in arguments (--member-enc-privk)"
    exit 1
fi

if [ -z "${member_id_privk}" ]; then
    echo "Error: No member identity private key in arguments (--member-id-privk)"
    exit 1
fi

if [ -z "${member_id_cert}" ]; then
    echo "Error: No member identity cert in arguments (--member-id-cert)"
    exit 1
fi

if [ ! -f "env/bin/activate" ]
    then
        python3 -m venv env
fi
source env/bin/activate
pip install -q ccf

# Compute member ID, as the SHA-256 fingerprint of the signing certificate
member_id=$(openssl x509 -in "$member_id_cert" -noout -fingerprint -sha256 | cut -d "=" -f 2 | sed 's/://g' | awk '{print tolower($0)}')

get_share_path="gov/recovery/encrypted-shares/${member_id}?api-version=${api_version}"
share_field="encryptedShare"
submit_share_path="gov/recovery/members/${member_id}:recover?api-version=${api_version}"

# First, retrieve the encrypted recovery share
encrypted_share=$(curl -sS --fail -X GET "${node_rpc_address}/${get_share_path}" "${@}" | jq -r ".${share_field}")

# Then, decrypt encrypted share with member private key submit decrypted recovery share
# Note: all in one line so that the decrypted recovery share is not exposed
echo "${encrypted_share}" \
    | openssl base64 -d \
    | openssl pkeyutl -inkey "${member_enc_privk}" -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    | openssl base64 -A | jq -c -R '{share: (.)}' \
    | ccf_cose_sign1 --ccf-gov-msg-type recovery_share --ccf-gov-msg-created_at "$(date -uIs)" --signing-key "${member_id_privk}" --signing-cert "${member_id_cert}" --content "-" \
    | curl -i -sS --fail -H "Content-Type: application/cose" -X POST "${node_rpc_address}/${submit_share_path}" "${@}" --data-binary @-