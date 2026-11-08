#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e
set -o pipefail

function usage()
{
    echo "Usage:"
    echo "  $0 https://<node-address> --member-enc-privk /path/to/member_enc_privk.pem --api-version api_version --member-id-privk /path/to/member_id_privk.pem --member-id-cert /path/to/member_cert.pem [CURL_OPTIONS]"
    echo "Retrieves the encrypted recovery share for a given member, decrypts the share and submits it for recovery."
    echo "Use --member-did-key <did:key> instead of --member-id-cert for certificate-free members."
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
identity_id_format="sha256"
identity_args=()
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
        --member-did-key)
            member_did_key="$2"
            ;;
        --api-version)
            api_version="$2"
            ;;
        --identity-id-format)
            identity_id_format="$2"
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

if [ -z "${member_id_cert}" ] && [ -z "${member_did_key}" ]; then
    echo "Error: Specify --member-id-cert or --member-did-key"
    exit 1
fi
if [ -n "${member_id_cert}" ] && [ -n "${member_did_key}" ]; then
    echo "Error: --member-id-cert and --member-did-key are mutually exclusive"
    exit 1
fi

if ! command -v ccf_cose_sign1 > /dev/null; then
    echo "Error: This script requires the ccf_cose_sign1 CLI tool, distributed as part of the CCF Python package. Please install it via 'pip install ccf' in the current Python environment"
    exit 1
fi

if [ -n "$member_did_key" ]; then
    member_id="$member_did_key"
    identity_args=(--signing-did-key "$member_did_key")
elif [ "$identity_id_format" = "sha256" ]; then
    member_id=$(openssl x509 -in "$member_id_cert" -noout -fingerprint -sha256 | cut -d "=" -f 2 | sed 's/://g' | awk '{print tolower($0)}')
    identity_args=(--signing-cert "$member_id_cert")
elif [ "$identity_id_format" = "did:key" ]; then
    member_id=$(python3 -m ccf.identity --cert "$member_id_cert" --id-format "$identity_id_format")
    identity_args=(--signing-did-key "$member_id")
else
    echo "Error: Unsupported identity ID format: $identity_id_format" >&2
    exit 1
fi

url_member_id="${member_id//:/%3A}"
get_share_path="gov/recovery/encrypted-shares/${url_member_id}?api-version=${api_version}"
share_field="encryptedShare"
submit_share_path="gov/recovery/members/${url_member_id}:recover?api-version=${api_version}"

# First, retrieve the encrypted recovery share
encrypted_share=$(curl -sS --fail -X GET "${node_rpc_address}/${get_share_path}" "${@}" | jq -r ".${share_field}")

# Then, decrypt encrypted share with member private key submit decrypted recovery share
# Note: all in one line so that the decrypted recovery share is not exposed
echo "${encrypted_share}" \
    | openssl base64 -d \
    | openssl pkeyutl -inkey "${member_enc_privk}" -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    | openssl base64 -A | jq -c -R '{share: (.)}' \
    | ccf_cose_sign1 "${identity_args[@]}" --ccf-gov-msg-type recovery_share --ccf-gov-msg-created_at "$(date -uIs)" --signing-key "${member_id_privk}" --content "-" \
    | curl -i -sS --fail -H "Content-Type: application/cose" -X POST "${node_rpc_address}/${submit_share_path}" "${@}" --data-binary @-