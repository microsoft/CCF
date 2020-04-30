#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

# TODO:
# 1. No need to base64 encode the share: hex encoding is fine


# 1. Retrieve encrypted share
encrypted_share=`curl -sS https://127.208.217.117:59615/members/getEncryptedRecoveryShare --cacert networkcert.pem --cert member0_cert.pem --key member0_privk.pem | jq -r .encrypted_recovery_share`

nonce=`curl -sS https://127.208.217.117:59615/members/getEncryptedRecoveryShare --cacert networkcert.pem --cert member0_cert.pem --key member0_privk.pem | jq -r .nonce`

# 2. Decrypt encrypted share

# i. Retrieve raw member encryption key
# openssl asn1parse -in member0_enc_priv.pem -i -strparse 12 -out key.raw -noout
# member_raw_private_key=`cat key.raw | od -tx1 -An | tr -d '[\n/ ]' | cut -c 5-`
# echo -n -e "{$member_raw_private_key}" > member0_privk.raw

# TODO: This does not seem right...
# ii. Retrieve raw network encryption key
openssl asn1parse -in network_enc_pubk.pem -i -strparse 9 -out key2.raw -noout
# network_raw_public_key=`cat key2.raw | od -tx1 -An | tr -d '[\n/ ]'`
# echo -n -e "${network_raw_public_key}" > network_pubk.raw

# iii. decrypt it
echo "About to attempt decryption..."
echo "Encrypted share: ${encrypted_share}"
echo "Nonce: ${nonce}"
echo "Private key: ${member_raw_private_key}"
echo "Public key:  ${network_raw_public_key}"
raw_nonce=`echo ${nonce} | openssl base64 -d`
raw_input=`echo ${encrypted_share} | openssl base64 -d`
echo "${raw_input}" | step crypto nacl box open "${raw_nonce}" key2.raw key.raw -raw

# 3. Submit encrypted share

