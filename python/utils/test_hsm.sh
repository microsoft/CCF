#!/bin/bash

set -e

rm -f signature.in
rm -f hash_to_sign.in
rm -f signature.in.der

input_to_hash="eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
echo "Input to hash: $input_to_hash"

# No padding needed here as size is right
hash_to_sign=$(echo $input_to_hash | openssl dgst -binary -sha384 | openssl base64)

echo $hash_to_sign

echo $hash_to_sign | openssl base64 -d > hash_to_sign.in

set -x
signature_base64url=$(curl -s -X POST https://demo-vault-ccf.vault.azure.net/keys/key-sign-ccf-pub4/98fa9e4ddbf24b16a6cf3a75bad9b7c0/sign?api-version=7.1 --data "{\"alg\":\"ES384\", \"value\":\"$hash_to_sign\"}" -H "Authorization: Bearer ${AZ_TOKEN}" -H "Content-Type: application/json")

signature=$(echo "$signature_base64url" | sed 's/-/+/g; s/_/\//g')
echo $signature | openssl base64 -d > signature.in

# TODO: Optional -> Self verification
validation_result=$(curl -s -X POST https://demo-vault-ccf.vault.azure.net/keys/key-sign-ccf-pub4/98fa9e4ddbf24b16a6cf3a75bad9b7c0/verify?api-version=7.1 --data "{\"alg\":\"ES384\", \"digest\": \"$hash_to_sign\", \"value\":\"$signature\"}" -H "Authorization: Bearer ${AZ_TOKEN}" -H "Content-Type: application/json" | jq .value)

echo "Self-validation result: $validation_result"

# Verification with openssl

# First, encode the JWS signature to valid DER
python3.8 ../python/utils/jws_to_der.py signature.in

printf "Openssl verification: "
openssl pkeyutl -verify -inkey ./workspace/sandbox_common/member0_privk.pem -sigfile signature.in.der -in hash_to_sign.in