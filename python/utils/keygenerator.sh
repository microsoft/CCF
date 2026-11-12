#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

DEFAULT_CURVE="secp384r1"
FAST_CURVE="secp256r1"
SUPPORTED_CURVES="$DEFAULT_CURVE|$FAST_CURVE"

DIGEST_SHA384="sha384"
DIGEST_SHA256="sha256"

RSA_SIZE=2048

curve=$DEFAULT_CURVE
name=""
generate_encryption_key=false
public_key_only=false

function usage()
{
    echo "Usage:"
    echo "  $0 --name participant_name [--curve $DEFAULT_CURVE] [--gen-enc-key] [--public-key-only]"
    echo "Generates identity private key and self-signed certificates for CCF participants."
    echo "Optionally generates a RSA key pair for recovery share encryption (optionally for consortium members only)."
    echo "Use --public-key-only for did:key identities: generates a public key instead of a certificate."
    echo ""
    echo "Supported curves are: $SUPPORTED_CURVES"
}

while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        -n|--name)
            name="$2"
            shift
            ;;
        -c|--curve)
            curve="$2"
            shift
            ;;
        -g|--gen-enc-key)
            generate_encryption_key=true
            ;;
        --public-key-only)
            public_key_only=true
            ;;
        *)
            break
    esac
    shift
done

# Validate parameters
if [ -z "$name" ]; then
    echo "Error: The name of the participant should be specified (e.g. member0 or user1)"
    exit 1
fi

if ! [[ "$curve" =~ ^($SUPPORTED_CURVES)$ ]]; then
    echo "$curve curve is not in $SUPPORTED_CURVES"
    exit 1
fi

if [ "$curve" == "$DEFAULT_CURVE" ]; then
    digest="$DIGEST_SHA384"
else
    digest="$DIGEST_SHA256"
fi

cert="$name"_cert.pem
privk="$name"_privk.pem

echo "-- Generating identity key pair for participant \"$name\"..."
echo "Identity curve: $curve"


openssl ecparam -out "$privk" -name "$curve" -genkey
if "$public_key_only"; then
    pubk="$name"_pubk.pem
    openssl pkey -in "$privk" -pubout -out "$pubk"
else
    openssl req -new -key "$privk" -x509 -nodes -days 365 -out "$cert" -"$digest" -subj=/CN="$name"
fi

echo "Identity private key generated at:   $privk"
if "$public_key_only"; then
    echo "Identity public key generated at:    $pubk (encode as did:key for enrollment)"
else
    echo "Identity certificate generated at:   $cert (to be registered in CCF)"
fi

if "$generate_encryption_key"; then
    echo "-- Generating RSA encryption key pair for participant \"$name\"..."

    enc_priv="$name"_enc_privk.pem
    enc_pub="$name"_enc_pubk.pem

    openssl genrsa -out "$enc_priv" "$RSA_SIZE"
    openssl rsa -in "$enc_priv" -pubout -out "$enc_pub"

    echo "Encryption private key generated at:  $enc_priv"
    echo "Encryption public key generated at:   $enc_pub (to be registered in CCF)"
fi