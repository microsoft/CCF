#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

DEFAULT_CURVE="secp384r1"
EDWARDS_CURVE="ed25519"
FAST_CURVE="secp256k1"
SUPPORTED_CURVES="$DEFAULT_CURVE|$EDWARDS_CURVE|$FAST_CURVE"

DIGEST_SHA384="sha384"
DIGEST_SHA256="sha256"
DIGEST_SHA512="sha512"

curve=$DEFAULT_CURVE
name=""
generate_encryption_key=false

function usage()
{
    echo "Generates identity private key and self-signed certificates for CCF participants."
    echo "Optionally generates a ed25519 key pair for share encryption (required for consortium members)."
    echo "Usage:"""
    echo "  $0 --name=participant_name [--curve=$DEFAULT_CURVE] [--gen-key-share]"
    echo ""
    echo "Supported curves are: $SUPPORTED_CURVES"
}

while [ "$1" != "" ]; do
    PARAM=${1%=*}
    VALUE=${1#*=}
    case $PARAM in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        -n|--name)
            name="$VALUE"
            ;;
        -c|--curve)
            curve="$VALUE"
            ;;
        -g|--gen-key-share)
            generate_encryption_key=true
            ;;
        *)
            break
    esac
    shift
done

# Validate parameters
if [ -z "$name" ]; then
    echo "The name of the participant should be specified (e.g. member0 or user1)"
    exit 1
fi

if ! [[ "$curve" =~ ^($SUPPORTED_CURVES)$ ]]; then
    echo "$curve curve is not in $SUPPORTED_CURVES"
    exit 1
fi

if [ "$curve" == "$DEFAULT_CURVE" ]; then
    digest="$DIGEST_SHA384"
elif [ "$curve" == "$EDWARDS_CURVE" ]; then
    digest="$DIGEST_SHA512"
else
    digest="$DIGEST_SHA256"
fi

cert="$name"_cert.pem
privk="$name"_privk.pem

echo "-- Generating identity private key and certificate for participant \"$name\"..."
echo "Identity curve: $curve"

# Because openssl CLI interface for ec key differs from Ed, detect which
# interface to use based on first letters of the specified curve
if ! [ "$curve" == $EDWARDS_CURVE ]; then
    openssl ecparam -out "$privk" -name "$curve" -genkey
else
    openssl genpkey -out "$privk" -algorithm "$curve"
fi

openssl req -new -key "$privk" -x509 -nodes -days 365 -out "$cert" -"$digest" -subj=/CN="$name"

echo "Identity certificate generated at:   $cert (to be registered in CCF)"
echo "Identity private key generated at:   $privk"

if "$generate_encryption_key"; then
    echo "-- Generating key share pair for participant \"$name\"..."

    keyshare_priv="$name"_kshare_priv.pem
    keyshare_pub="$name"_kshare_pub.pem

    openssl genpkey -out "$keyshare_priv" -algorithm "$EDWARDS_CURVE"
    openssl pkey -in "$keyshare_priv" -pubout -out "$keyshare_pub"

    echo "Key share public key generated at:   $keyshare_pub (to be registered in CCF)"
    echo "Key share private key generated at:  $keyshare_priv"
fi
