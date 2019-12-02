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

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  echo "Generates private key and self-signed certificates for CCF participants."
  echo "Usage:"""
  echo "  $0 participant [curve=$DEFAULT_CURVE]"
  echo ""
  echo "Supported curves are: $SUPPORTED_CURVES"
  exit 0
fi

if [ -z "$1" ]; then
    echo "The name of the participant should be specified (e.g. member0 or user1)"
    exit 1
fi

curve=${2:-$DEFAULT_CURVE}

if ! [[ "$curve" =~ ^($SUPPORTED_CURVES)$ ]]; then
    echo "$curve curve is not in $SUPPORTED_CURVES"
    exit 1
fi

if [ "$curve" == "$DEFAULT_CURVE" ]; then
    digest="$DIGEST_SHA384"
elif [ "$curve" ==  "$EDWARDS_CURVE" ]; then
    digest="$DIGEST_SHA512"
else
    digest="$DIGEST_SHA256"
fi

cert="$1"_cert.pem
privk="$1"_privk.pem

echo "Curve: $curve"
echo "Generating private key and certificate for participant \"$1\"..."

# Because openssl CLI interface for ec key differs from Ed, detect which
# interface to use based on first letters of the specified curve
if ! [ "$curve" == $EDWARDS_CURVE ]; then
    openssl ecparam -out "$privk" -name "$curve" -genkey
else
    openssl genpkey -out "$privk" -algorithm "$curve"
fi

openssl req -new -key "$privk" -x509 -nodes -days 365 -out "$cert" -"$digest" -subj=/CN="$1"

echo "Certificate generated at: $cert (to be registered in CCF)"
echo "Private key generated at: $privk"