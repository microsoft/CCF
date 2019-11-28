#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

DEFAULT_TYPE="ec"
EDWARDS_TYPE="ed"

DEFAULT_CURVE="secp384r1"

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  echo "Generates private key and self-signed certificates for CCF participants."
  echo "Usage:"""
  echo "  $0 participant [curve=$DEFAULT_CURVE]"
  exit 0
fi

if [ -z "$1" ]; then
    echo "The name of the participant should be specified (e.g. member0 or user1)"
    exit 1
fi

curve=${2:-$DEFAULT_CURVE}

# Because openssl CLI interface for generating EC and Ed keys is different,
# detect which interface to use based on first letter of the specified curve
if [[ "$curve" == ${EDWARDS_TYPE}* ]]; then
    type=$EDWARDS_TYPE
else
    type=$DEFAULT_TYPE
fi

cert="$1"_cert.pem
privk="$1"_privk.pem

echo "Curve type: $type"
echo "Curve: $curve"
echo "Generating private key and certificate for participant \"$1\"..."

if [ "$type" == $DEFAULT_TYPE ]; then
    openssl ecparam -out "$privk" -name "$curve" -genkey
elif [ "$type" == $EDWARDS_TYPE ]; then
    openssl genpkey -out "$privk" -algorithm "$curve"
else
    echo "Curve type $type not supported"
    exit 1
fi

openssl req -new -key "$privk" -x509 -nodes -days 365 -out "$cert" -subj=/CN="$1"

echo "Certificate generated at: $cert (to be registed in CCF)"
echo "Private key generated at: $privk"