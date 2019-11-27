#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  echo "Usage: $0 participant [curve]"
  exit 0
fi

if [ -z "$1" ]; then
    echo "The name of the participant should be specified (e.g. member0 or user1)"
    exit 1
fi

DEFAULT_CURVE="secp384r1"

if [ -z "$2" ]; then
    curve=$DEFAULT_CURVE
else
    curve=$2
fi

cert="$1"_cert.pem
privk="$1"_privk.pem

echo "Key type: $curve"
echo "Generating private key and certificate for participant \"$1\"..."

openssl ecparam -out "$privk" -name "$curve" -genkey
openssl req -new -key "$privk" -x509 -nodes -days 365 -out "$cert" -subj=/CN="$1"

# echo "\0" >> "$cert"

echo "Certificate generated at: $cert (to be registed in CCF)"
echo "Private key generated at: $privk"