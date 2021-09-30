#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Fetches the Universal Artifact from Azire that was built and published with
# build-v8.sh. Doesn't fetch if the tarball already exists.

SYNTAX="fetch-v8.sh <version (ex. 9.4.146.17)> [-f(orce)]"
if [ "$1" == "" ]; then
  echo "ERROR: Missing expected argument 'version'"
  echo "$SYNTAX"
  exit 1
fi
VERSION="$1"
MAJOR_VERSION=$(echo "$VERSION" | cut -d "." -f 1,2 | sed 's/\.//')
MINOR_VERSION=$(echo "$VERSION" | cut -d "." -f 3,4 | sed 's/\.//')
PKG_VERSION="$MAJOR_VERSION.$MINOR_VERSION"

## Check that the package exists, override with -f
FORCE="$2"
if [ -f v8-$"VERSION".tar.xz ] && [ "$FORCE" != "-f" ]; then
  echo " + Tarball built/fetched already"
  echo "   Use '-f' to force downloading the package again"
  exit 0
fi

## Check for the Azure client
if command -v az > /dev/null; then
  echo " + Azure client already installed"
else
  echo " + Installing the Azure Client..."
  sudo apt update && sudo apt install azure-cli -y
fi

## Login into Azure
if az account list | grep -q MSRC; then
  echo " + Already logged in"
else
  echo " + Login to Azure, follow instructions..."
  az login
fi

## Fetch the file
echo " + Fetch the tarball..."
az artifacts universal download \
  --organization https://dev.azure.com/MSRC-CCF \
  --project CCF \
  --scope project \
  --feed V8 \
  --name v8-monolith \
  --version "$PKG_VERSION.*" \
  --path .

TARBALL="v8-$VERSION.tar.xz"
if [ ! -f "$TARBALL" ]; then
  echo "ERROR: Artifact download failed"
  exit 1
fi

## Unpack on the same directory as it was built
echo " + Unpack the tarball..."
mkdir -p build-v8
tar Jxf v8-"$VERSION".tar.xz -C build-v8
