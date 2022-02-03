#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Fetches the Universal Artifact from Azure that was built and published with
# build.sh. Doesn't fetch if the tarball already exists.

# NB: No way to list available artifacts/versions with the CLI.
# View https://dev.azure.com/MSRC-CCF/CCF/_packaging?_a=feed&feed=V8 for current artifacts.
SYNTAX="fetch.sh <version (ex. 9.4.146.17)> <mode (debug|release)> <target (virtual|sgx)> [-f(orce)]"
if [ "$1" == "" ]; then
  echo "ERROR: Missing expected argument 'version'"
  echo "$SYNTAX"
  exit 1
fi
VERSION="$1"
MAJOR_VERSION=$(echo "$VERSION" | cut -d "." -f 1,2 | sed 's/\.//')
MINOR_VERSION=$(echo "$VERSION" | cut -d "." -f 3,4 | sed 's/\.//')
PKG_VERSION="$MAJOR_VERSION.$MINOR_VERSION"

MODE="$2"
if [ "$MODE" != "debug" ] && [ "$MODE" != "release" ]; then
  echo "ERROR: 'mode' argument must be 'debug' or 'release'"
  echo "$SYNTAX"
  exit 1
fi

TARGET="$3"
if [ "$TARGET" != "virtual" ] && [ "$TARGET" != "sgx" ]; then
  echo "ERROR: 'target' argument must be 'virtual' or 'sgx'"
  echo "$SYNTAX"
  exit 1
fi

BASE_DIR="build-v8"
mkdir -p "$BASE_DIR"
INSTALL_DIR="$BASE_DIR/$MODE-$TARGET"
TARBALL="$BASE_DIR/v8-$VERSION-$MODE-$TARGET.tar.xz"

## Check that the package exists, override with -f
FORCE="$4"
if [ -f "$TARBALL" ] && [ "$FORCE" != "-f" ]; then
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

## Check for the Azure DevOps extension
if az extension show --name azure-devops > /dev/null; then
  echo " + Azure DevOps extension already installed"
else
  echo " + Installing the Azure DevOps extension..."
  az extension add --name azure-devops
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
  --name "v8-monolith-$MODE-$TARGET" \
  --version "$PKG_VERSION.*" \
  --path "$BASE_DIR"

if [ ! -f "$TARBALL" ]; then
  echo "ERROR: Artifact download failed"
  exit 1
fi

## Unpack on the same directory as it was built
echo " + Unpack the tarball..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
tar Jxf "$TARBALL" --strip 1 -C "$INSTALL_DIR"
