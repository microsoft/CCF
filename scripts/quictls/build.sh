#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Check https://github.com/quictls/openssl for known stable versions

SKIP_CLEAN=${SKIP_CLEAN:-0}
VERBOSE=${VERBOSE:-0}
ASAN=${ASAN:-0}

SYNTAX="build.sh <version (ex. 1.1.1)> <revision (ex. i, j, k)> <mode (debug|release)> [publish (true|false)]"
if [ "$1" == "" ]; then
  echo "ERROR: Missing expected argument 'version'"
  echo "$SYNTAX"
  exit 1
fi
VERSION="$1"
REV="$2"
MODE="$3"
if [ "$MODE" != "debug" ] && [ "$MODE" != "release" ]; then
  echo "ERROR: 'mode' argument must be 'debug' or 'release'"
  echo "$SYNTAX"
  exit 1
fi
PUBLISH=false
if [ "$4" != "" ]; then
  # uppercase to support Azure Pipelines booleans
  if [ "$4" == "true" ] || [ "$4" == "True" ]; then
    PUBLISH="true"
  elif [ "$4" != "false" ] && [ "$4" != "False" ]; then
    echo "ERROR: Publish can only be 'true' or 'false', got: $4"
    echo "$SYNTAX"
    exit 1
  fi
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="$THIS_DIR/build-quictls"
INSTALL_DIR="install-quictls"
PREFIX="$THIS_DIR/$INSTALL_DIR"
SRC_TARBALL="$BUILD_DIR/openssl-$VERSION$REV.tgz"
PKG_TARBALL="$THIS_DIR/quictls-$VERSION$REV-$MODE.tar.xz"
BRANCH="OpenSSL_${VERSION//./_}$REV+quic"
SRC_DIR="src"

echo " + Version: $VERSION"
echo " + Revision: $REV"
echo " + Mode: $MODE"
echo " + Publish: $PUBLISH"
echo " + Source Tarball: $SRC_TARBALL"
echo " + Package Tarball: $PKG_TARBALL"
echo " + Branch: $BRANCH"

echo " + Installing dependencies"
sudo apt install -y clang

echo " + Cleaning up environment..."
if [ "$SKIP_CLEAN" != "1" ]; then
  rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"
# This should never fail but CI lint requires it
cd "$BUILD_DIR" || exit

if [ ! -f "$SRC_TARBALL" ]; then
  echo " + Fetch the branch"
  wget -O "$SRC_TARBALL" https://github.com/quictls/openssl/tarball/"$BRANCH"
fi

echo " + Prepare the source dir"
# This is quictls-openssl-hash (which changes depending on the ver/rev)
# Make sure we clean all past directories, if any
rm -rf quictls-openssl-*
tar xf "$SRC_TARBALL"
TEMP_DIR=$(find . -name "quictls-openssl-*")
mv "$TEMP_DIR" "$SRC_DIR"

echo " + Configure"
cd "$SRC_DIR" || exit
./Configure no-dso no-shared no-ui-console no-afalgeng \
            no-stdio no-posix-io no-threads no-tests \
            linux-x86_64-clang \
            --prefix="$PREFIX"

echo " + Make"
make -j "$(nproc)"
make install_sw

# Only generate tarball if asked to publish
# Creates in .../$BUILD_DIR/ root
if [ "$PUBLISH" == "true" ]; then
  echo " + Generate the tarball..."
  # Make sure we're one dir down
  cd "$PREFIX"/.. || exit
  rm -f "$PKG_TARBALL"
  tar Jcf "$PKG_TARBALL" "$INSTALL_DIR"
fi
