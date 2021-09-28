#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

SYNTAX="build-v8.sh <version (ex. 9.4.146.17)> [publish (true|false)]"
if [ "$1" == "" ]; then
  echo "ERROR: Missing expected argument 'version'"
  echo "$SYNTAX"
  exit 1
fi
EXPECTED_VERSION="$1"
MAJOR_VERSION="${1%.*.*}"
PUBLISH=false
if [ "$2" != "" ]; then
  if [ "$2" == "true" ]; then
    PUBLISH="$2"
  elif [ "$2" != "false" ]; then
    echo "ERROR: Publish can only be 'true' or 'false'"
    echo "$SYNTAX"
    exit 1
  fi
fi

echo " + Cleaning up environment..."
rm -rf build-v8
mkdir build-v8
# This should never fail but CI lint requires it
cd build-v8 || exit

echo " + Checking V8 build dependencies..."
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH=$PATH:$PWD/depot_tools
if command -v gn > /dev/null &&
   command -v fetch > /dev/null &&
   command -v gclient > /dev/null; then
  echo "depot_tools installation successful"
else
  echo "ERROR: depot_tools installation unsuccessful"
  exit 1
fi

echo " + Fetching V8 on known stable branch..."
fetch v8
cd v8 || exit
# This is known stable on all platforms according to omahaproxy.appspot.com
CHECKOUT_BANCH="branch-heads/$MAJOR_VERSION"
git checkout "$CHECKOUT_BANCH"
VERSION=$(git show | grep -o "$EXPECTED_VERSION")
if [ "$VERSION" != "$EXPECTED_VERSION" ]; then
  echo "ERROR: Invalid version $VERSION for checkout $CHECKOUT_BANCH"
  exit 1
fi

echo " + Install build dependencies..."
./build/install-build-deps.sh --quick-check --no-arm --no-nacl --syms
gclient sync -D

echo " + Build V8 monolith mode..."
# This is a mash of options from v8/infra/mb/mb_config.pyl
OUT_DIR="out.gn/x64.debug"
gn gen "$OUT_DIR" --args='v8_monolithic=true is_component_build=false v8_use_external_startup_data=false use_custom_libcxx=false is_debug=true v8_enable_backtrace=true use_lld=true target_cpu="x64" use_goma=false'
ninja -C "$OUT_DIR" v8_monolith
if [ ! -f "$OUT_DIR/obj/libv8_monolith.a" ]; then
  echo "ERROR: Compilation unsuccessful, bailing out"
  exit 1
fi

echo " + Create install dir..."
mkdir -p install/lib
cp -rv include install
cp -v "$OUT_DIR"/icudtl.dat install/lib
cp -rv "$OUT_DIR"/obj/*.a install/lib
cp -rv "$OUT_DIR"/obj/third_party/icu/*.a install/lib
du -sh install

# Always test, even when we don't want to publish
echo " + Test install..."
COMPILER=third_party/llvm-build/Release+Asserts/bin/clang++
$COMPILER -fuse-ld=lld -Iinstall -Iinstall/include samples/hello-world.cc -o hello_world -ldl -lv8_monolith -Linstall/lib -pthread -std=c++14 -DV8_COMPRESS_POINTERS
OUTPUT="$(./hello_world | grep "3 + 4 = 7")"
if [ "$OUTPUT" == "" ]; then
  echo "ERROR: Hello World test failed"
  exit 1
fi

$COMPILER -fuse-ld=lld -Iinstall -Iinstall/include samples/process.cc -o process -ldl -lv8_monolith -Linstall/lib -pthread -std=c++14 -DV8_COMPRESS_POINTERS
OUTPUT="$(./process samples/count-hosts.js | grep "yahoo.com: 3")"
if [ "$OUTPUT" == "" ]; then
  echo "ERROR: Process test failed"
  exit 1
fi

# Only generate tarball if asked to publish
# Creates in .../build-v8/ root
if [ "$PUBLISH" == "true" ]; then
  echo " + Generate the tarball..."
  tar Jcf ../v8.tar.xz install
fi
