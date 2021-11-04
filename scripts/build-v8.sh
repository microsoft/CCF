#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

SYNTAX="build-v8.sh <version (ex. 9.4.146.17)> [publish (true|false)]"
if [ "$1" == "" ]; then
  echo "ERROR: Missing expected argument 'version'"
  echo "$SYNTAX"
  exit 1
fi
VERSION="$1"
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
# Check omahaproxy.appspot.com for known stable versions
git checkout "refs/tags/$VERSION"
if [ $? -ne 0 ]; then
  echo "ERROR: Invalid version $VERSION for checkout"
  exit 1
fi

echo " + Install build dependencies..."
./build/install-build-deps.sh --quick-check --no-arm --no-nacl --syms
gclient sync -D

# echo " + Apply V8 patches..."
# this_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# patch -p0 < "$this_dir"/v8.patch
# if [ $? -ne 0 ]; then
#   echo "ERROR: Patching V8 failed"
#   exit 1
# fi

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
INSTALL_DIR="../install"
mkdir -p $INSTALL_DIR/lib
cp -rv include $INSTALL_DIR
cp -v "$OUT_DIR"/icudtl.dat $INSTALL_DIR/lib
cp -v "$OUT_DIR"/obj/libv8_monolith.a $INSTALL_DIR/lib
cp -rv "$OUT_DIR"/obj/third_party/icu/*.a $INSTALL_DIR/lib
du -sh $INSTALL_DIR

# Always test, even when we don't want to publish
echo " + Test install..."
COMPILER=third_party/llvm-build/Release+Asserts/bin/clang++
$COMPILER -fuse-ld=lld -stdlib=libc++ -I$INSTALL_DIR -I$INSTALL_DIR/include samples/hello-world.cc -o hello_world -ldl -lv8_monolith -L$INSTALL_DIR/lib -pthread -std=c++14 -DV8_COMPRESS_POINTERS
OUTPUT="$(./hello_world | grep "3 + 4 = 7")"
if [ "$OUTPUT" == "" ]; then
  echo "ERROR: Hello World test failed"
  exit 1
fi

$COMPILER -fuse-ld=lld -stdlib=libc++ -I$INSTALL_DIR -I$INSTALL_DIR/include samples/process.cc -o process -ldl -lv8_monolith -L$INSTALL_DIR/lib -pthread -std=c++14 -DV8_COMPRESS_POINTERS
OUTPUT="$(./process samples/count-hosts.js | grep "yahoo.com: 3")"
if [ "$OUTPUT" == "" ]; then
  echo "ERROR: Process test failed"
  exit 1
fi

# Only generate tarball if asked to publish
# Creates in .../build-v8/ root
if [ "$PUBLISH" == "true" ]; then
  echo " + Generate the tarball..."
  tar Jcf ../v8-"$VERSION".tar.xz $INSTALL_DIR
fi
