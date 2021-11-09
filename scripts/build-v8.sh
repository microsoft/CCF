#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

SYNTAX="build-v8.sh <version (ex. 9.4.146.17)> <mode (debug|release)> [publish (true|false)]"
if [ "$1" == "" ]; then
  echo "ERROR: Missing expected argument 'version'"
  echo "$SYNTAX"
  exit 1
fi
VERSION="$1"
MODE="$2"
if [ "$MODE" != "debug" ] && [ "$MODE" != "release" ]; then
  echo "ERROR: 'mode' argument must be 'debug' or 'release'"
  echo "$SYNTAX"
  exit 1
fi
PUBLISH=false
if [ "$3" != "" ]; then
  if [ "$3" == "true" ]; then
    PUBLISH="$3"
  elif [ "$3" != "false" ]; then
    echo "ERROR: Publish can only be 'true' or 'false'"
    echo "$SYNTAX"
    exit 1
  fi
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PATCH_PATH="$THIS_DIR/v8-patches/v8-$VERSION.patch"
if [ ! -f "$PATCH_PATH" ]; then
  echo "ERROR: Missing patch file '$PATCH_PATH'"
  exit 1
fi

echo " + Cleaning up environment..."
rm -rf build-v8/tmp
mkdir build-v8/tmp
# This should never fail but CI lint requires it
cd build-v8/tmp || exit

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

echo " + Apply V8 patches..."
patch -p0 < "$PATCH_PATH"
if [ $? -ne 0 ]; then
  echo "ERROR: Patching V8 failed"
  exit 1
fi

echo " + Build V8 monolith mode..."
# See v8/infra/mb/mb_config.pyl for options.
# is_component_build=false: don't build shared libraries
# v8_monolithic=true: build a single static archive
# v8_use_external_startup_data=false: bundle startup data in the archive
# v8_enable_i18n_support=false & icu_use_data_file=false: disable i18n (ECMA-402) support
# v8_enable_webassembly=false: disable wasm support 
# use_sysroot=false: use system libraries instead of vendored ones
# use_custom_libcxx=false: don't add flags for using V8's custom libc++
#   Note: Flags to use the system libc++ are added through a patch.
# is_clang=true: use V8's Clang (otherwise system gcc)
#   Note: V8 generally relies on features of the Clang version it vendors.
#   This version is typically newer than the one CCF uses. To still be
#   able to link correctly against the V8 static archive, the libc++ version
#   must match the one CCF uses. The work-around for now is to add the
#   corresponding libc++ include path manually through a patch.
#   Normally, `-stdlib=libc++` implies that the libc++ version matches
#   the compiler version. Here, we force an older libc++ version.
#   See also https://libcxx.llvm.org//UsingLibcxx.html#using-a-custom-built-libc.
#   Using an older libc++ essentially determines the libc++ ABI in use.
#   If features of newer C++ versions demand a newer ABI and V8 happens to use
#   those features, then this will break. The likelihood for that is very low,
#   especially considering that CCF also generally stays up-to-date
#   with compiler versions and C++ standards.
#   It is more likely that V8 may use a new API (not ABI) of the C++
#   standard library. This would result in a compiler error since
#   the old header files would not include that feature. Using a newer
#   libc++ version by upgrading to a newer compiler version would fix this.
if [ "$MODE" == "debug" ]; then
  MODE_ARGS="is_debug=true v8_enable_backtrace=true"
elif [ "$MODE" == "release" ]; then
  MODE_ARGS="is_debug=false dcheck_always_on=false"
else
  echo "ERROR: Invalid mode '$MODE'"
  exit 1
fi
OUT_DIR="out.gn/x64.$MODE"
gn gen "$OUT_DIR" --args="$MODE_ARGS v8_monolithic=true is_component_build=false v8_use_external_startup_data=false v8_enable_i18n_support=false icu_use_data_file=false v8_enable_webassembly=false use_sysroot=false use_custom_libcxx=false use_lld=true target_cpu=\"x64\" use_goma=false is_clang=true"
ninja -C "$OUT_DIR" v8_monolith
if [ ! -f "$OUT_DIR/obj/libv8_monolith.a" ]; then
  echo "ERROR: Compilation unsuccessful, bailing out"
  exit 1
fi

echo " + Create install dir..."
INSTALL_DIR="../../$MODE"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/lib"
cp -rv include "$INSTALL_DIR"
cp -v "$OUT_DIR"/obj/libv8_monolith.a "$INSTALL_DIR/lib"
du -sh "$INSTALL_DIR"

# Always test, even when we don't want to publish
echo " + Test install..."
COMPILER=clang++-10
$COMPILER -fuse-ld=lld -stdlib=libc++ "-I$INSTALL_DIR" "-I$INSTALL_DIR/include" samples/process.cc -o process -ldl -lv8_monolith "-L$INSTALL_DIR/lib" -pthread -std=c++14 -DV8_COMPRESS_POINTERS
OUTPUT="$(./process samples/count-hosts.js | grep "yahoo.com: 3")"
if [ "$OUTPUT" == "" ]; then
  echo "ERROR: Process test failed"
  exit 1
fi

echo " + Tests succeeded"

# Only generate tarball if asked to publish
# Creates in .../build-v8/ root
if [ "$PUBLISH" == "true" ]; then
  echo " + Generate the tarball..."
  tar Jcf ../../v8-"$VERSION"-"$MODE".tar.xz "$INSTALL_DIR"
fi
