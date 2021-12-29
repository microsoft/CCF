#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Check https://omahaproxy.appspot.com for known stable versions

SKIP_CLEAN=${SKIP_CLEAN:-0}
VERBOSE=${VERBOSE:-0}
ASAN=${ASAN:-0}

SYNTAX="build.sh <version (ex. 9.4.146.17)> <mode (debug|release)> <target (virtual|sgx)> [publish (true|false)]"
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
TARGET="$3"
if [ "$TARGET" != "virtual" ] && [ "$TARGET" != "sgx" ]; then
  echo "ERROR: 'target' argument must be 'virtual' or 'sgx'"
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
PATCH_PATH="$THIS_DIR/v8-$VERSION.patch"
if [ ! -f "$PATCH_PATH" ]; then
  echo "ERROR: Missing patch file '$PATCH_PATH'"
  exit 1
fi

echo " + Version: $VERSION"
echo " + Mode: $MODE"
echo " + Target: $TARGET"
echo " + Publish: $PUBLISH"

echo " + Cleaning up environment..."
if [ "$SKIP_CLEAN" != "1" ]; then
  rm -rf build-v8/tmp
fi
mkdir -p build-v8/tmp
# This should never fail but CI lint requires it
cd build-v8/tmp || exit

echo " + Checking V8 build dependencies..."
if [ ! -d depot_tools ]; then
  git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
fi
export PATH=$PATH:$PWD/depot_tools
if command -v gn > /dev/null &&
   command -v fetch > /dev/null &&
   command -v gclient > /dev/null; then
  echo "depot_tools installation successful"
else
  echo "ERROR: depot_tools installation unsuccessful"
  exit 1
fi

if [ ! -d v8 ]; then
  echo " + Fetching V8 $VERSION..."
  fetch v8
fi
cd v8 || exit
if ! git checkout "refs/tags/$VERSION"; then
  echo "ERROR: Invalid version $VERSION for checkout"
  exit 1
fi

echo " + Install build dependencies..."
./build/install-build-deps.sh --quick-check --no-arm --no-nacl --syms
gclient sync -D

# To re-create the patch file:
# cd build-v8/tmp/v8
# git diff --no-prefix > $PATCH_PATH
# git -C third_party/zlib diff --no-prefix --src-prefix third_party/zlib/ >> $PATCH_PATH

echo " + Apply V8 patches..."
if ! patch --forward -p0 < "$PATCH_PATH"; then
  if [ "$SKIP_CLEAN" != "1" ]; then
    echo "ERROR: Patching V8 failed"
    exit 1
  fi
fi

echo " + Build V8 monolith library..."
OUT_DIR="out.gn/x64.$MODE.$TARGET"

CCF_CLANG_VERSION=10

# target toolchain
clang_wrapper="$THIS_DIR/clang-wrap.sh"
export CC="$clang_wrapper clang-10"
export CXX="$clang_wrapper clang++-10"
export AR=ar
export NM=nm
echo "CC=$CC"
echo "CXX=$CXX"
echo "AR=$AR"
echo "NM=$NM"
if [ "$TARGET" == "sgx" ]; then
  # -nostdinc causes the compiler include dir to be excluded,
  # but V8 needs it for intrinsics and those headers are not part
  # of Open Enclave. Therefore, add it back manually.
  compiler_include_dir=/usr/lib/llvm-$CCF_CLANG_VERSION/lib/clang/$CCF_CLANG_VERSION.0.0/include
  
  # V8 uses some standard library functions unsupported and marked
  # as deprecated in OE, triggering a warning that fails the build.
  # Those functions are not used in our case, mostly as we run single-threaded.
  # To avoid the build failing, those warnings are silenced.
  # Note that OE does not provide implementations for those functions,
  # so they need to be stubbed out by the consumer of the V8 library.
  oe_ignore_warn="-Wno-deprecated-declarations"

  # Disable a warning about an unused variable
  # in src/base/debug/stack_trace_posix.cc which happens
  # because a guarded block (HAVE_EXECINFO_H) is not used
  # in our case (Open Enclave does not have that header).
  # Apparently this code path is never tested.
  other_ignore_warn="-Wno-unused-const-variable"

  oe_include_dir="/opt/openenclave/include"
  export CFLAGS="$oe_ignore_warn $other_ignore_warn -DV8_OS_OPENENCLAVE=1 -m64 -fPIE -ftls-model=local-exec -fvisibility=hidden -fstack-protector-strong -fno-omit-frame-pointer -ffunction-sections -fdata-sections -mllvm -x86-speculative-load-hardening -nostdinc -isystem $oe_include_dir/openenclave/3rdparty/libc -isystem $oe_include_dir/openenclave/3rdparty -isystem $oe_include_dir -isystem $compiler_include_dir"
  export CXXFLAGS="-isystem $oe_include_dir/openenclave/3rdparty/libcxx $CFLAGS"
elif [  "$TARGET" == "virtual" ]; then
  # Use libc++ to match CCF.
  export CFLAGS="-DV8_OS_OPENENCLAVE=0"
  export CXXFLAGS="$CFLAGS -stdlib=libc++"
else
  echo "ERROR: Invalid target '$TARGET'"
  exit 1
fi

# host toolchain
export BUILD_CC=$CC
export BUILD_CXX=$CXX
export BUILD_AR=$AR
export BUILD_NM=$NM
export BUILD_CFLAGS=""
export BUILD_CXXFLAGS=""

# See v8/infra/mb/mb_config.pyl for options.
# custom_toolchain=".../unbundle:default": use environment variables to configure the target toolchain
#   Note: This is typically used by Linux distributions.
#   Normally, the V8 build uses vendored tools.
#   The available variables are:
#   CC, CXX, AR, NM, CFLAGS, CXXFLAGS, LDFLAGS
#   Note that LDFLAGS is unused since we build statically.
# host_toolchain=".../unbundle:host": use environment variables to configure the host toolchain
#   The host toolchain is used for any build-time tools.
#   The available variables are the same as for custom_toolchain
#   but prefixed with 'BUILD_'.
# v8_snapshot_toolchain=".../unbundle:host": use environment variables to configure the snapshot toolchain
#   For our purposes, identical to host_toolchain.
# v8_enable_snapshot_compression=false: disable snapshot compression to avoid runtime decompression overhead
# v8_os_page_size=4: hardcode the page size to 4K
# target_cpu="x64": build for x64
# is_debug=true: include debug information
# v8_optimized_debug=false: disable compiler optimizations for debug builds
# v8_enable_backtrace=true: enable backtraces (for debugging)
# use_debug_fission=false: don't use split DWARF for debug builds
# dcheck_always_on=false: disable DCHECKs (for release)
# use_rtti=true: enable RTTI (for debug)
#   RTTI is required when ASAN is enabled in V8 itself or
#   the consuming software (CCF). Even if V8 was not built with ASAN
#   enabled it is still desirable to be able to use a single debug build
#   within CCF both with and without ASAN in CCF enabled.
#   Therefore, RTTI is enabled for all debug builds and when
#   explicitly requested for release builds.
#   The main use case is for the daily "Instrumented" CI job in CCF.
# is_component_build=false: don't build shared libraries
# v8_monolithic=true: build a single static archive
# v8_use_external_startup_data=false: bundle startup data in the archive
# v8_enable_i18n_support=false & icu_use_data_file=false: disable i18n (ECMA-402) support
# v8_enable_webassembly=false: disable wasm support
# v8_enable_pointer_compression=false: don't use pointer compression (not compatible with OE/SGX)
# use_lld=false: do not use lld for linking (host tools)
# use_sysroot=false: use system libraries instead of vendored ones
# use_custom_libcxx=false: don't add flags for using V8's custom libc++
#   Note: Flags to use the system libc++ are added through a patch.
# is_clang=true: assume Clang is used (instead of gcc)
#   Note: V8 generally relies on features of the Clang version it vendors.
#   This version is typically newer than the one CCF uses. To still be
#   able to link correctly against the V8 static archive, the libc++ version
#   must match the one CCF uses. See the toolchain flags for how this is done.
#   In practice, it means we use an older libc++ version than V8
#   was intended to be built with, which is typically fine.
#   Using an older libc++ essentially determines the libc++ ABI in use.
#   If features of newer C++ versions demand a newer ABI and V8 happens to use
#   those features, then this will break. The likelihood for that is very low,
#   especially considering that CCF also generally stays up-to-date
#   with compiler versions and C++ standards.
#   It is more likely that V8 may use a new API (not ABI) of the C++
#   standard library. This would result in a compiler error since
#   the old header files would not include that feature. Using a newer
#   libc++ version by upgrading to a newer compiler version would fix this.
# clang_use_chrome_plugins=false: don't use linting plugins for Clang from Chrome
# use_goma=false: don't use Google's internal build infrastructure
if [ "$MODE" == "debug" ]; then
  MODE_ARGS="is_debug=true v8_optimized_debug=false v8_enable_backtrace=true v8_enable_slow_dchecks=true use_debug_fission=false use_rtti=true"
elif [ "$MODE" == "release" ]; then
  MODE_ARGS="is_debug=false dcheck_always_on=false"
else
  echo "ERROR: Invalid mode '$MODE'"
  exit 1
fi

if [ "$ASAN" == "1" ]; then
  if [ "$TARGET" == "sgx" ]; then
    echo "ERROR: ASAN is not supported on sgx"
    exit 1
  fi
  ASAN_ARGS="is_asan=true v8_enable_test_features=true use_rtti=true"
else
  ASAN_ARGS=""
fi

GN_ARGS="\
  $MODE_ARGS \
  $ASAN_ARGS \
  custom_toolchain=\"//build/toolchain/linux/unbundle:default\" \
  host_toolchain=\"//build/toolchain/linux/unbundle:host\" \
  v8_snapshot_toolchain=\"//build/toolchain/linux/unbundle:host\" \
  v8_enable_snapshot_compression=false \
  is_clang=true \
  clang_use_chrome_plugins=false \
  target_cpu=\"x64\" \
  v8_os_page_size=\"4\" \
  use_sysroot=false \
  use_custom_libcxx=false \
  use_glib=false \
  use_lld=false \
  v8_monolithic=true \
  is_component_build=false \
  v8_use_external_startup_data=false \
  v8_enable_i18n_support=false \
  v8_enable_webassembly=false \
  v8_enable_pointer_compression=false \
  use_goma=false \
  "
echo " + gn args: $GN_ARGS"
gn gen "$OUT_DIR" --args="$GN_ARGS"

if [ "$VERBOSE" == 1 ]; then
  verbose_flag="-v"
else
  verbose_flag=""
fi

if ! ninja $verbose_flag -C "$OUT_DIR" v8_monolith; then
  echo "ERROR: Failed to build V8"
  exit 1
fi
if [ ! -f "$OUT_DIR/obj/libv8_monolith.a" ]; then
  echo "ERROR: libv8_monolith.a not found"
  exit 1
fi

echo " + Create install dir..."
INSTALL_DIR="../../$MODE-$TARGET"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/lib"
cp -rv include "$INSTALL_DIR"
cp -v "$OUT_DIR"/obj/libv8_monolith.a "$INSTALL_DIR/lib"
du -sh "$INSTALL_DIR"

# Always test, even when we don't want to publish
if [ "$TARGET" == "virtual" ]; then
  if [ "$ASAN" == "1" ]; then
    echo " + Skipping tests, ASAN=1 not supported..."
  else
    echo " + Test install..."
    # shellcheck disable=SC2086
    $CXX $CXXFLAGS "-I$INSTALL_DIR" "-I$INSTALL_DIR/include" samples/process.cc -o process -ldl -lv8_monolith "-L$INSTALL_DIR/lib" -pthread -std=c++14
    OUTPUT="$(./process samples/count-hosts.js | grep "yahoo.com: 3")"
    if [ "$OUTPUT" == "" ]; then
      echo "ERROR: Process test failed"
      exit 1
    fi
    echo " + Tests succeeded"
  fi
else
  echo " + Skipping tests, target 'sgx' not supported..."
fi

# Only generate tarball if asked to publish
# Creates in .../build-v8/ root
if [ "$PUBLISH" == "true" ]; then
  echo " + Generate the tarball..."
  tar Jcf ../../v8-"$VERSION"-"$MODE"-"$TARGET".tar.xz "$INSTALL_DIR"
fi
