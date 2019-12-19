#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

HACL_STAR_DIRECTORY=$1
CCF_DIST_DIRECTORY="$HACL_STAR_DIRECTORY/dist/ccf"
KREMLIN_DIRECTORY="$HACL_STAR_DIRECTORY/dist/kremlin/include"
KREMLIB_DIRECTORY="$HACL_STAR_DIRECTORY/dist/kremlin/kremlib/dist/minimal"
TARGET=$2

cp -rf "$CCF_DIST_DIRECTORY" "$TARGET"
cp -rf "$KREMLIN_DIRECTORY" "$TARGET"/kremlin
cp -rf "$KREMLIB_DIRECTORY" "$TARGET"/kremlin/kremlib

# Only keep Hacl* source files
rm -f "$TARGET"/{*.[oda],*.asm,Makefile*,*.so}
rm -f "$TARGET"/kremlin/kremlib/{*.[oda],Makefile*}
