#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

BIN_PATH="${1:-}" # allow passing explicit path to snp_canary binary
if [ -z "$BIN_PATH" ]; then
	# fallback: assume binary is in current working directory
	BIN_PATH="./snp_canary"
fi

if [ ! -x "$BIN_PATH" ]; then
	echo "Error: snp_canary binary not found or not executable at $BIN_PATH" >&2
	exit 1
fi

SECURITY_CONTEXT_DIR=$(echo /security-context-*)

HOST_AMD="${SECURITY_CONTEXT_DIR}/host-amd-cert-base64"
REF_INFO="${SECURITY_CONTEXT_DIR}/reference-info-base64"
SEC_POLICY="${SECURITY_CONTEXT_DIR}/security-policy-base64"

exec "$BIN_PATH" "$HOST_AMD" "$REF_INFO" "$SEC_POLICY"