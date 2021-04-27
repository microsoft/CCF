// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * The `openenclave` module provides access to Open Enclave functionality.
 *
 * @module
 */

import { openenclave } from "./global";

/**
 * @inheritDoc OpenEnclave.verifyOpenEnclaveEvidence
 */
export const verifyOpenEnclaveEvidence = openenclave.verifyOpenEnclaveEvidence;

export { EvidenceClaims } from "./global";
