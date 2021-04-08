// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * The `openenclave` module provides access to Open Enclave functionality.
 *
 * @module
 */

import { ccf } from "./global";

/**
 * @inheritDoc CCF.verifyOpenEnclaveEvidence
 */
export const verifyOpenEnclaveEvidence = ccf.verifyOpenEnclaveEvidence;

export { EvidenceClaims } from "./global";
