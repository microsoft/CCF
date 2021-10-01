// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * TODO change this
 *
 * @module
 */

import { ccf } from "./global.js";

/**
 * @inheritDoc CCF.consensus.getLastCommittedTxId;
 */
export const getLastCommittedTxId = ccf.consensus.getLastCommittedTxId;

/**
 * @inheritDoc CCF.consensus.getStatusForTxId;
 */
export const getStatusForTxId = ccf.consensus.getStatusForTxId;

/**
 * @inheritDoc CCF.consensus.getViewForSeqno;
 */
export const getViewForSeqno = ccf.consensus.getViewForSeqno;

export { TransactionStatus } from "./global";
