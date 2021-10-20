// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * The `consensus` module provides access to consensus information
 * as observed by the local node. While the information will converge
 * on all nodes in a healthy network, it is derived from distributed
 * state rather than distributed itself.
 *
 * @module
 */

import { ccf } from "./global.js";

/**
 * @inheritDoc CCFConsensus.getLastCommittedTxId;
 */
export const getLastCommittedTxId = ccf.consensus.getLastCommittedTxId;

/**
 * @inheritDoc CCFConsensus.getStatusForTxId;
 */
export const getStatusForTxId = ccf.consensus.getStatusForTxId;

/**
 * @inheritDoc CCFConsensus.getViewForSeqno;
 */
export const getViewForSeqno = ccf.consensus.getViewForSeqno;

export { TransactionStatus } from "./global";
