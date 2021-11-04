// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * The `consensus` module provides access to consensus information
 * as observed by the local node. While the information will converge
 * on all nodes in a healthy network, it is either derived from distributed state in BFT,
 * or replicated out by the primary in CFT.
 *
 * @module
 */

import { ccf } from "./global.js";

/**
 * @inheritDoc CCFConsensus.getLastCommittedTxId;
 */
export const getLastCommittedTxId = ccf.consensus.getLastCommittedTxId.bind(
  ccf.consensus
);

/**
 * @inheritDoc CCFConsensus.getStatusForTxId;
 */
export const getStatusForTxId = ccf.consensus.getStatusForTxId.bind(
  ccf.consensus
);

/**
 * @inheritDoc CCFConsensus.getViewForSeqno;
 */
export const getViewForSeqno = ccf.consensus.getViewForSeqno.bind(
  ccf.consensus
);

export { TransactionStatus } from "./global";
