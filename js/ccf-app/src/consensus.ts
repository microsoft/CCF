// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * The `consensus` module provides access to consensus information
 * as observed by the local node.
 *
 * @module
 */

import { ccf } from "./global.js";

/**
 * @inheritDoc global!CCFConsensus.getLastCommittedTxId
 */
export const getLastCommittedTxId = ccf.consensus.getLastCommittedTxId.bind(
  ccf.consensus
);

/**
 * @inheritDoc global!CCFConsensus.getStatusForTxId
 */
export const getStatusForTxId = ccf.consensus.getStatusForTxId.bind(
  ccf.consensus
);

/**
 * @inheritDoc global!CCFConsensus.getViewForSeqno
 */
export const getViewForSeqno = ccf.consensus.getViewForSeqno.bind(
  ccf.consensus
);

export { TransactionStatus } from "./global";
