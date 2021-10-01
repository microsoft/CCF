// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * TODO change this
 *
 * This module provides access to the historical state
 * in historic endpoints, corresponding to a specific transaction.
 *
 * Note that the Key-Value Store also reflects the historic state
 * and can be accessed through the {@linkcode kv} module as usual.
 *
 * @module
 */

import { ccf } from "./global.js";

/**
 * @inheritDoc CCF.historicalState
 */
export const historicalState = ccf.historicalState;

/**
 * @inheritDoc CCF.historical.getStateRange;
 */
export const getStateRange = ccf.historical.getStateRange;

/**
 * @inheritDoc CCF.historical.dropCachedStateRange;
 */
export const dropCachedStateRange = ccf.historical.dropCachedStateRange;

export { HistoricalState, Receipt, Proof, ProofElement } from "./global";
