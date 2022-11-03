// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * This module provides access to historical state.
 *
 * There are two options to access historical state:
 *
 * 1. Declare the endpoint mode as `"historical"` in `app.json`
 * and access historical state via `ccf.historicalState`.
 *
 * This option supports single transactions only and prescribes
 * how the transaction ID must be passed in the request (via
 * the `x-ms-ccf-transaction-id` HTTP header).
 * The {@linkcode historicalState} property provides access to
 * the historical state of the Key-Value store and information
 * like the transaction receipt.
 *
 * 2. Declare the endpoint mode as `"readonly"` in `app.json` and use
 * the programmatic API to request historical state.
 *
 * This option supports both single and multi-transaction requests.
 * It also leaves the decision of how to extract the transaction ID(s)
 * from the HTTP request to the app developer.
 * The {@linkcode getStateRange} function of this module
 * provides access to a sequential range of transactions.
 * See the documentation of that function for more details.
 *
 * @module
 */

import { ccf } from "./global.js";

/**
 * @inheritDoc global!CCF.historicalState
 */
export const historicalState = ccf.historicalState;

/**
 * @inheritDoc global!CCFHistorical.getStateRange
 */
export const getStateRange = ccf.historical.getStateRange.bind(ccf.historical);

/**
 * @inheritDoc global!CCFHistorical.dropCachedStates
 */
export const dropCachedStates = ccf.historical.dropCachedStates.bind(
  ccf.historical
);

export { HistoricalState, Receipt, Proof, ProofElement } from "./global";
