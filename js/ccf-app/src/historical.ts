// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * This module provides access to historical state.
 *
 * There are two options to access historical state:
 *
 * 1. Declare the endpoint mode as `"historical"` in `app.json`
 * and access the Key-Value Store as usual.
 *
 * This option supports single transactions only and prescribes
 * how the transaction ID must be passed in the request (via
 * the `x-ms-ccf-transaction-id` HTTP header).
 * The usual methods to access the Key-Value Store return the
 * historical state here.
 * It is not possible to access the current Key-Value Store state
 * using this option.
 * The {@linkcode historicalState} property provides access to further
 * information like the transaction receipt.
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
 * Compared to option 1, the current Key-Value Store state is always
 * accessible through the usual methods.
 *
 * @module
 */

import { ccf } from "./global.js";

/**
 * @inheritDoc CCF.historicalState
 */
export const historicalState = ccf.historicalState;

/**
 * @inheritDoc CCFHistorical.getStateRange
 */
export const getStateRange = ccf.historical.getStateRange;

/**
 * @inheritDoc CCFHistorical.dropCachedStateRange
 */
export const dropCachedStateRange = ccf.historical.dropCachedStateRange;

export { HistoricalState, Receipt, Proof, ProofElement } from "./global";
