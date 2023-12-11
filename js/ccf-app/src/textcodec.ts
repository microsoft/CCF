// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * The `textcodec` module provides access to TextEncoder Web API class.
 *
 * Example:
 * ```
 * import * as ccftextcodec from '@microsoft/ccf-app/textcodec.js';
 *
 * const bytes = new ccftextcodec.TextEncoder().encode("foo")
 * ```
 *
 * If you need TextEncoder Web API as a globally accessible class:
 * ```
 * import * as ccftextcodec from '@microsoft/ccf-app/textcodec.js';
 *
 * if (globalThis != undefined && (globalThis as any).TextEncoder == undefined) {
 *   (globalThis as any).TextEncoder = ccftextcodec.TextEncoder;
 * }
 *
 * ```
 *
 * @module
 */

import { ccf } from "./global.js";

export type TextEncoderEncodeIntoResult = {
  read?: number;
  written?: number;
};

/**
 * TextEncoder can be used to encode string to Uint8Array.
 */
export class TextEncoder {
  /**
   * Always returns "utf-8".
   */
  public readonly encoding: string = "utf-8";

  /**
   * Returns Uint8Array containing UTF-8 encoded text.
   * @param input Input string to encode.
   * @returns Encoded bytes.
   */
  encode(input: string): Uint8Array {
    return new Uint8Array(ccf.strToBuf(input));
  }

  /**
   * Not implemented.
   * @param input
   * @param output
   * @throws Always throws an Error object.
   */
  encodeInto(input: string, output: Uint8Array): TextEncoderEncodeIntoResult {
    throw new Error("Not implemented");
  }
}
