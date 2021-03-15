// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// The global ccf variable and associated types are exported
// as a regular module instead of using an ambient namespace
// in a .d.ts definition file.
// This avoids polluting the global namespace and helps with
// writing shims for tests outside of the CCF environment.

export const ccf: CCF = globalThis.ccf;

// This should eventually cover all JSON-compatible values.
// There are attempts at https://github.com/microsoft/TypeScript/issues/1897
// to create such a type but it needs further refinement.
type JsonCompatible<T> = any;

export interface Body<T extends JsonCompatible<T>> {
  text: () => string;
  json: () => T;
  arrayBuffer: () => ArrayBuffer;
}

export interface Request<T extends JsonCompatible<T> = any> {
  /**
   * An object mapping lower-case HTTP header names to their values.
   */
  headers: { [key: string]: string };

  /**
   * An object mapping URL path parameter names to their values.
   */
  params: { [key: string]: string };

  /**
   * The query string of the requested URL.
   */
  query: string;

  /**
   * An object with ``text()``/``json()``/``arrayBuffer()`` functions
   * to access the request body in various ways.
   */
  body: Body<T>;

  /**
   * An object describing the authenticated identity retrieved
   * by this endpoint's authentication policies.
   *
   * ``caller.policy`` is a string indicating which policy accepted this request,
   * for use when multiple policies are listed.
   * The other fields depend on which policy accepted;
   * most set ``caller.id``, ``caller.data``, and ``caller.cert``,
   * while the ``"jwt"`` policy sets ``caller.jwt``.
   */
  caller: any;
}

export type ResponseBodyType<T> = string | ArrayBuffer | JsonCompatible<T>;

export interface Response<T extends ResponseBodyType<T> = any> {
  /**
   * (Optional) The HTTP status code to return.
   * Defaults to ``200``, or ``500`` if an exception is raised.
   */
  statusCode?: number;

  /**
   * (Optional) An object mapping lower-case HTTP header names to their values.
   * The type of ``body`` determines the default value of the ``content-type`` header.
   */
  headers?: { [key: string]: string };

  /**
   * (Optional) The body of the response.
   * Either
   * a `string <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String>`_ (``text/plain``),
   * an `ArrayBuffer <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer>`_ (``application/octet-stream``),
   * a `TypedArray <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray>`_ (``application/octet-stream``),
   * or as fall-back any `JSON-serializable <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify>`_ value (``application/json``).
   *
   * The content type in parentheses is the default and can be overridden in ``headers``.
   */
  body?: T;
}

export type EndpointFn<
  A extends JsonCompatible<A> = any,
  B extends ResponseBodyType<B> = any
> = (request: Request<A>) => Response<B>;

/**
 * A map in the Key Value Store.
 *
 * ``KVMap`` is modelled after JavaScript's ``Map`` object,
 * except that keys and values must be of type ``ArrayBuffer``
 * and no guarantees on iteration order are provided.
 */
export interface KVMap {
  has(key: ArrayBuffer): boolean;
  get(key: ArrayBuffer): ArrayBuffer | undefined;
  set(key: ArrayBuffer, value: ArrayBuffer): KVMap;
  delete(key: ArrayBuffer): boolean;

  /**
   * @param callback A function with parameters ``value, key, kvmap``.
   */
  forEach(
    callback: (value: ArrayBuffer, key: ArrayBuffer, kvmap: KVMap) => void
  ): void;
}

export type KVMaps = { [key: string]: KVMap };

export interface WrapAlgoParams {
  name: string;
}

/**
 * TODO
 */
export interface RsaOaepParams extends WrapAlgoParams {
  name: "RSA-OAEP";
  label?: ArrayBuffer;
}

/**
 * TODO
 */
export interface AESKWPParams extends WrapAlgoParams {
  name: "AES-KWP";
}

/**
 * TODO
 */
export interface RsaOaepAESKWPParams extends WrapAlgoParams {
  name: "RSA-OAEP-AES-KWP";
  label?: ArrayBuffer;
}

export interface CryptoKeyPair {
  /**
   * RSA private key in PEM encoding.
   */
  privateKey: string;

  /**
   * RSA public key in PEM encoding.
   */
  publicKey: string;
}

export interface CCF {
  /**
   * Convert a string into an ArrayBuffer.
   */
  strToBuf(v: string): ArrayBuffer;

  /**
   * Convert an ArrayBuffer into a string.
   */
  bufToStr(v: ArrayBuffer): string;

  /**
   * Serialize a value to JSON and convert it to an ArrayBuffer.
   *
   * Equivalent to ``ccf.strToBuf(JSON.stringify(v))``.
   */
  jsonCompatibleToBuf<T extends JsonCompatible<T>>(v: T): ArrayBuffer;

  /**
   * Parse JSON from an ArrayBuffer.
   *
   * Equivalent to ``JSON.parse(ccf.bufToStr(v))``.
   */
  bufToJsonCompatible<T extends JsonCompatible<T>>(v: ArrayBuffer): T;

  /**
   * Generate an AES key.
   *
   * @param size The length in bits of the key to generate. 128, 192, or 256.
   */
  generateAesKey(size: number): ArrayBuffer;

  /**
   * Generate an RSA key pair.
   *
   * @param size The length in bits of the RSA modulus. Minimum: 2048.
   * @param exponent (optional) The public exponent. Default: 65537.
   */
  generateRsaKeyPair(size: number, exponent?: number): CryptoKeyPair;

  /**
   * Wraps a key using a wrapping key.
   *
   * Constraints on the ``key`` and ``wrappingKey`` parameters depend
   * on the wrapping algorithm that is used (``wrapAlgo``).
   */
  wrapKey(
    key: ArrayBuffer,
    wrappingKey: ArrayBuffer,
    wrapAlgo: WrapAlgoParams
  ): ArrayBuffer;

  /**
   * An object that provides access to the maps of the Key-Value Store of CCF.
   * Fields are map names and values are :js:class:`CCF.KVMap` objects.
   */
  kv: KVMaps;
}
