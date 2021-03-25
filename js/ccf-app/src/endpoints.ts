// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { JsonCompatible } from "./global";

export interface Body<T extends JsonCompatible<T>> {
  text(): string;
  json(): T;
  arrayBuffer(): ArrayBuffer;
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
