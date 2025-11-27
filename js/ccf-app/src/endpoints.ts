// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * The `endpoints` module contains all types needed to handle
 * requests and responses in endpoint functions.
 *
 * @module
 */

import { JsonCompatible, ccf } from "./global.js";

/**
 * The body of a request.
 *
 * @template T (Optional) The JSON type of the body.
 */
export interface Body<T extends JsonCompatible<T> = any> {
  /**
   * Parses the request body as UTF-8 string.
   */
  text(): string;

  /**
   * Parses the request body as JSON.
   */
  json(): T;

  /**
   * Returns the request body unmodified as ``ArrayBuffer``.
   */
  arrayBuffer(): ArrayBuffer;
}

/**
 * The request, passed as argument to endpoint functions.
 *
 * @template T (Optional) The JSON type of the body.
 */
export interface Request<T extends JsonCompatible<T> = any> {
  /**
   * An object mapping lower-case HTTP header names to their values.
   */
  headers: { [key: string]: string };

  /**
   * An object mapping URL path parameter names to their values.
   *
   * For example `GET /app/person/bob?fields=all` matched to `/app/person/{name}` becomes `{"name": "bob"}`
   */
  params: { [key: string]: string };

  /**
   * The full original requested URL.
   *
   * For example `GET /app/person/bob?fields=all` becomes `"/app/person/bob?fields=all"`
   */
  url: string;

  /**
   * The path component of the requested URL.
   *
   * For example `GET /app/person/bob?fields=all` becomes `"/app/person/bob"`
   */
  path: string;

  /**
   * The endpoint name which matched requested URL, potentially containing path parameters.
   *
   * For example `GET /app/person/bob?fields=all` becomes `"/app/person/{name}"`
   */
  route: string;

  /**
   * The query component of the requested URL.
   *
   * For example `GET /app/person/bob?fields=all` becomes `"fields=all"`
   */
  query: string;

  /**
   * The HTTP method of the request.
   *
   * For example `GET /app/person/bob?fields=all` becomes `"GET"`
   */
  method: string;

  /**
   * Hostname extracted from Host header, or null if header is missing
   */
  hostname: string;

  /**
   * An object to access the request body in various ways.
   */
  body: Body<T>;

  /**
   * An object describing the authenticated identity retrieved
   * by the endpoint's authentication policies, or ``undefined``
   * if no policy is defined for the endpoint.
   */
  caller?: AuthnIdentity;
}

export interface AuthnIdentityCommon {
  /**
   * A string indicating which policy accepted this request,
   * for use when multiple policies are listed in the endpoint
   * configuration of ``app.json``, or list-of-strings to identify
   * an all_of policy.
   */
  policy: string | string[];
}

export interface EmptyAuthnIdentity extends AuthnIdentityCommon {
  policy: "no_auth";
}

interface CertAuthnIdentityCommon extends AuthnIdentityCommon {
  /**
   * PEM-encoded certificate.
   */
  cert: string;
}

export interface AnyCertAuthnIdentity extends CertAuthnIdentityCommon {
  policy: "any_cert";
}

interface UserMemberAuthnIdentityCommon extends CertAuthnIdentityCommon {
  /**
   * User/member ID.
   */
  id: string;

  /**
   * User/member data object.
   */
  data: any;
}

export interface UserCertAuthnIdentity extends UserMemberAuthnIdentityCommon {
  policy: "user_cert";
}

export interface MemberCertAuthnIdentity extends UserMemberAuthnIdentityCommon {
  policy: "member_cert";
}

interface UserMemberCOSEAuthIdentityCommon {
  cose: {
    /**
     * COSE content
     */
    content: ArrayBuffer;
  };
}

export interface MemberCOSESign1AuthnIdentity
  extends UserMemberAuthnIdentityCommon, UserMemberCOSEAuthIdentityCommon {
  policy: "member_cose_sign1";
}

export interface UserCOSESign1AuthnIdentity
  extends UserMemberAuthnIdentityCommon, UserMemberCOSEAuthIdentityCommon {
  policy: "user_cose_sign1";
}

export interface JwtAuthnIdentity extends AuthnIdentityCommon {
  policy: "jwt";

  jwt: {
    /**
     * The issuer of the key that was used to validate the JWT signature.
     *
     * Note that the key issuer is not necessarily the same as the "iss"
     * claim in the JWT payload. Rather, it is the issuer used in the
     * ``set_jwt_issuer`` proposal.
     */
    keyIssuer: string;

    /**
     * The parsed JWT header.
     */
    header: any;

    /**
     * The parsed JWT payload.
     */
    payload: any;
  };
}

export interface AllOfAuthnIdentity extends AuthnIdentityCommon {
  policy: string[];

  user_cert?: UserCertAuthnIdentity;
  member_cert?: MemberCertAuthnIdentity;
  any_cert?: AnyCertAuthnIdentity;
  user_cose_sign1?: UserCOSESign1AuthnIdentity;
  member_cose_sign1?: MemberCOSESign1AuthnIdentity;
  jwt?: JwtAuthnIdentity;
}

/**
 * Authentication identities supported by CCF.
 * Each identity corresponds to a matching {@linkcode AuthnIdentityCommon.policy | policy}.
 * Policies have to be declared for each endpoint in ``app.json``.
 */
export type AuthnIdentity =
  | EmptyAuthnIdentity
  | UserCertAuthnIdentity
  | MemberCertAuthnIdentity
  | AnyCertAuthnIdentity
  | JwtAuthnIdentity
  | MemberCOSESign1AuthnIdentity
  | UserCOSESign1AuthnIdentity
  | AllOfAuthnIdentity;

/** See {@linkcode Response.body}. */
export type ResponseBodyType<T> = string | ArrayBuffer | JsonCompatible<T>;

/**
 * The response object returned from an endpoint function.
 *
 * Example returning JSON:
 * ```
 * return {
 *   body: {
 *     foo: "bar"
 *   }
 * };
 * ```
 *
 * Example returning plaintext and custom headers and status code:
 * ```
 * return {
 *   statusCode: 404,
 *   headers: {
 *     "x-request-id": "123"
 *   },
 *   body: "nobody's home"
 * };
 * ```
 *
 * See the property descriptions below for further details on
 * allowed data types, default headers, and default status codes.
 */
export interface Response<T extends ResponseBodyType<T> = any> {
  /**
   * The HTTP status code to return.
   * Defaults to `200`, or `500` if an exception is raised.
   */
  statusCode?: number;

  /**
   * An object mapping lower-case HTTP header names to their values.
   * The type of {@linkcode body} determines the default value of the `content-type` header.
   */
  headers?: { [key: string]: string };

  /**
   * The body of the response.
   *
   * Either
   * - a [string](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String) (`text/plain`),
   * - an [ArrayBuffer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer) (`application/octet-stream`),
   * - a [TypedArray](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray) (`application/octet-stream`),
   * - or as fall-back any [JSON-serializable](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify) value (`application/json`).
   *
   * The content type in parentheses is the default and can be overridden in {@linkcode headers}.
   */
  body?: T;
}

/**
 * The type of an endpoint function.
 * This type definition is typically not directly used.
 * Endpoint functions are usually defined as follows:
 *
 * ```
 * import * as ccfapp from '@microsoft/ccf-app';
 *
 * export function myEndpoint(request: ccfapp.Request): ccfapp.Response
 * { ... }
 * ```
 */
export type EndpointFn<
  A extends JsonCompatible<A> = any,
  B extends ResponseBodyType<B> = any,
> = (request: Request<A>) => Response<B>;

/**
 * @inheritDoc global!CCFRpc.setApplyWrites
 */
export const setApplyWrites = ccf.rpc.setApplyWrites.bind(ccf.rpc);

/**
 * @inheritDoc global!CCFRpc.setClaimsDigest
 */
export const setClaimsDigest = ccf.rpc.setClaimsDigest.bind(ccf.rpc);
