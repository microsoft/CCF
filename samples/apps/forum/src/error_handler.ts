// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { ValidateError as TsoaValidateError, FieldErrors } from "@tsoa/runtime";
import * as ccfapp from "ccf-app";

export interface ErrorResponse {
  message: string;
}

export interface ValidateErrorResponse extends ErrorResponse {
  message: "Validation failed";
  details: FieldErrors;
}

export abstract class ValidateError {
  static Status: 422 = 422;
}

class HttpError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message);
  }
}

export class BadRequestError extends HttpError {
  static Status: 400 = 400;

  constructor(message: string) {
    super(BadRequestError.Status, message);
  }
}

export class UnauthorizedError extends HttpError {
  static Status: 401 = 401;

  constructor(message: string) {
    super(UnauthorizedError.Status, message);
  }
}

export class ForbiddenError extends HttpError {
  static Status: 403 = 403;

  constructor(message: string) {
    super(ForbiddenError.Status, message);
  }
}

export class NotFoundError extends HttpError {
  static Status: 404 = 404;

  constructor(message: string) {
    super(NotFoundError.Status, message);
  }
}

/** The global error handler.
 *
 * This handler is called for:
 * - Request schema validation errors
 * - Exceptions thrown by the authentication module
 * - Uncaught exceptions in controller actions
 *
 * See https://tsoa-community.github.io/docs/error-handling.html#setting-up-error-handling
 * The code that imports and calls this handler is in tsoa-support/routes.ts.tmpl.
 */
export function errorHandler(
  err: unknown,
  req: ccfapp.Request
): ccfapp.Response<ErrorResponse | ValidateErrorResponse> {
  if (err instanceof TsoaValidateError) {
    return {
      body: {
        message: "Validation failed",
        details: err.fields,
      },
      statusCode: ValidateError.Status,
    };
  } else if (err instanceof HttpError) {
    return {
      body: {
        message: err.message,
      },
      statusCode: err.statusCode,
    };
  }
  // Let CCF turn all other errors into 500.
  throw err;
}
