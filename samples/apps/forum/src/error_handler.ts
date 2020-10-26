// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { ValidateError, FieldErrors } from "@tsoa/runtime";
import * as ccf from './types/ccf'

// The global error handler. Gets called for:
// - Request schema validation errors
// - Uncaught exceptions in controller actions

// See https://tsoa-community.github.io/docs/error-handling.html#setting-up-error-handling
// The code that imports and calls this handler is in tsoa-support/routes.ts.tmpl.

export interface ErrorResponse {
    message: string
}

export interface ValidateErrorResponse extends ErrorResponse {
    message: "Validation failed"
    details: FieldErrors
}

export const ValidateErrorStatus = 422

class HttpError extends Error {
    constructor(public statusCode: number, message: string) {
        super(message)
    }
}

export class BadRequestError extends HttpError {
    static Status = 400

    constructor(message: string) {
        super(BadRequestError.Status, message)
    }
}

export class ForbiddenError extends HttpError {
    static Status = 403

    constructor(message: string) {
        super(ForbiddenError.Status, message)
    }
}

export class NotFoundError extends HttpError {
    static Status = 404

    constructor(message: string) {
        super(NotFoundError.Status, message)
    }
}

export function errorHandler(err: unknown, req: ccf.Request): ccf.Response<ErrorResponse | ValidateErrorResponse> {
    if (err instanceof ValidateError) {
        return {
            body: {
                message: "Validation failed",
                details: err.fields
            },
            statusCode: ValidateErrorStatus
        }
    } else if (err instanceof HttpError) {
        return {
            body: {
                message: err.message
            },
            statusCode: err.statusCode
        }
    }
    // Let CCF turn all other errors into 500.
    throw err;
}
