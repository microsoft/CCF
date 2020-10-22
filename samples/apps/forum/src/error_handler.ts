// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { ValidateError, FieldErrors } from "@tsoa/runtime";
import * as ccf from './types/ccf'

// The global error handler. Gets called for:
// - Request schema validation errors
// - Uncaught exceptions in controller actions

// See https://tsoa-community.github.io/docs/error-handling.html#setting-up-error-handling
// The code that imports and calls this handler is in tsoa-support/routes.ts.tmpl.

export interface ValidateErrorResponse {
    message: "Validation failed"
    details: FieldErrors
}

export const ValidateErrorStatus = 422

export function errorHandler(err: unknown, req: ccf.Request): ccf.Response {
    if (err instanceof ValidateError) {
        return {
            body: {
                message: "Validation failed",
                details: err.fields
            },
            statusCode: ValidateErrorStatus
        }
    }
    // Let CCF turn all other errors into 500.
    throw err;
}
