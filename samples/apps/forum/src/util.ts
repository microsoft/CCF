// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import jwt_decode from 'jwt-decode'

export function parseAuthToken(authHeader: string): string {
    const parts = authHeader.split(' ', 2)
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        throw new Error('unexpected authorization type')
    }
    const token = parts[1]
    const jwt = jwt_decode(token) as any
    const user = jwt.sub
    if (!user) {
        throw new Error('invalid jwt, "sub" claim not found')
    }
    return user
}
