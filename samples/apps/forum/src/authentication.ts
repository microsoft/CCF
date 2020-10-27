// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import jwt_decode from 'jwt-decode'
import * as ccf from './types/ccf'

export function authentication(request: ccf.Request, securityName: string, scopes?: string[]): any {
    if (securityName === "jwt") {
        const authHeader = request.headers['authorization']
        if (!authHeader) {
            throw new Error('authorization header missing')
        }
        const parts = authHeader.split(' ', 2)
        if (parts.length !== 2 || parts[0] !== 'Bearer') {
            throw new Error('unexpected authentication type')
        }
        const token = parts[1]
        let claims: any
        try {
            claims = jwt_decode(token)
        } catch (e) {
            throw new Error(`malformed jwt: ${e.message}`)
        }
        return {
            claims: claims,
            userId: claims.sub
        }
    }
    throw new Error(`BUG: unknown securityName: ${securityName}`)
}
