import * as rs  from 'jsrsasign';
import { Base64 } from 'js-base64';

import * as ccf from '../types/ccf'

interface CryptoResponse {
    available: boolean
}

export function crypto(request: ccf.Request): ccf.Response<CryptoResponse> {
    // Most functionality of jsrsasign requires keys.
    // Generating a key here is too slow, so we'll just check if the
    // JS API got exported correctly.
    let available = rs.KEYUTIL.generateKeypair ? true : false;
    return { body: { available: available } };
}

interface GenerateAesKeyRequest {
    size: number
}

export function generateAesKey(request: ccf.Request<GenerateAesKeyRequest>): ccf.Response<ArrayBuffer> {
    return { body: ccf.ccf.generateAesKey(request.body.json().size) }
}

type Base64 = string

interface WrapKeyRsaOaepRequest {
    key: Base64 // typically an AES key
    wrappingKey: Base64 // RSA public key
    label?: Base64
}

export function wrapKeyRsaOaep(request: ccf.Request<WrapKeyRsaOaepRequest>): ccf.Response<ArrayBuffer> {
    const r = request.body.json()
    const key = b64ToBuf(r.key)
    const wrappingKey = b64ToBuf(r.wrappingKey)
    const label = r.label ? b64ToBuf(r.label) : undefined
    const wrappedKey = ccf.ccf.wrapKey(key, wrappingKey, {
        name: 'RSA-OAEP',
        label: label
    })
    return { body: wrappedKey }
}

function b64ToBuf(b64: string): ArrayBuffer {
    return Base64.toUint8Array(b64).buffer
}
