import * as rs  from 'jsrsasign';

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
    console.log(ccf.ccf)
    return { body: ccf.ccf.generateAesKey(request.body.json().size) }
}