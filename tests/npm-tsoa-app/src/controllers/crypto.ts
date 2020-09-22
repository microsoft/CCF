import {
    Controller,
    Get,
    Route,
} from "@tsoa/runtime";
import * as rs from 'jsrsasign';

interface CryptoResponse {
    available: boolean
}

@Route("crypto")
export class CryptoController extends Controller {

    @Get()
    public getCrypto(): CryptoResponse {
        // Most functionality of jsrsasign requires keys.
        // Generating a key here is too slow, so we'll just check if the
        // JS API got exported correctly.
        if (rs.KEYUTIL.generateKeypair) {
            return { available: true };
        } else {
            return { available: false };
        }
    }
}