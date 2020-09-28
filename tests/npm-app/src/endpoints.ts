import * as _ from 'lodash-es'
import * as rs  from 'jsrsasign';
// Importing the browser bundle works around https://github.com/protobufjs/protobuf.js/issues/1402.
import protobuf from 'protobufjs/dist/protobuf.js'

import * as ccf from './ccf'

type PartitionRequest = any[]
type PartitionResponse = [any[], any[]]

export function partition(request: ccf.Request<PartitionRequest>): ccf.Response<PartitionResponse> {
    // Example from https://lodash.com.
    let arr = request.body.json();
    return { body: _.partition(arr, n => n % 2) };
}

type ProtoResponse = Uint8Array

export function proto(request: ccf.Request): ccf.Response<ProtoResponse> {
    // Example from https://github.com/protobufjs/protobuf.js.
    let Type  = protobuf.Type;
    let Field = protobuf.Field;
    let AwesomeMessage = new Type("AwesomeMessage").add(new Field("awesomeField", 1, "string"));
    
    let message = AwesomeMessage.create({ awesomeField: request.body.text() });
    let arr = AwesomeMessage.encode(message).finish();
    return { 
        body: arr,
        headers: {
            'content-type': 'application/x-protobuf'
        }
    };
}

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
