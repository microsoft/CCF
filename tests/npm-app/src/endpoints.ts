import * as _ from 'lodash-es'
import * as rs  from 'jsrsasign';
// Importing the browser bundle works around https://github.com/protobufjs/protobuf.js/issues/1402.
import protobuf from 'protobufjs/dist/protobuf.js'

interface CCFBody<T> {
    text: () => string
    json: () => T
    arrayBuffer: () => ArrayBuffer
};
interface CCFRequest<T=any> {
    headers: { [key: string]: string; }
    params: { [key: string]: string; }
    query: string
    body: CCFBody<T>
}
interface CCFResponse<T=any> {
    statusCode?: number
    headers?: { [key: string]: string; }
    body?: T
}

type PartitionRequest = any[]
type PartitionResponse = [any[], any[]]

export function partition(request: CCFRequest<PartitionRequest>): CCFResponse<PartitionResponse> {
    // Example from https://lodash.com.
    let arr = request.body.json();
    return { body: _.partition(arr, n => n % 2) };
}

type ProtoResponse = Uint8Array

export function proto(request: CCFRequest): CCFResponse<ProtoResponse> {
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

export function crypto(request: CCFRequest): CCFResponse<CryptoResponse> {
    // Most functionality of jsrsasign requires keys.
    // Generating a key here is too slow, so we'll just check if the
    // JS API got exported correctly.
    let available = rs.KEYUTIL.generateKeypair ? true : false;
    return { body: { available: available } };
}
