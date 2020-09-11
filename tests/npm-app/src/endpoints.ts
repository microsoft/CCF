import * as _ from 'lodash-es'
import * as rs  from 'jsrsasign';
// Importing the browser bundle works around https://github.com/protobufjs/protobuf.js/issues/1402.
import protobuf from 'protobufjs/dist/protobuf.js'

interface CCFBody {
    text: () => string
    json: () => any
    arrayBuffer: () => ArrayBuffer
};
interface CCFRequest {
    headers: { [key: string]: string; }
    params: { [key: string]: string; }
    query: string
    body: CCFBody
}

type PartitionRequest = [any]
type PartitionResponse = [any[], any[]]

export function partition(request: CCFRequest): PartitionResponse {
    // Example from https://lodash.com.
    let arr: PartitionRequest = request.body.json();
    return _.partition(arr, n => n % 2);
}

type ProtoResponse = Uint8Array

export function proto(request: CCFRequest): ProtoResponse {
    // Example from https://github.com/protobufjs/protobuf.js.
    let Type  = protobuf.Type;
    let Field = protobuf.Field;
 
    let AwesomeMessage = new Type("AwesomeMessage").add(new Field("awesomeField", 1, "string"));
    
    let message = AwesomeMessage.create({ awesomeField: request.body.text() });
    let arr = AwesomeMessage.encode(message).finish();
    return arr;
}

interface CryptoResponse {
    available: boolean
}

export function crypto(request: CCFRequest): CryptoResponse {
    // Most functionality of jsrsasign requires keys.
    // Generating a key here is too slow, so we'll just check if the
    // JS API got exported correctly.
    if (rs.KEYUTIL.generateKeypair) {
        return { available: true };
    } else {
        return { available: false };
    }
}
