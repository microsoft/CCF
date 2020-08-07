import * as _ from 'lodash-es'
import protobuf from 'protobufjs/dist/protobuf.js'
import * as rs  from 'jsrsasign';

export function partition() {
    // Example from https://lodash.com.
    let arr = JSON.parse(body);
    return _.partition(arr, n => n % 2);
}

export function proto() {
    // Example from https://github.com/protobufjs/protobuf.js.
    let Type  = protobuf.Type;
    let Field = protobuf.Field;
 
    let AwesomeMessage = new Type("AwesomeMessage").add(new Field("awesomeField", 1, "string"));
    
    let message = AwesomeMessage.create({ awesomeField: body });
    let buffer = AwesomeMessage.encode(message).finish();

    // CCF doesn't support binary responses yet, so we'll convert the Uint8Array into a hex string.
    let hex = [...buffer].map(b => ('00' + b.toString(16)).slice(-2)).join("");

    return hex;
}

export function crypto() {
    let response;
    // Most functionality of jsrsasign requires keys.
    // Generating a key here is too slow, so we'll just check if the
    // JS API got exported correctly.
    if (rs.KEYUTIL.generateKeypair) {
        response = { available: true };
    } else {
        response = { available: false };
    }
    return response;
}
