import * as _ from 'lodash-es'
import protobuf from 'protobufjs/dist/protobuf.js'
import * as rs  from 'jsrsasign';

export function partition() {
    // Example from https://lodash.com.
    let arr = body.json();
    return _.partition(arr, n => n % 2);
}

export function proto() {
    // Example from https://github.com/protobufjs/protobuf.js.
    let Type  = protobuf.Type;
    let Field = protobuf.Field;
 
    let AwesomeMessage = new Type("AwesomeMessage").add(new Field("awesomeField", 1, "string"));
    
    let message = AwesomeMessage.create({ awesomeField: body.text() });
    let arr = AwesomeMessage.encode(message).finish();
    return arr;
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
