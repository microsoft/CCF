import * as _ from 'lodash-es'
import protobuf from 'protobufjs/dist/protobuf.js'
import * as rs  from 'jsrsasign';

export function partition() {
    // Example from https://lodash.com.
    let arr = JSON.parse(body);
    return JSON.stringify(_.partition(arr, n => n % 2));
}

export function pb() {
    // Example from https://github.com/protobufjs/protobuf.js.
    let Type  = protobuf.Type;
    let Field = protobuf.Field;
 
    let AwesomeMessage = new Type("AwesomeMessage").add(new Field("awesomeField", 1, "string"));
    
    let message = AwesomeMessage.create({ awesomeField: body });
    let buffer = AwesomeMessage.encode(message).finish();
    return buffer;
}

export function crypto() {
    let response;
    if (rs.KEYUTIL.generateKeypair) {
        response = { available: true };
    } else {
        response = { available: false };
    }
    return JSON.stringify(response);
}
