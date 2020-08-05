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

export function sign() {
    // Example from https://github.com/kjur/jsrsasign.
    let kp = rs.KEYUTIL.generateKeypair("EC", "secp256r1");
    let prvKey = kp.prvKeyObj;
    let pubKey = kp.pubKeyObj;

    let sig = new rs.KJUR.crypto.Signature({alg: 'SHA1withRSA'});
    sig.init(prvKey);
    sig.updateString(body);
    let sigHex = sig.sign();

    let pubKeyPEM = rs.KEYUTIL.getPEM(pubKey);
    return JSON.stringify({pubKey: pubKeyPEM, signed: sigHex});
}
