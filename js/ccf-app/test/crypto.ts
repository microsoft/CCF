import * as crypto from "crypto";
import { WrapAlgoParams } from '../src/global'

function nodeBufToArrBuf(buf: Buffer): ArrayBuffer {
  // Note: buf.buffer is not safe, see docs.
  const arrBuf = new ArrayBuffer(buf.byteLength);
  buf.copy(new Uint8Array(arrBuf));
  return arrBuf;
}

export function unwrapKey(wrappedKey: ArrayBuffer, unwrappingKey: ArrayBuffer, unwrapAlgo: WrapAlgoParams): ArrayBuffer {
  if (unwrapAlgo.name == 'RSA-OAEP') {
    return nodeBufToArrBuf(
      crypto.privateDecrypt(
        {
          key: Buffer.from(unwrappingKey),
          oaepHash: "sha256",
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        new Uint8Array(wrappedKey)
      )
    );
  } else if (unwrapAlgo.name == 'AES-KWP') {
    const iv = Buffer.from("A65959A6", "hex"); // defined in RFC 5649
    const decipher = crypto.createDecipheriv(
      "id-aes256-wrap-pad",
      new Uint8Array(unwrappingKey),
      iv
    );
    return nodeBufToArrBuf(
      Buffer.concat([decipher.update(new Uint8Array(wrappedKey)), decipher.final()])
    );
  } else if (unwrapAlgo.name == 'RSA-OAEP-AES-KWP') {
    /*
    const keyInfo = crypto.createPrivateKey(unwrappingKey);
    // asymmetricKeyDetails added in Node.js 15.7.0, we're at 14.
    const modulusLengthInBytes = keyInfo.asymmetricKeyDetails.modulusLength / 8;
    */
    // For now, hard-coded for the test in polyfill.test.ts.
    const modulusLengthInBytes = 2048 / 8;

    const wrap1 = wrappedKey.slice(0, modulusLengthInBytes);
    const wrap2 = wrappedKey.slice(modulusLengthInBytes);
    const aesKey = unwrapKey(wrap1, unwrappingKey, {
      name: 'RSA-OAEP',
      label: unwrapAlgo.label
    });
    return unwrapKey(wrap2, aesKey, {
      name: 'AES-KWP'
    });
  } else {
    throw new Error("unsupported unwrapAlgo.name");
  }
}