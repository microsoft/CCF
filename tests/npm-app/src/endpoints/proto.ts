// Importing the browser bundle works around https://github.com/protobufjs/protobuf.js/issues/1402.
import protobuf from "protobufjs/dist/protobuf.js";

import { CCF } from '../ccf/builtin'

type ProtoResponse = Uint8Array;

export function proto(request: CCF.Request): CCF.Response<ProtoResponse> {
  // Example from https://github.com/protobufjs/protobuf.js.
  let Type = protobuf.Type;
  let Field = protobuf.Field;
  let AwesomeMessage = new Type("AwesomeMessage").add(
    new Field("awesomeField", 1, "string")
  );

  let message = AwesomeMessage.create({ awesomeField: request.body.text() });
  let arr = AwesomeMessage.encode(message).finish();
  return {
    body: arr,
    headers: {
      "content-type": "application/x-protobuf",
    },
  };
}
