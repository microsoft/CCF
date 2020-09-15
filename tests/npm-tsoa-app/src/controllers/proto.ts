import {
    Request,
    Controller,
    Post,
    Route,
  } from "@tsoa/runtime";

// Importing the browser bundle works around https://github.com/protobufjs/protobuf.js/issues/1402.
import protobuf from 'protobufjs/dist/protobuf.js'

//type ProtoRequest = any
type ProtoResponse = any // should be Uint8Array, but not supported

@Route("proto")
export class ProtoController extends Controller {

  @Post()
  public wrapInProtobuf(
    @Request() request: any
  ): ProtoResponse {
    // Example from https://github.com/protobufjs/protobuf.js.
    let Type = protobuf.Type;
    let Field = protobuf.Field;

    let AwesomeMessage = new Type("AwesomeMessage").add(new Field("awesomeField", 1, "string"));

    let message = AwesomeMessage.create({ awesomeField: request.body.text() });
    let arr = AwesomeMessage.encode(message).finish();

    this.setHeader('content-type', 'application/x-protobuf')
    return arr;
  }
}