// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// toUint8ArrayBuffer(buffer) converts the buffer into a Uint8Array<ArrayBuffer>
// If the input is already a Uint8Array<ArrayBuffer>, it returns it directly
// Otherwise it will copy the data into a new Uint8Array<ArrayBuffer>
export function toUint8ArrayBuffer(
  buffer: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBuffer> {
  if (buffer.buffer instanceof ArrayBuffer) {
    return buffer as Uint8Array<ArrayBuffer>;
  }
  if (buffer.buffer instanceof SharedArrayBuffer) {
    const view = new Uint8Array(
      new ArrayBuffer((buffer.buffer as SharedArrayBuffer).byteLength),
    );
    view.set(buffer);
    return new Uint8Array(view.buffer, buffer.byteOffset, buffer.byteLength);
  }
  throw new Error("Unsupported buffer type");
}

// toArrayBuffer(buffer) converts the buffer to an ArrayBuffer
// If the input is already an ArrayBuffer, it returns it directly
// Otherwise it will copy the data into a new ArrayBuffer
export function toArrayBuffer(
  buffer: ArrayBufferLike | Buffer | Uint8Array,
): ArrayBuffer {
  if (buffer instanceof ArrayBuffer) {
    return buffer;
  }
  if (buffer instanceof SharedArrayBuffer) {
    const view = new Uint8Array( buffer);
    return toUint8ArrayBuffer(view).buffer;
  }
  if (buffer instanceof Uint8Array || (buffer as any) instanceof Buffer) {
    return toArrayBuffer(
      buffer.buffer.slice(
        buffer.byteOffset,
        buffer.byteOffset + buffer.byteLength,
      ),
    );
  }
  throw new Error("Unsupported buffer type");
}