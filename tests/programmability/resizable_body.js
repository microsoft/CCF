// Length-tracking Uint8Array over a resizable ArrayBuffer that has been
// shrunk after the view was created. The typed array's construction-time
// byteLength is 1 MiB, but the backing buffer only holds `shrunk` bytes.
// CCF must copy no more than the current backing-buffer length.
export function shrunk_body(request) {
  const shrunk = Number(request.query.split("=")[1]);
  const rab = new ArrayBuffer(1 << 20, { maxByteLength: 1 << 20 });
  const u8 = new Uint8Array(rab);
  for (let i = 0; i < 1 << 20; i++) {
    u8[i] = 0xab;
  }
  rab.resize(shrunk);
  return {
    statusCode: 200,
    body: u8,
  };
}

// Length-tracking Uint8Array over a resizable ArrayBuffer that has been
// grown after the view was created. The response body length must match
// the grown length.
export function grown_body(request) {
  const grown = Number(request.query.split("=")[1]);
  const rab = new ArrayBuffer(1, { maxByteLength: 1 << 20 });
  const u8 = new Uint8Array(rab);
  rab.resize(grown);
  for (let i = 0; i < grown; i++) {
    u8[i] = 0xcd;
  }
  return {
    statusCode: 200,
    body: u8,
  };
}

// Non-tracking view whose byteOffset ends up past the current buffer size
// after a resize(). Copy must be empty rather than reading past the end.
export function oob_offset_body(request) {
  const rab = new ArrayBuffer(64, { maxByteLength: 1 << 20 });
  const u8 = new Uint8Array(rab, 32, 16);
  rab.resize(8);
  return {
    statusCode: 200,
    body: u8,
  };
}
