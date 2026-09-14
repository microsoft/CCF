// Regression test for a heap over-read in the JS response-body copy path.
//
// A length-tracking Uint8Array constructed over a resizable ArrayBuffer
// captures the buffer's byteLength at construction time in the typed
// array's internal `length` field, but QuickJS does NOT refresh that
// field when the buffer is later shrunk. JS_GetTypedArrayBuffer therefore
// returns the stale, larger construction-time length. If CCF copied that
// many bytes out of the js_realloc'd-down backing allocation, it would
// return uninitialised enclave memory to the HTTP client.
//
// The endpoint returns a length-tracking view whose backing buffer has
// been shrunk to `n` bytes. The HTTP response body length must be `n`,
// not the 1 MiB construction-time length.
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
