export function text(request) {
  if (request.headers["content-type"] !== "text/plain")
    throw new Error(
      "unexpected content-type: " + request.headers["content-type"]
    );
  const text = request.body.text();
  if (text !== "text") throw new Error("unexpected body: " + text);
  return { body: "text" };
}

export function json(request) {
  if (request.headers["content-type"] !== "application/json")
    throw new Error(
      "unexpected content type: " + request.headers["content-type"]
    );
  const obj = request.body.json();
  if (obj.foo !== "bar") throw new Error("unexpected body: " + obj);
  return { body: { foo: "bar" } };
}

export function binary(request) {
  if (request.headers["content-type"] !== "application/octet-stream")
    throw new Error(
      "unexpected content type: " + request.headers["content-type"]
    );
  const buf = request.body.arrayBuffer();
  if (buf.byteLength !== 42)
    throw new Error(`unexpected body size: ${buf.byteLength}`);
  return { body: new ArrayBuffer(42) };
}

export function custom(request) {
  if (request.headers["content-type"] !== "foo/bar")
    throw new Error(
      "unexpected content type: " + request.headers["content-type"]
    );
  const text = request.body.text();
  if (text !== "text") throw new Error("unexpected body: " + text);
  return { body: "text" };
}
