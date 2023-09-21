export function recursive(request) {
  const depth = request.body.json()["depth"];
  _recursive(depth);
  return {};
}

function _recursive(depth) {
  if (depth > 0) {
    _recursive(--depth);
  }
}

export function alloc(request) {
  const size = request.body.json()["size"];
  new Uint8Array(size);
  return {};
}
