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

export function sleep(request) {
  const time = request.body.json()["time"];
  ccf.enableUntrustedDateTime(true);
  const start = new Date();
  while (true)
  {
    const now = new Date();
    const diff = now - start;
    if (diff > time)
    {
      break;
    }
  }
  return {};
}
