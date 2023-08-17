// TODO: REALLY don't do this
export function stash(request) {
  const body = request.body.json();
  globalThis[body.key] = body.value;
  return {};
}

