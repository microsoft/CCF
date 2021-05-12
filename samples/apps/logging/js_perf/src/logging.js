function get_id_from_request_query(request) {
  const elements = request.query.split("&");
  for (const kv of elements) {
    const [k, v] = kv.split("=");
    if (k == "id") {
      return ccf.strToBuf(v);
    }
  }
  throw new Error("Could not find 'id' in query");
}

function get_record(map, id) {
  const msg = map.get(id);
  if (msg === undefined) {
    return { body: { error: "No such key" } };
  }
  return { body: { msg: ccf.bufToStr(msg) } };
}

export function get_private(request) {
  const id = get_id_from_request_query(request);
  return get_record(ccf.kv["records"], id);
}

export function post_private(request) {
  let params = request.body.json();
  ccf.kv["records"].set(
    ccf.strToBuf(params.id.toString()),
    ccf.strToBuf(params.msg)
  );
  return { body: true };
}
