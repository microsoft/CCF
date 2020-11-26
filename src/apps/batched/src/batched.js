export function submit_batch(request) {
  const params = request.body.json();
  var count = 0;
  let entries_map = ccf.kv["entries"];
  for (var i = 0; i < params.entries.length; ++i) {
    const e = params.entries[i];
    const id = e.id;
    if (id % params.write_key_divisor == 0) {
      const msg = e.msg.repeat(params.write_size_multiplier);
      entries_map.set(ccf.jsonCompatibleToBuf(id), ccf.strToBuf(msg));
    }
    ++count;
  }

  return {
    body: count,
  };
}

export function fetch_batch(request) {
  const params = request.body.json();
  var results = [];
  let entries_map = ccf.kv["entries"];
  for (var i = 0; i < params.length; ++i) {
    const id = params[i];
    const msg = ccf.bufToStr(entries_map.get(ccf.jsonCompatibleToBuf(id)));
    results.push({ id: id, msg: msg });
  }
  return {
    body: results,
  };
}
