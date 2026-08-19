const MAX_RESPONSE_SIZE = 32 * 1024 * 1024;

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

export function generate_response(request) {
  const size = request.body.json().size;
  if (
    !Number.isSafeInteger(size) ||
    size < 0 ||
    size > MAX_RESPONSE_SIZE
  ) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: "InvalidInput",
          msg: `size must be an integer between 0 and ${MAX_RESPONSE_SIZE}`,
        },
      },
    };
  }

  return {
    body: "X".repeat(size),
  };
}
