const responseConfig = ccf.kv["response_config"];
const MAX_RESPONSE_SIZE_KEY = "max_response_size";

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

export function configure_response(request) {
  const maxResponseSize = request.body.json().max_response_size;
  if (!Number.isSafeInteger(maxResponseSize) || maxResponseSize < 0) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: "InvalidInput",
          msg: "max_response_size must be a non-negative safe integer",
        },
      },
    };
  }

  responseConfig.set(
    ccf.strToBuf(MAX_RESPONSE_SIZE_KEY),
    ccf.strToBuf(`${maxResponseSize}`),
  );
  return { statusCode: 204 };
}

export function generate_response(request) {
  const maxResponseSizeBuffer = responseConfig.get(
    ccf.strToBuf(MAX_RESPONSE_SIZE_KEY),
  );
  if (maxResponseSizeBuffer === undefined) {
    return {
      statusCode: 500,
      body: {
        error: {
          code: "InternalError",
          msg: "Response generator is not configured",
        },
      },
    };
  }

  const maxResponseSize = Number(ccf.bufToStr(maxResponseSizeBuffer));
  const size = request.body.json().size;
  if (!Number.isSafeInteger(size) || size < 0 || size > maxResponseSize) {
    return {
      statusCode: 400,
      body: {
        error: {
          code: "InvalidInput",
          msg: `size must be an integer between 0 and ${maxResponseSize}`,
        },
      },
    };
  }

  return {
    body: "X".repeat(size),
  };
}
