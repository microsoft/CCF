const FIXED_KEY = ccf.strToBuf("hello");
const FIXED_VALUE = ccf.strToBuf("world");

export function try_read(request) {
  const table_name = request.body.json().table;
  var handle;
  try {
    handle = ccf.kv[table_name];
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to get handle for table: ${table_name}\n${e}`,
    };
  }

  try {
    const v = handle.get(FIXED_KEY);
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to read from handle for table: ${table_name}\n${e}`,
    };
  }

  return {
    statusCode: 200,
    body: `Permitted to read from table: ${table_name}`,
  };
}

export function try_write(request) {
  const table_name = request.body.json().table;
  var handle;
  try {
    handle = ccf.kv[table_name];
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to get handle for table: ${table_name}\n${e}`,
    };
  }

  try {
    handle.set(FIXED_KEY, FIXED_VALUE);
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to write to handle for table: ${table_name}\n${e}`,
    };
  }

  return {
    statusCode: 200,
    body: `Permitted to write to table: ${table_name}`,
  };
}

// Tries to re-target a permitted method at a forged receiver.
export function try_read_retargeted(request) {
  const body = request.body.json();
  const permitted = ccf.kv[body.via];

  try {
    permitted.get.call({ _map_name: body.table }, FIXED_KEY);
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to read via forged handle for table: ${body.table}\n${e}`,
    };
  }

  return {
    statusCode: 200,
    body: `Permitted to read from table: ${body.table}`,
  };
}

// Reads a table from historical KV.
export function try_read_historical(request) {
  const body = request.body.json();
  const states = ccf.historical.getStateRange(1, body.seqno, body.seqno, 1800);
  if (states === null) {
    return {
      statusCode: 202,
      headers: { "retry-after": "1" },
      body: `Historical state at ${body.seqno} is not yet available`,
    };
  }

  var handle;
  try {
    handle = states[0].kv[body.table];
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to get historical handle for table: ${body.table}\n${e}`,
    };
  }

  try {
    handle.get(FIXED_KEY);
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to read from historical handle for table: ${body.table}\n${e}`,
    };
  }

  return {
    statusCode: 200,
    body: `Permitted to read from historical table: ${body.table}`,
  };
}

// Tries to use a historical handle with a current-KV method.
export function try_read_current_via_historical_handle(request) {
  const body = request.body.json();
  const states = ccf.historical.getStateRange(2, body.seqno, body.seqno, 1800);
  if (states === null) {
    return {
      statusCode: 202,
      headers: { "retry-after": "1" },
      body: `Historical state at ${body.seqno} is not yet available`,
    };
  }

  const historical_handle = states[0].kv[body.table];
  const permitted = ccf.kv[body.table];

  try {
    permitted.get.call(historical_handle, FIXED_KEY);
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to read current KV via historical handle for table: ${body.table}\n${e}`,
    };
  }

  return {
    statusCode: 200,
    body: `Permitted to read from table: ${body.table}`,
  };
}
