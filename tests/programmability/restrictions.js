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
