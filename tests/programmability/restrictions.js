const FIXED_KEY = ccf.strToBuf("hello");
const FIXED_VALUE = ccf.strToBuf("world");
const SIGNATURE_KEY = new ArrayBuffer(8);
const SIGNATURE_TABLES = [
  "public:ccf.internal.signatures",
  "public:ccf.internal.cose_signatures",
  "public:ccf.internal.tree",
];

function perform_operation(handle, receiver, operation) {
  switch (operation) {
    case "get":
      return handle.get.call(receiver, SIGNATURE_KEY);
    case "has":
      return handle.has.call(receiver, SIGNATURE_KEY);
    case "getVersionOfPreviousWrite":
      return handle.getVersionOfPreviousWrite.call(receiver, SIGNATURE_KEY);
    case "forEach":
      return handle.forEach.call(receiver, () => {});
    case "size":
      return Object.getOwnPropertyDescriptor(handle, "size").get.call(receiver);
    case "set":
      return handle.set.call(receiver, SIGNATURE_KEY, FIXED_VALUE);
    case "delete":
      return handle.delete.call(receiver, SIGNATURE_KEY);
    case "clear":
      return handle.clear.call(receiver);
    default:
      throw new Error(`Unknown operation: ${operation}`);
  }
}

export function try_operation(request) {
  const body = request.body.json();
  try {
    const receiver = body.forged
      ? { _map_name: body.table }
      : ccf.kv[body.table];
    const handle = ccf.kv[body.via ?? body.table];
    perform_operation(handle, receiver, body.operation);
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to ${body.operation} table: ${body.table}\n${e}`,
    };
  }

  return {
    statusCode: 200,
    body: `Permitted to ${body.operation} table: ${body.table}`,
  };
}

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
  const permitted = ccf.kv[body.via ?? body.table];

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

export function try_read_historical_via_current_handle(request) {
  const body = request.body.json();
  const states = ccf.historical.getStateRange(3, body.seqno, body.seqno, 1800);
  if (states === null) {
    return {
      statusCode: 202,
      headers: { "retry-after": "1" },
      body: `Historical state at ${body.seqno} is not yet available`,
    };
  }

  try {
    const historical_handle = states[0].kv[body.table];
    historical_handle.get.call(ccf.kv[body.table], SIGNATURE_KEY);
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to read historical KV via current handle for table: ${body.table}\n${e}`,
    };
  }

  return {
    statusCode: 200,
    body: `Permitted to read from table: ${body.table}`,
  };
}

export function read_historical_signature_tables(request) {
  const body = request.body.json();
  const states = ccf.historical.getStateRange(4, body.seqno, body.seqno, 1800);
  if (states === null) {
    return {
      statusCode: 202,
      headers: { "retry-after": "1" },
      body: `Historical state at ${body.seqno} is not yet available`,
    };
  }

  try {
    const state = states[0];
    const tables = {};
    for (const table of SIGNATURE_TABLES) {
      const handle = state.kv[table];
      const entries = [];
      handle.forEach((value, key) => {
        const stored_value = handle.get(key);
        const bytes = new Uint8Array(value);
        const stored_bytes = new Uint8Array(stored_value);
        entries.push({
          key: Array.from(new Uint8Array(key)),
          valueSize: value.byteLength,
          has: handle.has(key),
          getMatches:
            stored_value !== undefined &&
            stored_bytes.length === bytes.length &&
            bytes.every((byte, index) => byte === stored_bytes[index]),
          version: handle.getVersionOfPreviousWrite(key),
        });
      });
      const write_denied = {};
      for (const operation of ["set", "delete", "clear"]) {
        try {
          perform_operation(handle, handle, operation);
          write_denied[operation] = false;
        } catch (e) {
          if (!(e instanceof TypeError)) {
            throw e;
          }
          write_denied[operation] = true;
        }
      }
      tables[table] = {
        size: handle.size,
        entries,
        writeDenied: write_denied,
      };
    }

    return {
      statusCode: 200,
      body: {
        transactionId: state.transactionId,
        isSignatureTransaction: state.receipt.is_signature_transaction,
        rawSignatureExpected: state.receipt.signature.length > 0,
        tables,
      },
    };
  } catch (e) {
    return {
      statusCode: 400,
      body: `Failed to read historical signature tables at ${body.seqno}\n${e}`,
    };
  }
}
