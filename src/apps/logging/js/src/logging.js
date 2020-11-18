export function get_private(request) {
  const elements = request.query.split("&");
  for (const kv of elements) {
    const [k, v] = kv.split("=");
    if (k == "id") {
      const msg = ccf.kv.data.get(ccf.strToBuf(v));
      if (msg === undefined) {
        return { body: {error: 'No such key' } };
      }
      return { body: {msg: ccf.bufToStr(msg)} };
    }
  }
  throw new Error("Could not find 'id' in query");
}

export function get_public(request) {
  const elements = request.query.split("&");
  for (const kv of elements) {
    const [k, v] = kv.split("=");
    if (k == "id") {
      const msg = ccf.kv.data.get(ccf.strToBuf(v));
      if (msg === undefined) {
        return { body: {error: 'No such key' } };
      }
      return { body: {msg: ccf.bufToStr(msg)} };
    }
  }
  throw new Error("Could not find 'id' in query");
}

export function post_private(request) {
  let params = request.body.json();
  ccf.kv.data.set(ccf.strToBuf(params.id.toString()), ccf.strToBuf(params.msg));
  return { body: true };
}

export function post_public(request) {
  let params = request.body.json();
  ccf.kv.data.set(ccf.strToBuf(params.id.toString()), ccf.strToBuf(params.msg));
  return { body: true };
}

export function delete_private(request) {
  const elements = request.query.split("&");
  for (const kv of elements) {
    const [k, v] = kv.split("=");
    if (k == "id") {
      if (!ccf.kv.data.delete(ccf.strToBuf(v))) 
      {
        return { body: {error: 'No such key'} }
      }
      return { body: true };
    }
  }
  throw new Error("Could not find 'id' in query");
}

export function delete_public(request) {
  const elements = request.query.split("&");
  for (const kv of elements) {
    const [k, v] = kv.split("=");
    if (k == "id") {
      if (!ccf.kv.data.delete(ccf.strToBuf(v))) 
      {
        return { body: {error: 'No such key'} }
      }
      return { body: true };
    }
  }
  throw new Error("Could not find 'id' in query");
}
