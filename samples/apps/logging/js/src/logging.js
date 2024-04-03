function parse_request_query(request) {
  const elements = request.query.split("&");
  const obj = {};
  for (const kv of elements) {
    const [k, v] = kv.split("=");
    obj[k] = v;
  }
  return obj;
}

function get_id_from_query(parsedQuery) {
  if (parsedQuery.id === undefined) {
    throw new Error("Could not find 'id' in query");
  }
  return ccf.strToBuf(parsedQuery.id);
}

function public_records(store, scope) {
  if (scope === undefined) return store["public:records"];
  return store["public:records-" + scope];
}

function private_records(store, scope) {
  if (scope === undefined) return store["records"];
  return store["records-" + scope];
}

function get_record(map, id) {
  const msg = map.get(id);
  if (msg === undefined) {
    return { body: { error: "No such key" } };
  }
  return { body: { msg: ccf.bufToStr(msg) } };
}

function delete_record(map, id) {
  if (!map.has(id)) {
    return { body: { error: "No such key" } };
  }
  map.delete(id);
  return { body: true };
}

export function get_private(request) {
  const parsedQuery = parse_request_query(request);
  const id = get_id_from_query(parsedQuery);
  return get_record(private_records(ccf.kv, parsedQuery.scope), id);
}

export function get_historical(request) {
  const parsedQuery = parse_request_query(request);
  const id = get_id_from_query(parsedQuery);
  // Forward-compatibility with 2.x
  const kv = ccf.historicalState.kv || ccf.kv;
  return get_record(private_records(kv, parsedQuery.scope), id);
}

export function get_historical_with_receipt(request) {
  const result = get_historical(request);
  result.body.receipt = ccf.historicalState.receipt;
  return result;
}

export function get_historical_public(request) {
  const parsedQuery = parse_request_query(request);
  const id = get_id_from_query(parsedQuery);
  // Forward-compatibility with 2.x
  const kv = ccf.historicalState.kv || ccf.kv;
  return get_record(public_records(kv, parsedQuery.scope), id);
}

export function get_historical_public_with_receipt(request) {
  const result = get_historical_public(request);
  result.body.receipt = ccf.historicalState.receipt;
  // Claims are expanded as result.body.msg, so the claims digest is removed
  // from the receipt to force verification to re-compute it.
  delete result.body.receipt.leaf_components.claims_digest;
  return result;
}

function get_last_write_version(id, is_private = true, scope) {
  const records = is_private
    ? private_records(ccf.kv, scope)
    : public_records(ccf.kv, scope);
  return records.getVersionOfPreviousWrite(id);
}

function get_historical_range_impl(request, isPrivate, nextLinkPrefix) {
  const parsedQuery = parse_request_query(request);
  const id = get_id_from_query(parsedQuery);
  let { from_seqno, to_seqno } = parsedQuery;
  if (from_seqno !== undefined) {
    from_seqno = parseInt(from_seqno);
    if (isNaN(from_seqno)) {
      throw new Error("from_seqno is not an integer");
    }
  } else {
    // If no from_seqno is specified, defaults to very first transaction
    // in ledger
    from_seqno = 1;
  }

  if (to_seqno !== undefined) {
    to_seqno = parseInt(to_seqno);
    if (isNaN(to_seqno)) {
      throw new Error("to_seqno is not an integer");
    }
  } else {
    // If no end point is specified, use the last time this ID was
    // written to
    const lastWriteVersion = get_last_write_version(id, isPrivate);
    if (lastWriteVersion !== undefined) {
      to_seqno = lastWriteVersion;
    } else {
      // If there's no last written version, it may have never been
      // written but may simply be currently deleted. Use current commit
      // index as end point to ensure we include any deleted entries.
      to_seqno = ccf.consensus.getLastCommittedTxId().seqno;
    }
  }

  // Range must be in order
  if (to_seqno < from_seqno) {
    throw new Error("to_seqno must be >= from_seqno");
  }

  // End of range must be committed
  let isCommitted = false;
  const viewOfFinalSeqno = ccf.consensus.getViewForSeqno(to_seqno);
  if (viewOfFinalSeqno !== null) {
    const txStatus = ccf.consensus.getStatusForTxId(viewOfFinalSeqno, to_seqno);
    isCommitted = txStatus === "Committed";
  }
  if (!isCommitted) {
    throw new Error("End of range must be committed");
  }

  const max_seqno_per_page = 2000;
  const range_begin = from_seqno;
  const range_end = Math.min(to_seqno, range_begin + max_seqno_per_page);

  // Compute a deterministic handle for the range request.
  // Note: Instead of ccf.digest, an equivalent of std::hash should be used.
  const makeHandle = (begin, end, id) => {
    const cacheKey = `${begin}-${end}-${id}`;
    const digest = ccf.crypto.digest("SHA-256", ccf.strToBuf(cacheKey));
    const handle = new DataView(digest).getUint32(0);
    return handle;
  };
  const handle = makeHandle(range_begin, range_end, parsedQuery.id);

  // Fetch the requested range
  const expiry_seconds = 1800;
  const states = ccf.historical.getStateRange(
    handle,
    range_begin,
    range_end,
    expiry_seconds,
  );
  if (states === null) {
    return {
      statusCode: 202,
      headers: {
        "retry-after": "1",
      },
      body: `Historical transactions from ${range_begin} to ${range_end} are not yet available, fetching now`,
    };
  }

  // Process the fetched states
  const entries = [];
  const scope = parsedQuery.scope;
  for (const state of states) {
    const records = isPrivate
      ? private_records(state.kv, scope)
      : public_records(state.kv, scope);
    const msg = records.get(id);
    if (msg !== undefined) {
      entries.push({
        seqno: parseInt(state.transactionId.split(".")[1]),
        id: parseInt(parsedQuery.id),
        msg: ccf.bufToStr(msg),
      });
    }
    // This response does not include any entry when the given key wasn't
    // modified at this seqno. It could instead indicate that the store
    // was checked with an empty tombstone object, but this approach gives
    // smaller responses.
  }

  // If this didn't cover the total requested range, begin fetching the
  // next page and tell the caller how to retrieve it
  let nextLink;
  if (range_end != to_seqno) {
    const next_page_start = range_end + 1;
    const next_page_end = Math.min(
      to_seqno,
      next_page_start + max_seqno_per_page,
    );
    const next_page_handle = makeHandle(
      next_page_start,
      next_page_end,
      parsedQuery.id,
    );
    ccf.historical.getStateRange(
      next_page_handle,
      next_page_start,
      next_page_end,
    );

    // NB: This path tells the caller to continue to ask until the end of
    // the range, even if the next response is paginated
    nextLink = `${nextLinkPrefix}?from_seqno=${next_page_start}&to_seqno=${to_seqno}&id=${parsedQuery.id}`;
  }

  // Assume this response makes it all the way to the client, and
  // they're finished with it, so we can drop the retrieved state. In a
  // real app this may be driven by a separate client request or an LRU
  ccf.historical.dropCachedStates(handle);

  return {
    body: {
      entries: entries,
      "@nextLink": nextLink,
    },
  };
}

export function get_historical_range(request) {
  return get_historical_range_impl(
    request,
    true,
    "/app/log/private/historical/range",
  );
}

export function get_historical_range_public(request) {
  return get_historical_range_impl(
    request,
    false,
    "/app/log/public/historical/range",
  );
}

export function get_public(request) {
  const parsedQuery = parse_request_query(request);
  const id = get_id_from_query(parsedQuery);
  return get_record(public_records(ccf.kv, parsedQuery.scope), id);
}

export function post_private(request) {
  const parsedQuery = parse_request_query(request);
  let params = request.body.json();
  const id = ccf.strToBuf(params.id.toString());
  private_records(ccf.kv, parsedQuery.scope).set(id, ccf.strToBuf(params.msg));
  return { body: true };
}

export function post_private_admin_only(request) {
  // Return an auth error if the caller has no user data,
  // or the user data is not an object with isAdmin field,
  // or this field is not true
  const data = request.caller.data;
  if (data?.isAdmin !== true) {
    return {
      statusCode: 403,
      body: "Only admins may access this endpoint",
    };
  }

  return post_private(request);
}

export function post_private_prefix_cert(request) {
  const parsedQuery = parse_request_query(request);
  let params = request.body.json();
  const id = ccf.strToBuf(params.id.toString());
  const log_line = `${ccf.pemToId(request.caller.cert)}: ${params.msg}`;
  private_records(ccf.kv, parsedQuery.scope).set(id, ccf.strToBuf(log_line));
  return { body: true };
}

export function post_private_raw_text(request) {
  // Check content-type header
  const actual = request.headers["content-type"];
  const expected = "text/plain";
  if (actual !== expected) {
    return {
      statusCode: 415,
      body: `Expected content-type '${expected}'. Got '${actual}'.`,
    };
  }
  const id = ccf.strToBuf(request.params.id);
  const buf = request.body.arrayBuffer();
  const parsedQuery = parse_request_query(request);
  private_records(ccf.kv, parsedQuery.scope).set(id, buf);
  return { body: true };
}

export function post_public(request) {
  const parsedQuery = parse_request_query(request);
  let params = request.body.json();
  const id = ccf.strToBuf(params.id.toString());
  public_records(ccf.kv, parsedQuery.scope).set(id, ccf.strToBuf(params.msg));
  if (params.record_claim) {
    const claims_digest = ccf.crypto.digest(
      "SHA-256",
      ccf.strToBuf(params.msg),
    );
    ccf.rpc.setClaimsDigest(claims_digest);
  }
  return { body: true };
}

export function delete_private(request) {
  const parsedQuery = parse_request_query(request);
  const id = get_id_from_query(parsedQuery);
  return delete_record(private_records(ccf.kv, parsedQuery.scope), id);
}

export function delete_public(request) {
  const parsedQuery = parse_request_query(request);
  const id = get_id_from_query(parsedQuery);
  return delete_record(public_records(ccf.kv, parsedQuery.scope), id);
}

export function clear_private(request) {
  const parsedQuery = parse_request_query(request);
  const records = private_records(ccf.kv, parsedQuery.scope);
  records.clear();
  return { body: true };
}

export function clear_public(request) {
  const parsedQuery = parse_request_query(request);
  const records = public_records(ccf.kv, parsedQuery.scope);
  records.clear();
  return { body: true };
}

export function count_private(request) {
  const parsedQuery = parse_request_query(request);
  const records = private_records(ccf.kv, parsedQuery.scope);
  const count = records.size;
  return { body: count };
}

export function count_public(request) {
  const parsedQuery = parse_request_query(request);
  const records = public_records(ccf.kv, parsedQuery.scope);
  const count = records.size;
  return { body: count };
}

function get_custom_identity(request) {
  // If a specific header is present, throw an exception
  const explodeHeaderKey = "x-custom-auth-explode";
  if (explodeHeaderKey in request.headers) {
    throw new Error(request.headers[explodeHeaderKey]);
  }

  const nameHeaderKey = "x-custom-auth-name";
  if (!(nameHeaderKey in request.headers)) {
    return [null, `Missing required header ${nameHeaderKey}`];
  }

  const name = request.headers[nameHeaderKey];
  if (name.length === 0) {
    return [null, "Name must not be empty"];
  }

  const ageHeaderKey = "x-custom-auth-age";
  if (!(ageHeaderKey in request.headers)) {
    console.log("Missing age header");
    return [null, `Missing required header ${ageHeaderKey}`];
  }

  const age = Number(request.headers[ageHeaderKey]);

  const minAge = 16;
  if (age < minAge) {
    return [null, `Caller age must be at least ${minAge}`];
  }

  const ident = {
    name: name,
    age: age,
  };

  return [ident, ""];
}

export function custom_auth(request) {
  // Custom authn policy is implemented here, directly in the endpoint
  const [callerIdentity, errorReason] = get_custom_identity(request);
  if (callerIdentity !== null) {
    var body = callerIdentity;
    body.description = `Your name is ${body.name} and you are ${body.age}`;
    return {
      body: body,
    };
  } else {
    return {
      statusCode: 401,
      body: errorReason,
    };
  }
}

function describe_user_cert_ident(lines, obj) {
  lines.push("User TLS cert");
  lines.push(`The caller is a user with ID: ${obj.id}`);
  lines.push(`The caller's user data is: ${JSON.stringify(obj.data, null, 2)}`);
  lines.push(`The caller's cert is:\n${obj.cert}`);
}

function describe_member_cert_ident(lines, obj) {
  lines.push("Member TLS cert");
  lines.push(`The caller is a member with ID: ${obj.id}`);
  lines.push(`The caller's user data is: ${JSON.stringify(obj.data, null, 2)}`);
  lines.push(`The caller's cert is:\n${obj.cert}`);
}

function describe_jwt_ident(lines, obj) {
  lines.push("JWT");
  lines.push(
    `The caller is identified by a JWT issued by: ${obj.jwt.keyIssuer}`,
  );
  lines.push(`The JWT header is:\n${JSON.stringify(obj.jwt.header, null, 2)}`);
  lines.push(
    `The JWT payload is:\n${JSON.stringify(obj.jwt.payload, null, 2)}`,
  );
}

function describe_cose_ident(lines, obj) {
  lines.push("User COSE Sign1");
  lines.push(
    `The caller is identified by a COSE Sign1 signed by kid: ${obj.id}`,
  );
  lines.push(
    `The caller is identified by a COSE Sign1 with content of size: ${obj.cose.content.byteLength}`,
  );
}

function describe_noauth_ident(lines, obj) {
  lines.push("Unauthenticated");
  lines.push("The caller did not provide any authenticated identity");
}

export function multi_auth(request) {
  var lines = [];

  const describers = {
    user_cert: describe_user_cert_ident,
    member_cert: describe_member_cert_ident,
    jwt: describe_jwt_ident,
    user_cose_sign1: describe_cose_ident,
    no_auth: describe_noauth_ident,
  };

  const describe = (name, obj) => {
    const describer = describers[name];
    if (describer === undefined) {
      throw new Error(`Unhandled auth policy: ${name}`);
    }
    describer(lines, obj);
  };

  if (typeof request.caller.policy === "string") {
    describe(request.caller.policy, request.caller);
  } else if (Array.isArray(request.caller.policy)) {
    lines.push(`Conjoined auth policy: ${request.caller.policy}`);
    for (const [i, name] of request.caller.policy.entries()) {
      lines.push("");
      lines.push(`${name}:`);
      describe(name, request.caller[name]);
    }
  } else {
    throw new Error(`Unhandled auth policy: ${request.caller.policy}`);
  }

  let s = lines.join("\n");
  console.log(s);
  return { body: s };
}
