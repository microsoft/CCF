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
  if (!map.delete(id)) {
    return { body: { error: "No such key" } };
  }
  return { body: true };
}

export function get_private(request, scope) {
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
    const digest = ccf.digest("SHA-256", ccf.strToBuf(cacheKey));
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
    expiry_seconds
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
      next_page_start + max_seqno_per_page
    );
    const next_page_handle = makeHandle(
      next_page_start,
      next_page_end,
      parsedQuery.id
    );
    ccf.historical.getStateRange(
      next_page_handle,
      next_page_start,
      next_page_end
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
    "/app/log/private/historical/range"
  );
}

export function get_historical_range_public(request) {
  return get_historical_range_impl(
    request,
    false,
    "/app/log/public/historical/range"
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

export function post_public(request) {
  const parsedQuery = parse_request_query(request);
  let params = request.body.json();
  const id = ccf.strToBuf(params.id.toString());
  public_records(ccf.kv, parsedQuery.scope).set(id, ccf.strToBuf(params.msg));
  if (params.record_claim) {
    const claims_digest = ccf.digest("SHA-256", ccf.strToBuf(params.msg));
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
