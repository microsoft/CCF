import * as ccfapp from "@microsoft/ccf-app";
import { TransactionId, ccf } from "@microsoft/ccf-app/global";

function globals(request) {
  // ccf.rpc
  {
    if (!("rpc" in globalThis)) {
      globalThis.rpc = ccf.rpc;
    }

    globalThis.rpc.setApplyWrites(false);
    globalThis.rpc.setApplyWrites(true);

    const claims_digest = ccf.crypto.digest(
      "SHA-256",
      ccf.strToBuf("Hello world"),
    );
    globalThis.rpc.setClaimsDigest(claims_digest);
  }

  // ccf.consensus
  var txId: TransactionId;
  {
    if (!("consensus" in globalThis)) {
      globalThis.consensus = ccf.consensus;
    }

    txId = globalThis.consensus.getLastCommittedTxId();
    globalThis.consensus.getStatusForTxId(txId.view, txId.seqno);
    globalThis.consensus.getViewForSeqno(txId.seqno);
  }

  // ccf.historical
  {
    if (!("historical" in globalThis)) {
      globalThis.historical = ccf.historical;
    }

    const handle: number = 1;
    globalThis.historical.getStateRange(handle, 1, txId.seqno, 180);
    globalThis.historical.dropCachedStates(handle);
  }

  // request
  var body;
  {
    if (!("requestBody" in globalThis)) {
      // NB: Stashing the request like this is an extremely suspicious thing to do!
      // The semantics here are unexpected - body is actually a light wrapper around
      // whatever the _current_ request body is. If the original request is desired,
      // it must be extracted first (eg - stashed = request.body.arrayBuffer())
      globalThis.requestBody = request.body;
    }

    body = globalThis.requestBody.json();
  }

  return { body: body };
}

function increment() {
  if (!("kvHandle" in globalThis)) {
    globalThis.kvHandle = ccfapp.typedKv(
      "public:cached_handle_table",
      ccfapp.string,
      ccfapp.uint32,
    );
  }

  const k = "single_key";
  if (!globalThis.kvHandle.has(k)) {
    globalThis.kvHandle.set(k, 0);
  } else {
    const v = globalThis.kvHandle.get(k);
    globalThis.kvHandle.set(k, v + 1);
  }

  const v = globalThis.kvHandle.get(k);

  return { body: { value: v } };
}

export { globals, increment };
