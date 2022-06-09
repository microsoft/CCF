import * as ccfapp from "@microsoft/ccf-app";

export function postApplyWrites(request: ccfapp.Request): ccfapp.Response {
  const kv = ccfapp.typedKv(
    "public:apply_writes",
    ccfapp.string,
    ccfapp.string
  );
  const params = request.body.json();
  kv.set("foo", params.val);
  if ('setApplyWrites' in params) {
    ccfapp.setApplyWrites(params.setApplyWrites);
  }
  return {
    statusCode: params.statusCode,
  };
}

export function getApplyWrites(request: ccfapp.Request): ccfapp.Response {
  const kv = ccfapp.typedKv(
    "public:apply_writes",
    ccfapp.string,
    ccfapp.string
  );
  const v = kv.get("foo");
  return {
    body: v
  };
}

export function sequenceNumber(): ccfapp.TypedKvMap<number, number> {
  return ccfapp.typedKv(`private-sequence`, ccfapp.int32, ccfapp.int32);
}

export function getNextSequence(domain: number): number {
  let sequenceNum = sequenceNumber().get(domain);
  if (sequenceNum) {
    sequenceNum = sequenceNum + 1;
  } else {
    sequenceNum = 1;
  }
  sequenceNumber().set(domain, sequenceNum);
  return sequenceNum;
}

export function transfer(request: ccfapp.Request): ccfapp.Response {
  const newTransaction = {
    txnId: getNextSequence(1)
  };
  console.log(`Trying to return ${newTransaction.txnId}`);
  return {
    statusCode: 401,
    headers: {},
    body: {
      txnId: newTransaction.txnId
    }
  };
}