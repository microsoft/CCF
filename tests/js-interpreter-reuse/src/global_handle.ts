import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";

function globals() {
  // ccf.rpc
  {
    if (!("rpc" in globalThis)) {
      globalThis.rpc = ccf.rpc;
    }

    globalThis.rpc.setApplyWrites(false);
    globalThis.rpc.setApplyWrites(true);

    const claims_digest = ccf.crypto.digest(
      "SHA-256",
      ccf.strToBuf("Hello world")
    );
    globalThis.rpc.setClaimsDigest(claims_digest);
  }

  // ccf.host
  {
    if (!("host" in globalThis)) {
      // ccf.host is not described in TypeScript, so work around the type system here
      let globalAny: any = ccf;
      globalThis.host = globalAny.host;
    }
  }

  // ccf.consensus
  {
    if (!("consensus" in globalThis)) {
      globalThis.consensus = ccf.consensus;
    }
  }

  // ccf.historical
  {
    if (!("historical" in globalThis)) {
      globalThis.historical = ccf.historical;
    }
  }

    console.info("FFF");
    return { statusCode: 204 };
}

function increment() {
  if (!("kvHandle" in globalThis)) {
    globalThis.kvHandle = ccfapp.typedKv(
      "public:cached_handle_table",
      ccfapp.string,
      ccfapp.uint32
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
