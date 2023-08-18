import { fibonacci } from "./bad_fib.js";

// Note: Applications should be careful of using the global state as a generic cache
// like this, in particular providing any behavioural change indicating whether
// the cache was available. This results in transactions which are not reproducible
// from the ledger. This is only done here to aid testing of the interpreter reuse
// behaviour.
export function cachedFib(request) {
  if (!(globalThis.BadCache instanceof Object)) {
    globalThis.BadCache = {};
  }

  const body = request.body.json();
  const n = body.n;
  var wasCached = true;

  if (!(n in globalThis.BadCache)) {
    const fib = fibonacci(n);
    console.log(`Calculated fibonacci(${n}) = ${fib}`);
    globalThis.BadCache[n] = fib;
    wasCached = false;
  }

  return { body: { fib: globalThis.BadCache[n], wasCached: wasCached } };
}
