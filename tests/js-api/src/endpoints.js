export function echo(request) {
  return { body: JSON.stringify(request) };
}

export function make_randoms(request) {
  return {
    body: {
      a: Math.random(),
      b: Math.random(),
    },
  };
}

function slow_fibonacci(n) {
  return n < 1 ? 0 : n <= 2 ? 1 : slow_fibonacci(n - 1) + slow_fibonacci(n - 2);
}

export function fibonacci(request) {
  const params = request.params;
  const n = Number(params.n);
  const fib = slow_fibonacci(n);
  return {
    body: {
      n: n,
      fib: fib,
    },
  };
}

export function time_now(request) {
  const definitely_1970 = new Date(0);
  const definitely_now = new Date();

  ccf.enableUntrustedDateTime(true);
  const untrusted_on = new Date();
  ccf.enableUntrustedDateTime(false);
  const untrusted_off = new Date();

  return {
    body: {
      definitely_1970: definitely_1970.toISOString(),
      definitely_now: definitely_now.toISOString(),
      untrusted_on: untrusted_on.toISOString(),
      untrusted_off: untrusted_off.toISOString(),
    },
  };
}
