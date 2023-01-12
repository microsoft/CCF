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

ccf.enable_untrusted_date_time(true);

export function time_now(request) {
  const a = new Date();

  ccf.enable_untrusted_date_time(false);

  const b = new Date();

  ccf.enable_untrusted_date_time(true);

  const c = new Date();

  return {
    body: {
      a: a.toISOString(),
      b: b.toISOString(),
      c: c.toISOString(),
    }
  }
}
