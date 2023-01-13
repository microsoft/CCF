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
  const original = new Date();

  const prev_setting = ccf.enable_untrusted_date_time(false);
  const definitely_1970 = new Date();

  ccf.enable_untrusted_date_time(true);
  const definitely_now = new Date();

  ccf.enable_untrusted_date_time(prev_setting);

  return {
    body: {
      default: original.toISOString(),
      definitely_1970: definitely_1970.toISOString(),
      definitely_now: definitely_now.toISOString(),
    }
  }
}
