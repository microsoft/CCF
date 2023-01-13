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

ccf.enableUntrustedDateTime(true);

export function time_now(request) {
  const original = new Date();

  const prev_setting = ccf.enableUntrustedDateTime(false);
  const definitely_1970 = new Date();

  ccf.enableUntrustedDateTime(true);
  const definitely_now = new Date();

  ccf.enableUntrustedDateTime(prev_setting);

  return {
    body: {
      default: original.toISOString(),
      definitely_1970: definitely_1970.toISOString(),
      definitely_now: definitely_now.toISOString(),
    },
  };
}
