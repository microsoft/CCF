export function launch(request) {
  const body = request.body.json();

  ccf.host.triggerSubprocess(body.args, ccf.strToBuf(body.input));
  return {};
}

export function launchMany(request) {
  const body = request.body.json();
  for (let i = 0; i < body.count; i++) {
    const args = [body.program, `${i}`, `${body.out_dir}/${i}`];
    ccf.host.triggerSubprocess(args);
  }
  return {};
}
