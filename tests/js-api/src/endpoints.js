export function echo(request) {
  return { body: JSON.stringify(request) };
}
