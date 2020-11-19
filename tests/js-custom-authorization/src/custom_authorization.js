export function compare_bearer(request) {
  // Header names become lower-case
  const auth = request.headers["authorization"];
  return { body: auth === "Bearer 42" };
}
