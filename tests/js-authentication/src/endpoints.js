export function jwt(request) {
  return { body: request.user };
}
