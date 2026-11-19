A templated URL component which is the last one in its path segment can now contain the literal which follows it, so `/{id}:action` matches `/a:b:action` with `id` set to `a:b`.
Such requests previously did not match the endpoint.
