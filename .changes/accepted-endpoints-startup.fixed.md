A node now builds its RPC interfaces' `accepted_endpoints` regular expressions once at startup, instead of on its first requests, where concurrent requests could race and fail. A node with an invalid pattern now refuses to start, instead of failing every request.
See [node configuration](doc/operations/configuration.rst).
