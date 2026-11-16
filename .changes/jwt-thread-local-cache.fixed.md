JWT signature verification now uses a thread-local signing-key cache rather than serialising verification across worker threads.
See [JWT authentication](doc/build_apps/auth/jwt.rst#validating-tokens).
