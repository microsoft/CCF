Recovery authenticates local snapshot receipts before reading and hashing snapshot bodies, avoiding full reads of candidates that cannot authenticate against the configured previous service identity.
See [recovery](doc/operations/recovery.rst).
