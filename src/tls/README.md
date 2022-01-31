# OpenSSL TLS Implementation

This is a TLS implementation using OpenSSL that mimics the existing MbedTLS
one in a similar fashion. Because of that, some structures and call backs
look odd and have some work-arounds to make it fit the current workflow.

Once we completely deprecate the MbedTLS implementation from CCF, we should
re-write the TLS implementation to fit the OpenSSL coding flow, which would
make it much simpler and easier to use.

## CAs and Certificates

In the MbedTLS world, certificates can be null and have methods to change
some configurations in the TLS config/session objects. There isn't a lot of
cross-over, so updating the config does the trick.

However, in OpenSSL, session objects (ssl) are created from config objects
(cfg) and inherit all its properties. Therefore, to emulate MbedTLS, we need
to do to the session object every action we do to the config object, which is
not only redundant, but could be unsafe, if the calls are slightly different.

### Validation

Certificate validation can be complex to handle if you can accept connections
with certificates or not, and if they come, when and how to validate.

MbedTLS is a lot more lenient on checks. For example, CAs are not tested for
validity of actually signing other certificates, while OpenSSL has extensive
checks, which can fail functionality that was previously passing.

For this reason, a number of extra checks in the OpenSSL side were disabled.
Once we get rid of MbedTLS we should revisit those checks again and improve
CCF's usage of TLS, and perhaps also creating weaker checks for non-CA
certificates, etc.

## Context

### BIOs

MbedTLS operates reads and writes solely via callbacks, with a buffer in the
session object acting as async I/O. This is in stark contrast with OpenSSL
which uses BIO objects to pass information back and forth, and only have
callbacks for debug or very specialized cases.

We had to implement callbacks and specialize our case, but it could really be
just done with BIOs between the ring buffer and the context, but we'd have to
change a lot of code outside of the TLS implementation to add that.

### Reads and Writes

Reading and writing in MbedTLS returns a positive value for success (number of
bytes written) or a negative value for error (pre-defined error codes) including
WANTS_READ and WANTS_WRITE.

In OpenSSL, those methods return 1 for success and 0 or -1 for errors (depending
on the version), with all errors, including WANTS_READ and WANTS_WRITE
accessible through `SSL_get_error`. This imposes a number of hacks needed to
mimic the MbedTLS implementation, including:

- Multiple `#define`s with common error messages in `tls.h`
- Having to negate the error code to match
- Multiple checks to `SSL_want_read` and `SSL_want_write`

### Error Handling

As discussed above, the error handling is slightly different and promotes
verbose code in OpenSSL's side.
