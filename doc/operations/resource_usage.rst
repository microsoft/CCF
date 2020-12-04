Resource Usage
==============

CPU
---

A CCF application currently consists of two threads. A host thread manages sockets and files, and handles communication with the enclave via ringbuffers.
An enclave thread contains the TLS termination, all cryptography, and the application and key value code. It communicates with the host via ringbuffers too.

In the current implementation, both threads spin on their input ringbuffer, meaning that a CCF application will generally appear to consume two full cores in normal operation.

Memory
------

The maximum amount of heap memory usable in the enclave is set in the configuration passed to the oesign tool (``oe_sign.conf``), when creating the enclave binary file.

This amount cannot be exceeded, or modified after the fact, so it is necessary to set it in advance to the maximum amount of memory the application is ever expected to consume.