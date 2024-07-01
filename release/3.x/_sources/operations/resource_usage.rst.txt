Resource Usage
==============

CPU
---

A CCF application currently consists of two threads. A host thread manages sockets and files, and handles communication with the enclave via ringbuffers.
An enclave thread contains the TLS termination, all cryptography, and the application and key value code. It communicates with the host via ringbuffers too.

Memory
------

The maximum amount of heap memory usable in the enclave is set in the configuration passed to the oesign tool (``oe_sign.conf``), when creating the enclave binary file.

This amount cannot be exceeded, or modified after the fact, so it is necessary to set it in advance to the maximum amount of memory the application is ever expected to consume.

.. note:: If a JavaScript application is deployed, then by default the source code is pre-compiled into bytecode and stored in the Key Value store. While this reduces RPC latency it increases memory usage. The size of the bytecode cache can be queried via the ``/node/js_metrics`` RPC. See the :ref:`JavaScript Deployment <build_apps/js_app_bundle:Deployment>` section for details on enabling or disabling the cache.
