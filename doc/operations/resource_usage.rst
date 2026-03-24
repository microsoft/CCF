Resource Usage
==============

CPU
---

A single CCF node process runs at least two threads. A host thread manages sockets and files, and handles communication with the enclave via ring-buffers.
An enclave thread contains the TLS termination, all cryptography, and the application and key value code. It communicates with the host via ring-buffers too.
It is possible to add additional worker threads inside the enclave via the :ref:`operations/configuration:``worker_threads``` configuration entry.

Memory
------

The memory available to a CCF node process is ultimately bounded by the environment it runs in, typically the size of the virtual machine (VM) or container, and any additional OS- or container-level limits applied to the process.
On SEV-SNP, the node process runs inside a confidential VM; the VM size chosen at deployment time sets an upper bound on the memory that can be made available to the node, subject to any further limits imposed by the guest OS or container.

.. note:: If a JavaScript application is deployed, then by default the source code is pre-compiled into bytecode and stored in the Key Value store. While this reduces RPC latency it increases memory usage. The size of the bytecode cache can be queried via the ``/node/js_metrics`` RPC. See the :ref:`JavaScript Deployment <build_apps/js_app_bundle:Deployment>` section for details on enabling or disabling the cache.
