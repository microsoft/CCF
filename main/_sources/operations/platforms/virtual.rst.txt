Insecure Virtual
================

.. warning:: The Insecure Virtual mode does not provide any security guarantees and should be used for development purposes only.

How to use the Insecure Virtual Platform
----------------------------------------

The insecure virtual platform can run on any hardware supported by CCF.

To use virtual, in the :ref:`operations/configuration:``enclave``` configuration section, the enclave ``platform`` should be set to ``Virtual``, and ``type`` to ``Virtual``.

Attestation
-----------

As no attestation is provided by virtual nodes, any CCF node (e.g. a malicious node that would leak the service secret key) is allowed to join an existing CCF service.
