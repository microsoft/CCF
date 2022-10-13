Insecure Virtual
===================

How to use the Insecure Virtual Platform
----------------------
The insecure virtual platform can run on any hardware supported by CCF.

To use the insecure virtual platform, ``virtual`` must be specified in ``COMPILE_TARGETS`` at compile time. If any other targets are specified, you will also need to specify the ``TEST_ENCLAVE=virtual`` runtime argument.

Attestation
----------------------
No attestation is provided with virtual nodes, so nodes using this platform should not be trusted to the same degree as other nodes.
