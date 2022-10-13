AMD SEV-SNP
===================

.. warning:: SEV-SNP support is currently experimental and in active development.

How to use the AMD SEV-SNP platform
-----------------------------------
CCF must run on an AMD CPU which supports SEV-SNP.

To use SNP, ``virtual`` must be specified in ``COMPILE_TARGETS``, at compile time. If any other targets are specified, you may also need to specify the ``TEST_ENCLAVE=virtual`` runtime argument.

Attestation
-----------
SNP attestation provide several fields needed to establish trust.

- Measurement

Measurement is a digest of the UVM (Utility Virtual Machine) that is running, which CCF stores as a :doc:`code id <../../audit/builtin_maps>`. New nodes joining a network will provide their code id and the primary will perform an identity check against the table entries.

The first node in a new network will add it's code id to the table. Members can then manage which code ids are present in the table with the ``add_node_code`` and ``remove_node_code`` actions.

- Security Policy

On startup, the UVM checks code in the container against a security policy. A digest of the security policy is then provided in the attestation. CCF stores authorised security policy digests in the :doc:`security_policies <../../audit/builtin_maps>` table. New nodes joining a netowrk will provide their policy digest and the primary will perform an identity check against the table entries.

The first node in a new network will add it's policy digest to the table. Members can then manage which policy digests are present in the table with the ``add_security_policy`` and ``remove_security_policy`` actions.

.. note:: A node's security policy can be obtained by decoding the value of the ``SECURITY_POLICY`` environment variable from it's base64 encoding to get a raw policy string. The digest is then a SHA256 hash of this raw string.
