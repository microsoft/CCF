AMD SEV-SNP
===================

How to use the AMD SEV-SNP platform
-----------------------------------
CCF must run on an AMD CPU which supports SEV-SNP.

To use SNP, set the enclave type in the :doc:`node configuration <../configuration>` to ``Virtual``.

Attestation
-----------
SNP attestation provide several fields needed to establish trust. This is specific to the SNP hardware as deployed in confidential Azure Container Instances, see `here <https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers>`_ for more information.

- Measurement

Measurement is a digest of the initial memory pages for the SEV-SNP VM, which CCF stores in the :ref:`audit/builtin_maps:``nodes.snp.measurements``` table. New nodes joining a network will provide their code id and the primary will perform an identity check against the table entries.

The first node in a new network will add its code id to the table. Members can then manage which code ids are present in the table with the ``add_snp_measurement`` and ``remove_node_code`` actions.

- Security Policy

On startup, the UVM checks code in the container against a security policy. A digest of the security policy is then provided in the attestation in the host_data field. CCF stores authorised host data in the :ref:`audit/builtin_maps:``nodes.snp.host_data``` table. New nodes joining a network will provide their policy digest and the primary will perform an identity check against the table entries.

The first node in a new network will add its policy digest to the table. Members can then manage which policy digests are present in the table with the ``add_snp_host_data`` and ``remove_snp_host_data`` actions.

.. note:: A node's security policy can be obtained by decoding the value of the ``SECURITY_POLICY`` environment variable from its base64 encoding to get a raw policy string. The digest is then a SHA256 hash of this raw string.
