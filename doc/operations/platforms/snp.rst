AMD SEV-SNP
===========

How to use the AMD SEV-SNP platform
-----------------------------------

CCF must run on an AMD CPU which supports SEV-SNP (typically `Azure confidential containers <https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers>`_).

To use SNP, in the :ref:`operations/configuration:``enclave``` configuration section, the enclave ``platform`` should be set to ``SNP``.

Attestation
-----------

SNP attestation provide several fields needed to establish trust. Several deployment scenarios are possible.

Confidential Azure Container Instance (ACI)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note:: See `here <https://learn.microsoft.com/en-us/azure/container-instances/container-instances-tutorial-deploy-confidential-containers-cce-arm>`_ for more information on the deployment of confidential containers in Azure.

Azure Confidential ACI provides a security context directory containing the following files. The content of these files are checked against the attestation report on node startup and join, and stored in the ledger for audit and improved serviceability. 

- ``host-amd-cert-base64``: The certificate chain corresponding to the key (VCEK) used to sign the attestation report, up to the well-known AMD root of trust certificate authority (Base64 encoded). 
- ``security-policy-base64``: The security policy [#security_policy]_ describing the state and transitions allowed for the container (Base64 encoded). The SHA256 hash of the decoded value should match the attestation report ``host_data``. This value is stored in the :ref:`audit/builtin_maps:``nodes.snp.host_data``` table.
- ``reference-info-base64``: The COSE Sign1 document containing the measurement [#measurement]_ of the utility VM (UVM) used to launch the container (Base64 encoded). The measurement contained in the document payload should match the report ``measurement``. If set, the value is stored in the :ref:`audit/builtin_maps:``nodes.snp.uvm_endorsements``` table and new nodes must present measurement endorsements from the same issuer (`did:x509`) to be trusted.

The location of the security context directory is passed to the container's startup command as the ``UVM_SECURITY_CONTEXT_DIR`` environment variable. The name of this environment variable should be specified as the value of the ``security_context_directory`` in the :ref:`operations/configuration:``environment``` configuration section.

.. tip:: See :ccf_repo:`samples/config/start_config_aci_sev_snp.json` for a sample node configuration for ACI deployments.

Non-ACI Deployment
~~~~~~~~~~~~~~~~~~

For non-ACI deployments, the certificate chain for VCEK will need to be retrieved from an endorsement server, as specified in the :ref:`operations/configuration:``snp_endorsements_servers``` configuration section. For example, for the `well-known AMD endorsement server <https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf>`_, the value should be set to:

.. code-block:: json

    "attestation": {
        "snp_endorsements_servers": [
            {
                "type": "AMD",
                "url": "kdsintf.amd.com"
            }
        ]
    }

.. tip:: See :ccf_repo:`samples/config/start_config_amd_sev_snp.json` for a sample node configuration for non-ACI deployments.

.. note:: The CCF node will fetch the endorsements from the server on startup, which may cause substantial deployment delays (up to tens of seconds) depending on network latency and endpoint throttling. 

Governance Proposals
~~~~~~~~~~~~~~~~~~~~

The following governance proposals can be issued to add/remove these trusted values, e.g. when upgrading the service (see :doc:`/operations/code_upgrade`):

- ``add_snp_host_data``/``remove_snp_host_data``: To add/remove a trusted security policy, e.g. when adding a new trusted container image as part of the code upgrade procedure. 
- ``add_snp_uvm_endorsement``/``add_snp_uvm_endorsement``: To add remove a trusted UVM endorsement (ACI deployment only).
- ``add_snp_measurement``/``remove_snp_measurement``: To add/remove a trusted measurement.

.. rubric:: Footnotes

.. [#security_policy] A `REGO <https://www.openpolicyagent.org/docs/latest/policy-language/>`_ policy checked by the utility VM (UVM) against the ACI container. 
.. [#measurement] Digest of the initial memory pages for the SEV-SNP VM. 