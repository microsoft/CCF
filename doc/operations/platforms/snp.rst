AMD SEV-SNP
===========

How to use the AMD SEV-SNP platform
-----------------------------------

CCF must run on an AMD CPU which supports SEV-SNP, such as `Azure confidential containers <https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers>`_ or `Azure Kubernetes Service with Confidential Containers <https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview>`_.

To use SNP, in the :ref:`operations/configuration:``enclave``` configuration section, the enclave ``platform`` should be set to ``SNP``.

Attestation
-----------

SNP attestation provide several fields needed to establish trust. Several deployment scenarios are possible.

Confidential Azure Container Instance (ACI)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note:: See `here <https://learn.microsoft.com/en-us/azure/container-instances/container-instances-tutorial-deploy-confidential-containers-cce-arm>`__ and `here <https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md>`__ for more information on the deployment of confidential containers in Azure.

Azure Confidential ACI provides a security context directory containing the following files.

- ``security-policy-base64``: The security policy [#security_policy]_ describing the state and transitions allowed for the container (Base64 encoded). The SHA256 hash of the decoded value should match the attestation report ``host_data``. This value is stored in the :ref:`audit/builtin_maps:``nodes.snp.host_data``` table.
- ``reference-info-base64``: The COSE Sign1 document containing the measurement [#measurement]_ of the utility VM (UVM) used to launch the container (Base64 encoded). The measurement contained in the document payload should match the report ``measurement``. If set, the value is stored in the :ref:`audit/builtin_maps:``nodes.snp.uvm_endorsements``` table and new nodes must present measurement endorsements from the same issuer (`did:x509`) to be trusted.
- ``host-amd-cert-base64``: The Base64 encoded certificate chain for the VCEK used to sign the attestation report. Note that since this file is provisioned early in the container's lifetime, and because PSP firmware updates can happen at any time, it may be out of date by the time the node attempts to make use of it. Configuring at least one fall-back server is recommended for that reason.

The location of the security context directory is passed to the container's startup command as the ``UVM_SECURITY_CONTEXT_DIR`` environment variable. CCF can be configured to fetch the security policy and UVM endorsements from the security context directory by setting the ``snp_security_policy_file`` and ``snp_uvm_endorsements_file`` configuration options, respectively.

The preferred backup source for AMD VCEK endorsements is the THIM service, exposed at ``$Fabric_NodeIPOrFQDN:2377`` in Confidential ACI containers, but configuring the Azure cache or the AMD server is also possible.

.. tip:: See :ccf_repo:`samples/config/start_config_aci_sev_snp.json` for a sample node configuration for ACI deployments.

Confidential Azure Kubernetes Service (AKS)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note:: See `here <https://learn.microsoft.com/en-us/azure/aks/deploy-confidential-containers-default-policy>`__ for more information on the deployment of confidential containers in Azure.

Confidential AKS provides a security context directory containing the following file.

- ``reference-info-base64``: The COSE Sign1 document containing the measurement [#measurement]_ of the utility VM (UVM) used to launch the container (Base64 encoded). The measurement contained in the document payload should match the report ``measurement``. If set, the value is stored in the :ref:`audit/builtin_maps:``nodes.snp.uvm_endorsements``` table and new nodes must present measurement endorsements from the same issuer (`did:x509`) to be trusted.

The security policy must be provided by the operator, and will be picked up by CCF on startup if is named ``security-policy-base64`` and located in the security context directory. The SHA256 hash of the decoded value should match the attestation report ``host_data``. This value is stored in the :ref:`audit/builtin_maps:``nodes.snp.host_data``` table.

AMD VCEK endorsements must be fetched, preferably from the THIM service, but configuring the Azure cache or the AMD server is also possible.

.. tip:: See :ccf_repo:`samples/config/start_config_aks_sev_snp.json` for a sample node configuration for Confidential AKS deployments.


Non-Azure Deployment
~~~~~~~~~~~~~~~~~~~~

For non-Azure deployments, the certificate chain for VCEK can be retrieved either from file, if already cached, or from an endorsement server, as specified in the :ref:`operations/configuration:``attestation.snp_endorsements_servers``` configuration section. For example, for the `well-known AMD endorsement server <https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf>`_, the value should be set to:

.. code-block:: json

    "attestation": {
        "snp_endorsements_servers": [
            {
                "type": "AMD",
                "url": "kdsintf.amd.com"
            }
        ],
        "snp_security_policy_file": "/path/to/security-policy-base64",
        "snp_uvm_endorsements_file": "/path/to/reference-info-base64",
        "snp_endorsements_file": "/path/to/host-amd-cert-base64"
    }

.. tip:: See :ccf_repo:`samples/config/start_config_amd_sev_snp.json` for a sample node configuration for non-Azure deployments.

.. note:: If no local file is available, the CCF node will fetch the AMD VCEK endorsements from the server on startup, which may cause substantial deployment delays (up to tens of seconds) depending on network latency and endpoint throttling. 

Governance Proposals
~~~~~~~~~~~~~~~~~~~~

The following governance proposals can be issued to add/remove these trusted values, e.g. when upgrading the service (see :doc:`/operations/code_upgrade`):

- ``add_snp_host_data``/``remove_snp_host_data``: To add/remove a trusted security policy, e.g. when adding a new trusted container image as part of the code upgrade procedure. 
- ``add_snp_uvm_endorsement``/``add_snp_uvm_endorsement``: To add remove a trusted UVM endorsement (Azure deployment only).
- ``add_snp_measurement``/``remove_snp_measurement``: To add/remove a trusted measurement.
- ``set_snp_minimum_tcb_version``/``remove_snp_minimum_tcb_version``: To add/remove a minimum trusted TCB version.

.. rubric:: Footnotes

.. [#security_policy] A `REGO <https://www.openpolicyagent.org/docs/latest/policy-language/>`_ policy checked by the utility VM (UVM) against the container. 
.. [#measurement] Digest of the initial memory pages for the SEV-SNP VM. 
