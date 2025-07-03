5.x to 6.0 Migration Guide
==========================

This page outlines the major changes introduced in 6.0 and how developers and operators should update their applications and deployments when migrating from 5.x to 6.0.

A full feature list is available in the `6.0 release notes <https://github.com/microsoft/CCF/releases/tag/ccf-6.0.0-rc0>`_.


Join policy updates
-------------------

When a node is started in ``Start`` or ``Recovery`` mode, it populates the join policy with its own environment.
Specifically on C-ACI, new SNP nodes will populate ``nodes.snp.host_data``, ``nodes.snp.uvm_endorsements`` and ``nodes.snp.tcb_versions`` with their corresponding local values.

The benefit is that if new nodes are deployed on homogenous hardware and software stacks, then the join policy will automatically be populated with the correct values.

SNP TCB version
~~~~~~~~~~~~~~~

CCF now also supports validating the TCB version of the joining node's attestation.
This introduced a new table, ``nodes.snp.tcb_versions``, which is the minimum TCB version for joining nodes, per CPU model, and is automatically populated for new networks.

Old networks which are migrating to 6.0 will need to populate this table manually, using the ``set_snp_minimum_tcb_version`` governance action.
If they are not populated then new nodes may fail to join the network.

.. note:: 
  In 6.0.9 we introduced ``set_minimum_tcb_version_hex``, a more ergonomic governance action to set the minimum TCB version.
  This action takes the CPUID of the CPU and a hexstring of the TCB version in an attestation expands it into the relevant fields in the ``nodes.snp.tcb_versions`` table.
  We strongly recommend using this action as we can transparently add support for new CPU models which change the TCB version format, such as Turin.

For example to set the minimum TCB version on Milan CPUs the following proposal can be submitted:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_snp_minimum_tcb_version",
          "args": {
            "cpuid": "00a00f11",
            "tcb_version": {
              "boot_loader": 255,
              "tee": 255,
              "snp": 255, 
              "microcode": 255 
            }
          }
        }
      ]
    }

.. note::
    The CPUID must be presented as a lower-case hex-string. The value in the above example is for Milan CPUs, broken down as follows:

    +-----------------+-----------+
    |                 |    Value  |
    |      Field      +-----+-----+
    |                 | dec | hex |
    +=================+=====+=====+
    | Reserved        | 0   | 0x0 |
    +-----------------+-----+-----+
    | Extended Family | 10  | 0x0a|
    +-----------------+-----+-----+
    | Extended Model  | 0   | 0x0 |
    +-----------------+-----+-----+
    | Reserved        | 0   | 0x0 |
    +-----------------+-----+-----+
    | Base Family     | 15  | 0xf |
    +-----------------+-----+-----+
    | Base Model      | 1   | 0x1 |
    +-----------------+-----+-----+
    | Stepping        | 1   | 0x1 |
    +-----------------+-----+-----+

    SNP attestation structures contain the combined Family (``Extended Family + Base Family``) and Model (``Extended Model : Base Model``) values, so 25 (0x19) and 1 (0x01) respectively for the above Milan example.


CCF release distribution
------------------------

Binary releases now target Azure Linux 3.0, and are provided as RPM packages, `ccf_devel` for application development, and `ccf` for the runtime. Containers and Debian packages are no longer published.

Version live compatibility
--------------------------

When upgrading CCF services from one major version to the next, our usual recommendation is to upgrade first to the initial release in the new major version before attempting upgrade to later versions; ``N.latest`` transitions to ``N+1.0.0``. Interoperation between other versions is not guaranteed.

.. warning:: We make an exception for upgrades from 5.x to 6.0, and recommend that services upgrade from 5.latest directly to 6.0.2.

There is a bug in ``6.0.0`` and ``6.0.1`` which can cause a node to crash when running in a mixed-version service. This is described in detail in `GitHub issue #7002 <https://github.com/microsoft/CCF/issues/7002>`_, but a brief summary is that if a ``5.x`` node becomes primary and emits a signature `after` a ``6.0.0`` or ``6.0.1`` node has been primary, then the resulting ledger transactions will be unparseable by a ``6.0.0`` or ``6.0.1`` node. Any such node receiving these errors will report ``Failed to deserialise`` errors in its log. It is not guaranteed that multi-versioned services will hit this - if the upgrade and node rotation happens smoothly then it is possible for the service to reach a point where all nodes are running ``6.0.0`` and it is safe from this issue.

This bug is resolved in ``6.0.2``, and does not affect the ledger history - it is purely an issue with how ``6.0.0`` and ``6.0.1`` nodes `parse` these entries, rather than with the entries themselves. If an upgrade to ``6.0.0`` or ``6.0.1`` has been attempted, and results in nodes failing with ``Failed to deserialise`` errors, then it may be necessary to run a disaster recovery process to reach the ``6.0.2`` version and restore the service.
