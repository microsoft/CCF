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

For example to set the minimum TCB version on Milan CPUs the following proposal can be submitted:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_snp_minimum_tcb_version",
          "args": {
            "cpuid": "00a0f11",
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

CCF release distribution
------------------------

Binary releases now target Azure Linux 3.0, and are provided as RPM packages, `ccf_devel` for application development, and `ccf` for the runtime. Containers and Debian packages are no longer published.