Common Governance Operations
============================

Trusting a New Node
-------------------

As opposed to an opening network in which nodes are trusted automatically, new nodes added to an open network must become trusted through a governance proposal and vote before becoming part of the network.

When an operator starts a new node with the ``join`` option (see :ref:`operators/start_network:Adding a New Node to the Network`), the joining node is assigned a unique node id and is recorded in state `PENDING`. Then, members can vote to accept the new node, using the unique assigned node id (see :ref:`members/proposals:Proposing and Voting for a Proposal` for more detail).

Once the proposal successfully completes, the new node automatically becomes part of the network.

.. note:: Once trusted, it may take some time for the new node to update its ledger and replay the transactions run on the network before it joined.

Updating Code Version
---------------------

For new nodes to be able to join the network, the version of the code they run (as specified by the ``--enclave-file``) should be first trusted by the consortium of members.

If the version of the code being executed needs to be updated (for example, to support additional endpoints), members can create a ``new_node_code`` proposal, specifying the new code version.

.. note:: For a given :term:`Open Enclave` enclave library, the version of the code (``mrenclave``) can be found by running the ``oesign`` utility:

    .. code-block:: bash

        $ /opt/openenclave/bin/oesign dump -e enclave_library
        === Entry point:
        name=_start
        address=000000000097fa38

        === SGX Enclave Properties:
        product_id=1
        security_version=1
        debug=1
        xfrm=0
        num_heap_pages=50000
        num_stack_pages=1024
        num_tcs=8
        mrenclave=3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9

Once the proposal has been accepted, nodes running the new code are authorised to join the network. Nodes running older versions of the code can then be retired and stopped.

.. note:: It is important to keep the code compatible with the previous version, since there will be a point in time in which the new code is running on at least one node, while the other version is running on a different node.

.. note:: The safest way to restart or replace nodes is by stopping a single node running the old version and starting a node running the new version as a sequence of operations, in order to avoid a situation in which most nodes have been stopped, and new nodes will not be able to join since it would be impossible to reach a majority of nodes agreeing to accept new nodes (this restriction is imposed by the consensus algorithm).


Rekeying Ledger
---------------

To limit the scope of key compromise, members of the consortium can refresh the key used to encrypt the ledger. For example, rekeying can be triggered by members when existing nodes are removed from the service.

.. code-block:: bash

    $ cat rekey_ledger.json
    {
        "script": {
            "text": "return Calls:call(\"rekey_ledger\")"
        }
    }

    $ ./scurl.sh https://<ccf-node-address>/gov/propose --cacert network_cert --key member1_privk --cert member1_cert --data-binary @rekey_ledger.json -H "content-type: application/json"
    {
        "completed": false,
        "id": 1
    }

    $ ./scurl.sh https://<ccf-node-address>/gov/vote --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    false

    $ ./scurl.sh https://<ccf-node-address>/gov/vote --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    true

Once the proposal is accepted (``"result":true``), all subsequent transactions will be encrypted with a fresh new ledger encryption key.

Updating Recovery Threshold
---------------------------

To protect the ledger secrets required to recover an existing service, CCF requires :ref:`members to submit their recovery shares <members/accept_recovery:Submitting Recovery Shares>`.

.. note:: The initial value of the recovery threshold is set via the ``--recovery-threshold`` option to the starting CCF node. If this value is unspecified, it is set to the initial number of consortium members.

The number of member shares required to restore the private ledger (``recovery_threshold``) is part of the service configuration and can be updated by members via the usual propose and vote process.

.. code-block:: bash

    $ cat set_recovery_threshold.json
    {
        "parameter": <new_recovery_threshold>,
        "script": {
            "text": "return Calls:call(\"set_recovery_threshold\")"
        }
    }

    $ ./scurl.sh https://<ccf-node-address>/gov/propose --cacert network_cert --key member1_privk --cert member1_cert --data-binary @set_recovery_threshold.json -H "content-type: application/json"
    {
        "completed": false,
        "id": 1
    }

    $ ./scurl.sh https://<ccf-node-address>/gov/vote --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    false

    $ ./scurl.sh https://<ccf-node-address>/gov/vote --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    true

.. note:: The new recovery threshold has to be in the range between 1 and the current number of active members.