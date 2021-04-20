Common Governance Operations
============================

Trusting a New Node
-------------------

As opposed to an opening network in which nodes are trusted automatically, new nodes added to an open network must become trusted through a governance proposal and vote before becoming part of the network.

When an operator starts a new node with the ``join`` option (see :ref:`operations/start_network:Adding a New Node to the Network`), the node is recorded in state ``Pending``. Then, members can vote to accept the new node, using the unique node id (hex-encoded string of the SHA-256 digest of the node's identity public key). See :ref:`governance/proposals:Proposing and Voting for a Proposal` for more detail.

Once the proposal successfully completes, the new node automatically becomes part of the network.

.. note:: Once trusted, it may take some time for the new node to update its ledger and replay the transactions run on the network before it joined (from the beginning of time, or from the snapshot it started from).

Updating Code Version
---------------------

For new nodes to be able to join the network, the version of the code they run (as specified by the ``--enclave-file``) should be first trusted by the consortium of members.

If the version of the code being executed needs to be updated (for example, to support additional endpoints), members can create an ``add_node_code`` proposal, specifying the new code version.

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

    $ cat trigger_ledger_rekey.json
    {
        "actions": [
            {
                "name": "trigger_ledger_rekey",
                "args": null
            }
        ]
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert network_cert --key member1_privk --cert member1_cert --data-binary @trigger_ledger_rekey.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e/ballots --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    {
        "ballot_count": 1,
        "proposal_id": "2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e/ballots --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    {
        "ballot_count": 2,
        "proposal_id": "2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Accepted"
    }

Once the proposal is accepted (``"state": "Accepted"``) it is immediately enacted. All subsequent transactions will be encrypted with a fresh new ledger encryption key.

Updating Recovery Threshold
---------------------------

To protect the ledger secrets required to recover an existing service, CCF requires :ref:`members to submit their recovery shares <governance/accept_recovery:Submitting Recovery Shares>`.

.. note:: The initial value of the recovery threshold is set via the ``--recovery-threshold`` option to the starting CCF node. If this value is unspecified, it is set to the initial number of consortium members.

The number of member shares required to restore the private ledger (``recovery_threshold``) is part of the service configuration and can be updated by members via the usual propose and vote process.

.. code-block:: bash

    $ cat set_recovery_threshold.json
    {
        "actions": [
            {
                "name": "set_recovery_threshold",
                "args": {
                    "recovery_threshold": 2
                }
            }
        ]
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert network_cert --key member1_privk --cert member1_cert --data-binary @set_recovery_threshold.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8/ballots --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    {
        "ballot_count": 1,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8/ballots --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    {
        "ballot_count": 2,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Accepted"
    }

.. note:: The new recovery threshold has to be in the range between 1 and the current number of active recovery members.