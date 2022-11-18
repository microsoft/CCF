Common Governance Operations
============================

Trusting a New Node
-------------------

As opposed to an opening network in which nodes are trusted automatically, new nodes added to an open network must become trusted through a governance proposal and vote before becoming part of the network.

When an operator starts a new node with the ``join`` option (see :ref:`operations/start_network:Adding a New Node to the Network`), the node is recorded in state ``Pending``. Then, members can propose and vote to accept the new node via the ``transition_node_to_trusted`` proposal, using the unique node id (hex-encoded string of the SHA-256 digest of the node's identity public key). See :ref:`governance/proposals:Proposing and Voting for a Proposal` for more detail.

Once the proposal successfully completes, the new node automatically becomes part of the network.

.. note:: Once trusted, it may take some time for the new node to update its ledger and replay the transactions run on the network before it joined (from the beginning of time, or from the snapshot it started from).

Removing an Existing Node
-------------------------

A node that is already part of the service can be retired using the ``remove_node`` proposal.

The operator can establish if it is safe to remove a node by calling :http:GET:`/node/network/removable_nodes`. Nodes that have been shut down must be cleaned up from the store by calling :http:DELETE:`/node/network/nodes/{node_id}`.

.. note:: If the now-retired node was the primary node, once the proposal successfully completes, an election will take place to elect a new primary.


Updating Code Version
---------------------

For new nodes to be able to join the network, the version of the code they run (as specified by ``enclave.file``) should be first trusted by the consortium of members.

The specifics of how to manage code updates depends on the :doc:`platform <../operations/platforms/index>` being run.

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

.. code-block:: bash

    $ ccf_cose_sign1 --ccf-gov-msg-type proposal --signing-key member1_privk.pem --signing-cert member1_cert.pem --content trigger_ledger_rekey.json | \
      curl https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 0,
        "proposal_id": "2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-proposal_id 2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e --signing-key member2_privk.pem --signing-cert member2_cert.pem --content vote_accept_1.json | \
      curl https://<ccf-node-address>/gov/proposals/2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 1,
        "proposal_id": "2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-proposal_id 2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e --signing-key member3_privk.pem --signing-cert member3_cert.pem --content vote_accept_1.json | \
      curl https://<ccf-node-address>/gov/proposals/2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 2,
        "proposal_id": "2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Accepted"
    }

Or alternatively, with the old signature method:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --signing-key member1_privk.pem --signing-cert member1_cert.pem --data-binary @trigger_ledger_rekey.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e/ballots --cacert service_cert.pem --signing-key member2_privk.pem --signing-cert member2_cert.pem --data-binary @vote_accept_1.json -H "content-type: application/json"
    {
        "ballot_count": 1,
        "proposal_id": "2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/2f739d154b8cddacd7fc6d03cc8d4d20626e477ec4b1af10a74c670bb38bed5e/ballots --cacert service_cert.pem --signing-key member3_privk --signing-cert member3_cert.pem --data-binary @vote_accept_1.json -H "content-type: application/json"
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

.. note:: The initial value of the recovery threshold is set via the ``start.service_configuration.recovery_threshold`` configuration entry when starting the first node in a new service. If this value is unspecified, it is set to the initial number of consortium members.

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

.. code-block:: bash

    $ ccf_cose_sign1 --ccf-gov-msg-type proposal --signing-key member1_privk.pem --signing-cert member1_cert.pem --content set_recovery_threshold.json | \
      curl https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 0,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-proposal_id b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8 --signing-key member2_privk.pem --signing-cert member2_cert.pem --content vote_accept_1.json | \
      curl https://<ccf-node-address>/gov/proposals/b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 1,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-proposal_id b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8 --signing-key member3_privk.pem --signing-cert member3_cert.pem --content vote_accept_1.json | \
      curl https://<ccf-node-address>/gov/proposals/b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 2,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Accepted"
    }

Or alternatively, with the old signature method:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --signing-key member1_privk.pem --signing-cert member1_cert.pem --data-binary @set_recovery_threshold.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8/ballots --cacert service_cert.pem --signing-key member2_privk.pem --signing-cert member2_cert.pem --data-binary @vote_accept_1.json -H "content-type: application/json"
    {
        "ballot_count": 1,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8/ballots --cacert service_cert.pem --signing-key member3_privk.pem --signing-cert member3_cert.pem --data-binary @vote_accept_1.json -H "content-type: application/json"
    {
        "ballot_count": 2,
        "proposal_id": "b9c08b3861395eca904d913427dcb436136e277cf4712eb14e9e9cddf9d231a8",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Accepted"
    }

.. note:: The new recovery threshold has to be in the range between 1 and the current number of active recovery members.

Renewing Node Certificate
-------------------------

.. note:: Renewing the certificate of a node does not change the identity (public key) of that node but only its validity period.

To renew the soon-to-be-expired certificate of a node, members should issue a ``set_node_certificate_validity`` proposal, specifying the date at which the validity period of the renewed certificate should start (``valid_from``), as well as its validity period in days (``validity_period_days`` -- optional).

- The ``valid_from`` date/time argument accepts time points in ASN.1 UTCTime format (``"YYMMDDhhmmssZ"``) or ISO 8601 format (``"YYYY-MM-DD HH:MM:SS.ssssss+HH:MM"``), with optional fractional seconds and timezone offset. For details see :ccf_repo:`src/ds/x509_time_fmt.h`.
- If set, the ``validity_period_days`` should be less than the service-wide maximum validity period configured by operators. If omitted, the ``validity_period_days`` defaults to the service-wide maximum validity period configured by operators (see :ref:`operations/certificates:Node Certificates`).
- Both Service-endorsed and self-signed node certificates are renewed by this proposal.

A sample proposal is:

.. code-block:: bash

    $ cat set_node_certificate_validity.json
    {
        "actions": [
            {
                "name": "set_node_certificate_validity",
                "args": {
                    "node_id": "86c0ccfab4b869abbc779937c51158c9dd2a130d58323643a3119e83b33dcf5c"
                    "valid_from": "220101143018Z",
                    "validity_period_days": 365
                }
            }
        ]
    }

.. tip:: All currently trusted nodes certificates can be renewed at once using the ``set_all_nodes_certificate_validity`` proposal (same arguments minus ``node_id``).

Renewing Service Certificate
----------------------------

.. note:: Renewing the certificate of the service does not change its identity (public key) but only its validity period.

Similarly to node certificates, the service certificate can be renewed via the ``set_service_certificate_validity`` proposal.

If omitted, the ``validity_period_days`` defaults to the service-wide maximum validity period configured by operators (see :ref:`operations/certificates:Service Certificate`).

A sample proposal is:

.. code-block:: bash

    $ cat set_service_certificate_validity.json
    {
        "actions": [
            {
                "name": "set_service_certificate_validity",
                "args": {
                    "valid_from": "220101143018Z",
                    "validity_period_days": 365
                }
            }
        ]
    }
