Accepting Recovery and Submitting Shares
========================================

.. note:: Before members can initiate the end of the recovery procedure, operators should have started a new network and recovered all public transactions. See :ref:`details for public recovery operator procedure <operations/recovery:Establishing a Recovered Public Network>`.

.. note:: See :ref:`build_apps/run_app:Recovering a Service` for an automated way to recover a defunct CCF service.

Accepting Recovery
------------------

Once the public recovered network has been established by operators, members are allowed to vote to confirm that the configuration of the new network is suitable to complete the recovery procedure.

A member proposes to recover the network and other members can vote on the proposal:

.. code-block:: bash

    $ cat transition_service_to_open.json
    {
        "actions": [
            {
                "name": "transition_service_to_open",
                "args": null
            }
        ]
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert network_cert --key member1_privk --cert member1_cert --data-binary @transition_service_to_open.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377",
        "proposer_id": "d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377/ballots --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_accept.json -H "content-type: application/json"
    {
        "ballot_count": 1,
        "proposal_id": "1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377",
        "proposer_id": "d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1",
        "state": "Open"
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals/1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377/ballots --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept.json -H "content-type: application/json"
    {
        "ballot_count": 2,
        "proposal_id": "1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377",
        "proposer_id": "d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1",
        "state": "Accepted"
    }

Once the proposal to recover the network has passed under the rules of the :term:`Constitution`, the recovered service is ready for members to submit their recovery shares.

Submitting Recovery Shares
--------------------------

To restore private transactions and complete the recovery procedure, recovery members (i.e. members whose public encryption key has been registered in CCF) should submit their recovery shares. The number of members required to submit their shares is set by the ``recovery_threshold`` CCF configuration parameter and :ref:`can be updated by the consortium at any time <governance/common_member_operations:Updating Recovery Threshold>`.

.. note:: The recovery members who submit their recovery shares do not necessarily have to be the members who previously accepted the recovery.

The recovery share retrieval, decryption and submission steps are conveniently performed by the ``submit_recovery_share.sh`` script as follows:

.. code-block:: bash

    $ submit_recovery_share.sh https://<ccf-node-address> --member-enc-privk member0_enc_privk.pem --cert member0_cert
    --key member0_privk --cacert network_cert
    HTTP/1.1 200 OK
    content-type: text/plain
    x-ms-ccf-transaction-id: 4.28
    1/2 recovery shares successfully submitted.

    $ submit_recovery_share.sh https://<ccf-node-address> --member-enc-privk member1_enc_privk.pem --cert member1_cert
    --key member1_privk --cacert network_cert
    HTTP/1.1 200 OK
    content-type: text/plain
    x-ms-ccf-transaction-id: 4.30
    2/2 recovery shares successfully submitted. End of recovery procedure initiated.

When the recovery threshold is reached, the ``POST /gov/recovery_share`` RPC returns that the end of the recovery procedure is initiated and the private ledger is now being recovered.

.. note:: While all nodes are recovering the private ledger, no new transaction can be executed by the network.

Once the recovery of the private ledger is complete on a quorum of nodes that have joined the new network, the ledger is fully recovered and users are able to continue issuing business transactions.

.. note:: Recovery shares are updated every time a new recovery member is added or removed and when the ledger is rekeyed. It also possible for members to update the recovery shares via the ``trigger_recovery_shares_refresh`` proposal.

Summary Diagram
---------------

.. mermaid::

    sequenceDiagram
        participant Member 0
        participant Member 1
        participant Users
        participant Node 2
        participant Node 3

        Note over Node 2, Node 3: Operators have restarted a public-only service

        Member 0->>+Node 2: Propose transition_service_to_open
        Node 2-->>Member 0: Proposal ID
        Member 1->>+Node 2: Vote for Proposal ID
        Node 2-->>Member 1: State: Accepted
        Note over Node 2, Node 3: transition_service_to_open proposal completes. Service is ready to accept recovery shares.

        Member 0->>+Node 2: GET /gov/recovery_share
        Node 2-->>Member 0: Encrypted recovery share for Member 0
        Note over Member 0: Decrypts recovery share
        Member 0->>+Node 2: POST /gov/recovery_share: "<recovery_share_0>"
        Node 2-->>Member 0: False

        Member 1->>+Node 2: GET /gov/recovery_share
        Node 2-->>Member 1: Encrypted recovery share for Member 1
        Note over Member 1: Decrypts recovery share
        Member 1->>+Node 2: POST /gov/recovery_share: "<recovery_share_1>"
        Node 2-->>Member 1: True

        Note over Node 2, Node 3: Reading Private Ledger...

        Note over Node 2: Recovery procedure complete
        Note over Node 3: Recovery procedure complete
